# File Integrity Monitor — core engine.
# All hashing, baseline, signing, scanning and alert logic lives here.
"""Core engine for the File Integrity Monitor.

The CLI (fim.py), the monitor (fim_monitor.py) and the GUI (fim_gui.py)
all import from this module. No hashing or baseline logic is duplicated
anywhere else, so a fix here fixes every front end.

Security model, in brief: a baseline is only trusted after its
HMAC-SHA256 signature verifies against a 32-byte key kept in a separate
file. The key never lives inside the baseline, and a failed signature
means the baseline is refused, never silently used or overwritten.
"""

from __future__ import annotations

import csv
import fnmatch
import hashlib
import hmac
import json
import logging
import os
import secrets
import smtplib
import sqlite3
import stat
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any


def get_project_root() -> Path:
    """Return the folder the app runs from.

    When frozen by PyInstaller, ``__file__`` points inside a temporary
    extraction folder that disappears on every run, so the baseline,
    logs and reports would be lost. In that case use the folder
    containing the .exe instead. Otherwise use this file's folder.
    """

    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


DEFAULT_CHUNK_SIZE = 65536
LARGE_FILE_THRESHOLD = 100 * 1024 * 1024
LARGE_FILE_CHUNK_SIZE = 1024 * 1024
MAX_WORKERS = 4
MAX_SCAN_INTERVAL = 3600
MIN_SCAN_INTERVAL = 10
BASELINE_VERSION = 1
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
EXIT_OK = 0
EXIT_CHANGES = 1
EXIT_ERROR = 2
LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
LOGGER = logging.getLogger("fim_core")
DB_WRITE_LOCK = threading.Lock()

DEFAULT_CONFIG: dict[str, Any] = {
    "monitored_paths": [],
    "recursive": True,
    "exclude_patterns": ["*.tmp", "*.log", "__pycache__", "*.bak"],
    "include_patterns": [],
    "hash_chunk_size": DEFAULT_CHUNK_SIZE,
    "scan_interval_seconds": 60,
    "alert_channels": ["console", "log"],
    "log_level": "INFO",
    "baseline_path": "baseline",
    "report_dir": "reports",
    "max_file_size_mb": 0,
}


class FimError(Exception):
    """Base error for the monitor; the CLI turns this into exit code 2."""


class BaselineError(FimError):
    """Raised when a baseline is missing, corrupt or fails its signature."""


class ConfigError(FimError):
    """Raised when a config file or a CLI value is invalid."""


@dataclass
class FileRecord:
    """One file as recorded in a baseline."""

    relative_path: str
    absolute_path: str
    sha256: str
    size: int
    mtime_utc: str
    mode: int
    created_utc: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a plain dict, safe for JSON and SQLite storage."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FileRecord:
        """Build a record from a stored dict, rejecting unsafe paths."""
        relative = str(data.get("relative_path", ""))
        if not relative or relative.startswith("..") or Path(relative).is_absolute():
            raise BaselineError(f"Unsafe relative path in baseline: {relative!r}")
        return cls(
            relative_path=relative,
            absolute_path=str(data.get("absolute_path", "")),
            sha256=str(data.get("sha256", "")),
            size=int(data.get("size", 0)),
            mtime_utc=str(data.get("mtime_utc", "")),
            mode=int(data.get("mode", 0)),
            created_utc=str(data.get("created_utc", "")),
        )


@dataclass
class Change:
    """One detected difference between a baseline and a live scan."""

    kind: str
    relative_path: str
    old_record: FileRecord | None = None
    new_record: FileRecord | None = None
    old_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a plain dict for reports."""
        return {
            "kind": self.kind,
            "relative_path": self.relative_path,
            "old_path": self.old_path,
            "old_sha256": self.old_record.sha256 if self.old_record else "",
            "new_sha256": self.new_record.sha256 if self.new_record else "",
            "old_size": self.old_record.size if self.old_record else 0,
            "new_size": self.new_record.size if self.new_record else 0,
        }


@dataclass
class ScanResult:
    """Outcome of scanning one directory tree."""

    records: list[FileRecord] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class VerifyResult:
    """Outcome of comparing a live scan against a baseline."""

    changes: list[Change] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    scanned_at_utc: str = ""


def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(UTC).isoformat()


def _stat_time_iso(timestamp: float) -> str:
    """Convert a filesystem timestamp to a UTC ISO-8601 string."""
    return datetime.fromtimestamp(timestamp, tz=UTC).isoformat()


def _windows_long_path(path: Path) -> Path:
    """Add the long-path prefix on Windows when the path is very long."""
    text = str(path)
    if os.name == "nt" and len(text) > 240 and not text.startswith("\\\\?\\"):
        return Path("\\\\?\\" + text)
    return path


def enable_windows_colours() -> None:
    """Enable ANSI colours in a Windows console, silently if unavailable."""
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32(0)
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 4)
    except Exception:  # Console handling must never break a scan.
        LOGGER.debug("Could not enable Windows ANSI colours.", exc_info=True)


def setup_logging(log_dir: Path, level: str = "INFO") -> logging.Logger:
    """Configure rotating file logging plus a console handler."""
    log_dir.mkdir(parents=True, exist_ok=True)
    numeric_level = getattr(logging, str(level).upper(), logging.INFO)
    logger = logging.getLogger("fim")
    logger.setLevel(numeric_level)
    logger.handlers.clear()
    formatter = logging.Formatter(LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S")
    file_handler = RotatingFileHandler(
        log_dir / "fim.log",
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(numeric_level)
    logger.addHandler(console_handler)
    LOGGER.setLevel(numeric_level)
    return logger


def hash_bytes(data: bytes) -> str:
    """Return the SHA-256 hex digest of a byte string."""
    return hashlib.sha256(data).hexdigest()


def hash_file(path: Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Hash one file in chunks, never loading the whole file into memory."""
    if chunk_size <= 0 or (chunk_size & (chunk_size - 1)) != 0:
        raise ValueError("chunk_size must be a positive power of two")
    digest = hashlib.sha256()
    size = path.stat().st_size
    if size > LARGE_FILE_THRESHOLD:
        chunk_size = max(chunk_size, LARGE_FILE_CHUNK_SIZE)
    with open(_windows_long_path(path), "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def get_key_path(explicit: Path | None = None) -> Path:
    """Return where the HMAC key lives, honouring FIM_KEY_PATH in tests."""
    if explicit is not None:
        return Path(explicit)
    override = os.environ.get("FIM_KEY_PATH")
    if override:
        return Path(override)
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
        return base / "FIM" / "fim.key"
    return Path.home() / ".config" / "fim" / "fim.key"


def load_or_create_key(key_path: Path) -> bytes:
    """Load the 32-byte HMAC key, creating it once on first use."""
    key_path = Path(key_path)
    if key_path.exists():
        key = key_path.read_bytes()
        if len(key) != 32:
            raise BaselineError("HMAC key file is corrupt: expected 32 bytes.")
        return key
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    write_file_atomic(key_path, key)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        LOGGER.debug("Could not set 0600 on the key file.", exc_info=True)
    return key


def load_key(key_path: Path) -> bytes | None:
    """Load the HMAC key, returning None instead of creating one."""
    key_path = Path(key_path)
    if not key_path.exists():
        return None
    key = key_path.read_bytes()
    if len(key) != 32:
        raise BaselineError("HMAC key file is corrupt: expected 32 bytes.")
    return key


def _canonical_payload_bytes(payload: dict[str, Any]) -> bytes:
    """Serialise a payload deterministically for signing."""
    text = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return text.encode("utf-8")


def sign_baseline(payload: dict[str, Any], key: bytes) -> dict[str, Any]:
    """Return a copy of payload with an HMAC-SHA256 signature attached."""
    signed = dict(payload)
    signature = hmac.new(key, _canonical_payload_bytes(payload), hashlib.sha256)
    signed["hmac"] = signature.hexdigest()
    return signed


def verify_signed_baseline(data: dict[str, Any], key: bytes) -> bool:
    """Check a signed baseline dict; False on any mismatch or bad shape."""
    if not isinstance(data, dict) or "hmac" not in data:
        return False
    expected = str(data["hmac"])
    payload = {k: v for k, v in data.items() if k != "hmac"}
    actual = hmac.new(key, _canonical_payload_bytes(payload), hashlib.sha256)
    return hmac.compare_digest(expected, actual.hexdigest())


def write_file_atomic(path: Path, data: bytes) -> None:
    """Write a file via a temporary file plus replace, so a crash or a full disk never leaves a half-written file behind."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.tmp")
    with open(temp_path, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_path, path)


def write_sha256_sidecar(path: Path) -> Path:
    """Write a sidecar file holding the SHA-256 of the given file."""
    sidecar = Path(str(path) + ".sha256")
    digest = hash_file(Path(path))
    write_file_atomic(sidecar, f"{digest}  {Path(path).name}\n".encode())
    return sidecar


def verify_sha256_sidecar(path: Path) -> bool:
    """Check a sidecar file against the file it describes."""
    sidecar = Path(str(path) + ".sha256")
    if not sidecar.exists():
        return False
    try:
        recorded = sidecar.read_text(encoding="utf-8").split()[0]
    except (OSError, IndexError):
        return False
    return hmac.compare_digest(recorded, hash_file(Path(path)))


def validate_path(root: Path) -> Path:
    """Resolve a monitored path and reject it if it does not exist."""
    resolved = Path(root).expanduser().resolve()
    if not resolved.exists():
        raise FimError(f"Monitored path does not exist: {root}")
    return resolved


def _pattern_matches(patterns: list[str], name: str, relative: str) -> bool:
    """Case-insensitive glob match against a file name or relative path."""
    lowered_name = name.lower()
    lowered_relative = relative.replace(os.sep, "/").lower()
    for pattern in patterns:
        lowered = pattern.lower()
        if fnmatch.fnmatch(lowered_name, lowered):
            return True
        if fnmatch.fnmatch(lowered_relative, lowered):
            return True
        if fnmatch.fnmatch(lowered_relative, lowered.rstrip("/") + "/*"):
            return True
    return False


def _should_include(
    name: str, relative: str, include: list[str], exclude: list[str]
) -> bool:
    """Apply include then exclude patterns; exclude always wins."""
    if exclude and _pattern_matches(exclude, name, relative):
        return False
    return not include or _pattern_matches(include, name, relative)


def _hash_one_file(path: Path, root: Path, chunk_size: int) -> FileRecord | str:
    """Hash a single file, returning a record or an error string."""
    try:
        before = path.stat()
        digest = hash_file(path, chunk_size)
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            LOGGER.warning("File changing during scan, re-hashing once: %s", path)
            digest = hash_file(path, chunk_size)
            after = path.stat()
            if (before.st_size, before.st_mtime_ns) != (
                after.st_size,
                after.st_mtime_ns,
            ):
                LOGGER.warning("File still changing during scan: %s", path)
    except FileNotFoundError:
        return f"SKIPPED (deleted during scan): {path}"
    except PermissionError:
        return f"ERROR (permission denied): {path}"
    except OSError as exc:
        return f"ERROR ({exc}): {path}"
    relative = path.relative_to(root).as_posix()
    return FileRecord(
        relative_path=relative,
        absolute_path=str(path),
        sha256=digest,
        size=after.st_size,
        mtime_utc=_stat_time_iso(after.st_mtime),
        mode=stat.S_IMODE(after.st_mode),
        created_utc=_stat_time_iso(after.st_ctime),
    )


def collect_files(
    root: Path,
    recursive: bool = True,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    max_size_mb: int = 0,
    follow_symlinks: bool = False,
) -> tuple[list[Path], list[str]]:
    """Walk a tree and return the files to hash plus reasons for skips."""
    include = include or []
    exclude = exclude or []
    files: list[Path] = []
    skipped: list[str] = []
    max_bytes = max_size_mb * 1024 * 1024 if max_size_mb else 0
    for current, dir_names, file_names in os.walk(root, followlinks=follow_symlinks):
        current_path = Path(current)
        if not recursive and current_path != root:
            dir_names.clear()
            continue
        dir_names.sort()
        kept_dirs: list[str] = []
        for name in dir_names:
            child = current_path / name
            relative = child.relative_to(root).as_posix()
            if child.is_symlink() and not follow_symlinks:
                skipped.append(f"SKIPPED (symlink directory, not followed): {child}")
                continue
            # Include patterns apply to files only: a directory must not
            # be dropped just because its own name does not match "*.txt".
            if exclude and _pattern_matches(exclude, name, relative):
                skipped.append(f"SKIPPED (excluded): {child}")
                continue
            kept_dirs.append(name)
        dir_names[:] = kept_dirs
        for name in sorted(file_names):
            child = current_path / name
            relative = child.relative_to(root).as_posix()
            if child.is_symlink() and not follow_symlinks:
                skipped.append(f"SKIPPED (symlink, not followed): {child}")
                continue
            if not _should_include(name, relative, include, exclude):
                skipped.append(f"SKIPPED (excluded): {child}")
                continue
            if max_bytes:
                try:
                    if child.stat().st_size > max_bytes:
                        skipped.append(f"SKIPPED (over max size): {child}")
                        continue
                except OSError as exc:
                    skipped.append(f"SKIPPED (cannot stat): {child} ({exc})")
                    continue
            files.append(child)
    return files, skipped


def scan_directory(
    root: Path,
    recursive: bool = True,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    max_size_mb: int = 0,
    follow_symlinks: bool = False,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    workers: int = MAX_WORKERS,
) -> ScanResult:
    """Hash every matching file under root, in parallel, without crashing on one bad file."""
    root = validate_path(root)
    if follow_symlinks:
        LOGGER.warning(
            "Following symlinks is enabled; links outside the monitored root will be followed."
        )
    paths, skipped = collect_files(
        root, recursive, include, exclude, max_size_mb, follow_symlinks
    )
    records: list[FileRecord] = []
    errors: list[str] = []
    total = len(paths)
    if total > 100:
        LOGGER.info("Scanning %d files under %s", total, root)
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(_hash_one_file, p, root, chunk_size) for p in paths]
        for index, future in enumerate(futures, start=1):
            outcome = future.result()
            if isinstance(outcome, FileRecord):
                records.append(outcome)
            else:
                if outcome.startswith("ERROR"):
                    errors.append(outcome)
                skipped.append(outcome)
            if total > 100 and index % 100 == 0:
                LOGGER.info("Scanned %d / %d files", index, total)
    records.sort(key=lambda record: record.relative_path)
    return ScanResult(records=records, skipped=skipped, errors=errors)


def _init_database(database_path: Path) -> None:
    """Create the baseline and scan-history tables if they do not exist."""
    with DB_WRITE_LOCK, sqlite3.connect(str(database_path)) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS files ("
            "relative_path TEXT PRIMARY KEY, absolute_path TEXT, "
            "sha256 TEXT, size INTEGER, mtime_utc TEXT, mode INTEGER, "
            "created_utc TEXT)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS scans ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, scanned_utc TEXT, "
            "monitored_path TEXT, total INTEGER, unchanged INTEGER, "
            "added INTEGER, deleted INTEGER, modified INTEGER, "
            "renamed INTEGER, errors INTEGER)"
        )
        connection.commit()


def _store_records(database_path: Path, records: list[FileRecord]) -> None:
    """Replace the stored file records, under the single-writer lock."""
    with DB_WRITE_LOCK, sqlite3.connect(str(database_path)) as connection:
        connection.execute("DELETE FROM files")
        connection.executemany(
            "INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    r.relative_path,
                    r.absolute_path,
                    r.sha256,
                    r.size,
                    r.mtime_utc,
                    r.mode,
                    r.created_utc,
                )
                for r in records
            ],
        )
        connection.commit()


def _record_scan_history(
    database_path: Path, root: Path, counts: dict[str, int]
) -> None:
    """Append one row to the scan-history table."""
    with DB_WRITE_LOCK, sqlite3.connect(str(database_path)) as connection:
        connection.execute(
            "INSERT INTO scans (scanned_utc, monitored_path, total, "
            "unchanged, added, deleted, modified, renamed, errors) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                _utc_now_iso(),
                str(root),
                counts.get("total", 0),
                counts.get("unchanged", 0),
                counts.get("added", 0),
                counts.get("deleted", 0),
                counts.get("modified", 0),
                counts.get("renamed", 0),
                counts.get("errors", 0),
            ),
        )
        connection.commit()


def create_baseline(
    root: Path,
    baseline_dir: Path,
    key_path: Path,
    recursive: bool = True,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    max_size_mb: int = 0,
    follow_symlinks: bool = False,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> ScanResult:
    """Scan a tree and write a signed baseline (SQLite plus signed JSON)."""
    root = validate_path(root)
    baseline_dir = Path(baseline_dir)
    baseline_dir.mkdir(parents=True, exist_ok=True)
    key = load_or_create_key(key_path)
    result = scan_directory(
        root, recursive, include, exclude, max_size_mb, follow_symlinks, chunk_size
    )
    database_path = baseline_dir / "baseline.db"
    _init_database(database_path)
    _store_records(database_path, result.records)
    payload: dict[str, Any] = {
        "version": BASELINE_VERSION,
        "created_utc": _utc_now_iso(),
        "monitored_path": str(root),
        "files": [record.to_dict() for record in result.records],
    }
    signed = sign_baseline(payload, key)
    json_path = baseline_dir / "baseline.json"
    write_file_atomic(
        json_path, json.dumps(signed, indent=2, sort_keys=True).encode("utf-8")
    )
    write_sha256_sidecar(json_path)
    for line in result.skipped:
        LOGGER.info("%s", line)
    for line in result.errors:
        LOGGER.error("%s", line)
    LOGGER.info("Baseline created: %d files under %s", len(result.records), root)
    return result


def load_baseline(baseline_dir: Path, key_path: Path) -> list[FileRecord]:
    """Load a baseline, verifying its HMAC signature before trusting it."""
    baseline_dir = Path(baseline_dir)
    json_path = baseline_dir / "baseline.json"
    database_path = baseline_dir / "baseline.db"
    if not json_path.exists() or not database_path.exists():
        raise BaselineError("Baseline not found. Run fim init first.")
    key = load_key(key_path)
    if key is None:
        raise BaselineError("HMAC key not found. Run fim init first.")
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineError(f"Baseline is corrupt and cannot be read: {exc}") from exc
    if not verify_signed_baseline(data, key):
        raise BaselineError("Baseline tampered or corrupt.")
    if not verify_sha256_sidecar(json_path):
        raise BaselineError("Baseline tampered or corrupt.")
    files = data.get("files")
    if not isinstance(files, list):
        raise BaselineError("Baseline is corrupt: file list is missing.")
    return [FileRecord.from_dict(item) for item in files]


def _detect_renames(changes: list[Change]) -> list[Change]:
    """Pair an added file with a deleted file of identical hash and size."""
    added = [c for c in changes if c.kind == "ADDED"]
    deleted = [c for c in changes if c.kind == "DELETED"]
    used_added: set[int] = set()
    used_deleted: set[int] = set()
    renames: list[Change] = []
    for d_index, deleted_change in enumerate(deleted):
        old = deleted_change.old_record
        if old is None:
            continue
        for a_index, added_change in enumerate(added):
            if a_index in used_added:
                continue
            new = added_change.new_record
            if new is not None and new.sha256 == old.sha256 and new.size == old.size:
                renames.append(
                    Change(
                        kind="RENAMED",
                        relative_path=new.relative_path,
                        old_record=old,
                        new_record=new,
                        old_path=old.relative_path,
                    )
                )
                used_added.add(a_index)
                used_deleted.add(d_index)
                break
    kept: list[Change] = []
    added_ids = {id(added[i]) for i in used_added}
    deleted_ids = {id(deleted[i]) for i in used_deleted}
    for change in changes:
        if id(change) in added_ids or id(change) in deleted_ids:
            continue
        kept.append(change)
    return kept + renames


def verify_baseline(
    root: Path,
    baseline_dir: Path,
    key_path: Path,
    recursive: bool = True,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    max_size_mb: int = 0,
    follow_symlinks: bool = False,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    report_dir: Path | None = None,
) -> VerifyResult:
    """Compare a live scan with the signed baseline and record the scan."""
    root = validate_path(root)
    baseline_records = load_baseline(baseline_dir, key_path)
    baseline_by_path = {r.relative_path: r for r in baseline_records}
    result = scan_directory(
        root, recursive, include, exclude, max_size_mb, follow_symlinks, chunk_size
    )
    current_by_path = {r.relative_path: r for r in result.records}
    changes: list[Change] = []
    unchanged = 0
    for relative, old in baseline_by_path.items():
        current = current_by_path.get(relative)
        if current is None:
            # A file that still exists on disk but could not be hashed is
            # in an unknown state: never report it as deleted.
            if Path(old.absolute_path).exists():
                continue
            changes.append(Change("DELETED", relative, old_record=old))
            continue
        if current.sha256 != old.sha256:
            changes.append(
                Change("MODIFIED", relative, old_record=old, new_record=current)
            )
        elif current.mode != old.mode:
            changes.append(
                Change(
                    "PERMISSION_CHANGED", relative, old_record=old, new_record=current
                )
            )
        else:
            unchanged += 1
    for relative, current in current_by_path.items():
        if relative not in baseline_by_path:
            changes.append(Change("ADDED", relative, new_record=current))
    changes = _detect_renames(changes)
    counts = {
        "total": len(result.records),
        "unchanged": unchanged,
        "added": sum(1 for c in changes if c.kind == "ADDED"),
        "deleted": sum(1 for c in changes if c.kind == "DELETED"),
        "modified": sum(1 for c in changes if c.kind == "MODIFIED"),
        "renamed": sum(1 for c in changes if c.kind == "RENAMED"),
        "permission_changed": sum(1 for c in changes if c.kind == "PERMISSION_CHANGED"),
        "errors": len(result.errors),
    }
    verify_result = VerifyResult(
        changes=changes, counts=counts, scanned_at_utc=_utc_now_iso()
    )
    database_path = Path(baseline_dir) / "baseline.db"
    if database_path.exists():
        _record_scan_history(database_path, root, counts)
    if report_dir is not None:
        write_report(report_dir, root, verify_result)
    return verify_result


def update_baseline(
    root: Path,
    baseline_dir: Path,
    key_path: Path,
    recursive: bool = True,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    max_size_mb: int = 0,
    follow_symlinks: bool = False,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> ScanResult:
    """Rebuild the baseline from the current tree; call only after review."""
    result = create_baseline(
        root,
        baseline_dir,
        key_path,
        recursive,
        include,
        exclude,
        max_size_mb,
        follow_symlinks,
        chunk_size,
    )
    LOGGER.info(
        "Baseline updated at %s by %s",
        _utc_now_iso(),
        os.environ.get("USERNAME") or os.environ.get("USER") or "user",
    )
    return result


def get_status(baseline_dir: Path) -> dict[str, Any]:
    """Return baseline metadata: path, file count, last scan, last counts."""
    baseline_dir = Path(baseline_dir)
    json_path = baseline_dir / "baseline.json"
    database_path = baseline_dir / "baseline.db"
    if not json_path.exists() or not database_path.exists():
        raise BaselineError("Baseline not found. Run fim init first.")
    data = json.loads(json_path.read_text(encoding="utf-8"))
    with sqlite3.connect(str(database_path)) as connection:
        count = connection.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        row = connection.execute(
            "SELECT scanned_utc, total, added, deleted, modified, renamed "
            "FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
    status: dict[str, Any] = {
        "monitored_path": data.get("monitored_path", ""),
        "created_utc": data.get("created_utc", ""),
        "file_count": int(count),
        "last_scan_utc": row[0] if row else "",
        "last_total": row[1] if row else 0,
        "last_added": row[2] if row else 0,
        "last_deleted": row[3] if row else 0,
        "last_modified": row[4] if row else 0,
        "last_renamed": row[5] if row else 0,
    }
    return status


def get_history(baseline_dir: Path, limit: int = 20) -> list[dict[str, Any]]:
    """Return the most recent scan-history rows, newest first."""
    database_path = Path(baseline_dir) / "baseline.db"
    if not database_path.exists():
        raise BaselineError("Baseline not found. Run fim init first.")
    columns = [
        "id",
        "scanned_utc",
        "monitored_path",
        "total",
        "unchanged",
        "added",
        "deleted",
        "modified",
        "renamed",
        "errors",
    ]
    with sqlite3.connect(str(database_path)) as connection:
        rows = connection.execute(
            "SELECT id, scanned_utc, monitored_path, total, unchanged, "
            "added, deleted, modified, renamed, errors FROM scans "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(zip(columns, row)) for row in rows]


def _unique_report_path(report_dir: Path, stem: str, suffix: str) -> Path:
    """Return a report path, adding -2, -3 when the name already exists."""
    candidate = report_dir / f"{stem}{suffix}"
    counter = 2
    while candidate.exists():
        candidate = report_dir / f"{stem}-{counter}{suffix}"
        counter += 1
    return candidate


def sanitize_for_report(text: str) -> str:
    """Strip control characters so a path cannot corrupt a report."""
    return "".join(ch for ch in str(text) if ch == "\n" or ch == "\t" or ord(ch) >= 32)


def write_report(report_dir: Path, root: Path, result: VerifyResult) -> Path:
    """Write JSON, text and CSV reports for one verification run."""
    report_dir = Path(report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y-%m-%d_%H-%M-%S")
    stem = f"fim-report-{stamp}"
    payload = {
        "scanned_at_utc": result.scanned_at_utc,
        "monitored_path": str(root),
        "counts": result.counts,
        "changes": [c.to_dict() for c in result.changes],
    }
    json_path = _unique_report_path(report_dir, stem, ".json")
    write_file_atomic(
        json_path, json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    )
    text_path = json_path.with_suffix(".txt")
    lines = [
        "File Integrity Monitor — verification report",
        f"Scanned at (UTC): {result.scanned_at_utc}",
        f"Monitored path: {sanitize_for_report(str(root))}",
        f"Counts: {result.counts}",
        "",
    ]
    for change in result.changes:
        lines.append(
            f"[{change.kind}] {sanitize_for_report(change.relative_path)}"
            + (
                f" (was {sanitize_for_report(change.old_path)})"
                if change.old_path
                else ""
            )
        )
    if not result.changes:
        lines.append("No changes detected.")
    write_file_atomic(text_path, "\n".join(lines).encode("utf-8"))
    csv_path = json_path.with_suffix(".csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "kind",
                "relative_path",
                "old_path",
                "old_sha256",
                "new_sha256",
                "old_size",
                "new_size",
            ]
        )
        for change in result.changes:
            item = change.to_dict()
            writer.writerow(
                [
                    item["kind"],
                    item["relative_path"],
                    item["old_path"],
                    item["old_sha256"],
                    item["new_sha256"],
                    item["old_size"],
                    item["new_size"],
                ]
            )
    return json_path


def send_alert(change: Change, config: dict[str, Any], log_dir: Path) -> None:
    """Send one change through every enabled alert channel, never crashing."""
    channels = config.get("alert_channels", ["console", "log"])
    now_utc = _utc_now_iso()
    local_now = datetime.now().astimezone().isoformat()
    message = (
        f"[ALERT] [{change.kind}] {change.relative_path} — "
        f"old hash: {change.old_record.sha256 if change.old_record else ''} → "
        f"new hash: {change.new_record.sha256 if change.new_record else ''} "
        f"(old size {change.old_record.size if change.old_record else 0}, "
        f"new size {change.new_record.size if change.new_record else 0})"
    )
    if "console" in channels:
        enable_windows_colours()
        print(f"{now_utc} {message}")
    if "log" in channels:
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            with open(log_dir / "alerts.log", "a", encoding="utf-8") as handle:
                handle.write(f"{now_utc} (local {local_now}) {message}\n")
        except OSError:
            LOGGER.exception("Could not write alerts.log.")
    if "desktop" in channels:
        try:
            from plyer import notification

            notification.notify(
                title="File Integrity Monitor",
                message=f"{change.kind}: {change.relative_path}",
                timeout=10,
            )
        except Exception:
            LOGGER.debug("Desktop notification failed; continuing.", exc_info=True)
    if "email" in channels:
        _send_email_alert(change, message)


def _send_email_alert(change: Change, message: str) -> None:
    """Send an email alert only when SMTP settings come from the environment."""
    host = os.environ.get("FIM_SMTP_HOST", "")
    user = os.environ.get("FIM_SMTP_USER", "")
    password = os.environ.get("FIM_SMTP_PASSWORD", "")
    recipient = os.environ.get("FIM_ALERT_EMAIL", "")
    if not all([host, user, password, recipient]):
        LOGGER.info("Email alerts disabled: SMTP settings are not configured.")
        return
    try:
        email = EmailMessage()
        email["Subject"] = f"FIM alert: {change.kind} {change.relative_path}"
        email["From"] = user
        email["To"] = recipient
        email.set_content(message)
        with smtplib.SMTP(host, int(os.environ.get("FIM_SMTP_PORT", "587"))) as server:
            server.starttls()
            server.login(user, password)
            server.send_message(email)
    except Exception:
        LOGGER.exception("Email alert failed.")


def alert_for_changes(
    changes: list[Change], config: dict[str, Any], log_dir: Path
) -> None:
    """Send alerts for every change in a verification result."""
    for change in changes:
        send_alert(change, config, log_dir)


def load_config(config_path: Path | None) -> dict[str, Any]:
    """Load and validate a config file; missing file means defaults."""
    config: dict[str, Any] = dict(DEFAULT_CONFIG)
    if config_path is None:
        return config
    path = Path(config_path)
    if not path.exists():
        LOGGER.warning("Config file not found: %s — using defaults.", path)
        return config
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid config {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ConfigError(f"Invalid config {path}: top level must be an object.")
    for key, value in loaded.items():
        if key not in DEFAULT_CONFIG:
            raise ConfigError(f"Invalid config {path}: unknown field {key!r}.")
        config[key] = value
    interval = config.get("scan_interval_seconds", 60)
    if (
        not isinstance(interval, int)
        or not MIN_SCAN_INTERVAL <= interval <= MAX_SCAN_INTERVAL
    ):
        raise ConfigError(
            "Invalid config: scan_interval_seconds must be an integer between "
            f"{MIN_SCAN_INTERVAL} and {MAX_SCAN_INTERVAL}."
        )
    chunk = config.get("hash_chunk_size", DEFAULT_CHUNK_SIZE)
    if not isinstance(chunk, int) or chunk <= 0 or (chunk & (chunk - 1)) != 0:
        raise ConfigError(
            "Invalid config: hash_chunk_size must be a positive power of two."
        )
    max_size = config.get("max_file_size_mb", 0)
    if not isinstance(max_size, int) or max_size < 0:
        raise ConfigError("Invalid config: max_file_size_mb must be 0 or more.")
    if not isinstance(config.get("monitored_paths", []), list):
        raise ConfigError("Invalid config: monitored_paths must be a list.")
    return config


def print_summary(result: VerifyResult) -> None:
    """Print a coloured summary table for a verification run."""
    enable_windows_colours()
    counts = result.counts
    print("File Integrity Monitor — summary")
    print(f"  Total:              {counts.get('total', 0)}")
    print(f"  Unchanged:          {counts.get('unchanged', 0)}")
    print(f"  Added:              {counts.get('added', 0)}")
    print(f"  Deleted:            {counts.get('deleted', 0)}")
    print(f"  Modified:           {counts.get('modified', 0)}")
    print(f"  Renamed:            {counts.get('renamed', 0)}")
    print(f"  Permission changed: {counts.get('permission_changed', 0)}")
    print(f"  Errors:             {counts.get('errors', 0)}")
    if result.changes:
        print("Changes:")
        for change in result.changes:
            print(f"  [{change.kind}] {change.relative_path}")
    else:
        print("No changes detected.")
