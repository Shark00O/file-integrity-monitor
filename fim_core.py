# File Integrity Monitor - core engine.
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

import base64
import csv
import fnmatch
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import smtplib
import sqlite3
import stat
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

VERSION = "1.1.0"
GITHUB_REPO = "Shark00O/file-integrity-monitor"
UPDATE_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
WEBHOOK_TYPES = ("discord", "slack", "generic")
ALERT_CHANNELS = ("console", "log", "desktop", "email", "webhook")


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
    "webhook_url": "",
    "webhook_type": "discord",
    "check_for_updates": True,
    "scheduled_scan_interval_minutes": 0,
    "mass_change_threshold": 10,
    "mass_change_percent": 20,
    "gui_theme": "light",
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
    # Every file found in the live scan, so callers (e.g. the GUI) can
    # show unchanged files as OK instead of only listing changes.
    records: list[FileRecord] = field(default_factory=list)
    # True when the change count trips the mass-change rule (see
    # is_mass_change): many files changed in one scan.
    mass_change: bool = False


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


ENCRYPTED_BASELINE_FORMAT = "fim-encrypted-v1"
ENCRYPTION_LABEL = b"fim-encryption-v1"


def _derive_encryption_key(key: bytes) -> bytes:
    """Derive a separate encryption key from the HMAC key.

    The HMAC key itself is never used directly as a stream key.
    A fixed domain-separation label keeps the two uses apart.
    """
    return hmac.new(key, ENCRYPTION_LABEL, hashlib.sha256).digest()


def _xor_with_keystream(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """XOR data with an HMAC-SHA256 counter-mode keystream.

    This is NOT AES. It is a documented, stdlib-only stream cipher:
    each 32-byte block is HMAC(enc_key, nonce || counter). The nonce
    is random per write and is stored with the ciphertext, so a
    keystream is never reused for a different plaintext. The
    ciphertext is authenticated by the HMAC over the whole
    baseline file (see sign_baseline), so a flipped bit is detected
    before decryption is trusted. Limits: if the 32-byte HMAC key
    leaks, an attacker can decrypt; there is no forward secrecy.
    """
    out = bytearray()
    counter = 0
    while len(out) < len(data):
        block = hmac.new(
            key, nonce + counter.to_bytes(8, "big"), hashlib.sha256
        ).digest()
        chunk = data[len(out) : len(out) + len(block)]
        out.extend(b ^ block[i] for i, b in enumerate(chunk))
        counter += 1
    return bytes(out)


def _write_baseline_json(json_path: Path, payload: dict[str, Any], key: bytes) -> None:
    """Write baseline.json encrypted and signed.

    The file on disk is {"format": "fim-encrypted-v1", "data": base64,
    "hmac": ...}. The plaintext (file names, hashes, paths) never
    appears in the file. The HMAC covers the ciphertext, so tampering
    is caught before decryption.
    """
    plaintext = _canonical_payload_bytes(payload)
    enc_key = _derive_encryption_key(key)
    nonce = secrets.token_bytes(16)
    encrypted = nonce + _xor_with_keystream(enc_key, nonce, plaintext)
    wrapper: dict[str, Any] = {
        "format": ENCRYPTED_BASELINE_FORMAT,
        "data": base64.b64encode(encrypted).decode("ascii"),
    }
    signed = sign_baseline(wrapper, key)
    write_file_atomic(
        json_path, json.dumps(signed, indent=2, sort_keys=True).encode("utf-8")
    )


def _read_baseline_payload(data: dict[str, Any], key: bytes) -> dict[str, Any]:
    """Verify a baseline dict and return its plaintext payload.

    Handles both the new encrypted format and the old plain signed
    format (migration: old baselines load, and are re-written
    encrypted on the next init/update or key rotation).
    """
    if not verify_signed_baseline(data, key):
        raise BaselineError("Baseline tampered or corrupt.")
    if data.get("format") == ENCRYPTED_BASELINE_FORMAT:
        try:
            encrypted = base64.b64decode(str(data.get("data", "")), validate=True)
        except Exception as exc:
            raise BaselineError("Baseline tampered or corrupt.") from exc
        if len(encrypted) < 17:
            raise BaselineError("Baseline tampered or corrupt.")
        nonce, ciphertext = encrypted[:16], encrypted[16:]
        enc_key = _derive_encryption_key(key)
        plaintext = _xor_with_keystream(enc_key, nonce, ciphertext)
        try:
            payload = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BaselineError("Baseline tampered or corrupt.") from exc
        if not isinstance(payload, dict):
            raise BaselineError("Baseline is corrupt: payload is missing.")
        return payload
    return data


def _baseline_subdir_name(root: Path) -> str:
    """Return a safe, collision-free subfolder name for one folder.

    "<folder-name>_<first-12-hex-of-sha256-of-absolute-path>".
    Two folders with the same name in different places get different
    names, and the name can never contain a path separator.
    """
    resolved = str(Path(root).resolve())
    digest = hashlib.sha256(resolved.encode("utf-8")).hexdigest()[:12]
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(resolved).name) or "root"
    return f"{safe_name}_{digest}"


def resolve_baseline_dir(
    base_dir: Path, root: Path, single_folder: bool = True
) -> Path:
    """Return the baseline directory for one monitored folder.

    One folder keeps using baseline/ itself, exactly as in v1.0, so
    an existing single-folder baseline keeps working. When several
    folders are monitored at once, each gets its own
    baseline/<name>_<hash>/ subfolder. Switching from one folder to
    several (or back) requires re-running init for the folders
    involved - that migration is documented in the README.
    """
    base = Path(base_dir)
    if single_folder:
        return base
    return base / _baseline_subdir_name(root)


def find_baseline_dir(base_dir: Path, root: Path) -> Path:
    """Return the baseline directory that actually holds a folder's baseline.

    Prefers the single-folder location (baseline/ itself, v1.0), and
    falls back to the multi-folder subfolder when that is where the
    baseline lives - so verifying or scheduling one folder still works
    after the folder was initialised as part of several. When neither
    exists, the single-folder location is returned, so the error
    message stays the familiar "run fim init first".
    """
    base = Path(base_dir)
    if (base / "baseline.json").exists():
        return base
    multi = base / _baseline_subdir_name(root)
    if (multi / "baseline.json").exists():
        return multi
    return base


def rotate_baseline_key(baseline_dir: Path, key_path: Path) -> int:
    """Re-encrypt and re-sign a baseline with a fresh 32-byte key.

    The old baseline is verified first; a tampered baseline is
    refused and the key is left untouched. Returns the file count.
    Old-format baselines are migrated to the encrypted format.
    """
    baseline_dir = Path(baseline_dir)
    records = load_baseline(baseline_dir, key_path)
    payload = _load_baseline_payload_for_rotation(baseline_dir, key_path)
    new_key = secrets.token_bytes(32)
    key_path = Path(key_path)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    write_file_atomic(key_path, new_key)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        LOGGER.debug("Could not set 0600 on the key file.", exc_info=True)
    _write_baseline_json(baseline_dir / "baseline.json", payload, new_key)
    write_sha256_sidecar(baseline_dir / "baseline.json")
    return len(records)


def _load_baseline_payload_for_rotation(
    baseline_dir: Path, key_path: Path
) -> dict[str, Any]:
    """Load the raw payload dict for rotation, after verifying it."""
    baseline_dir = Path(baseline_dir)
    json_path = baseline_dir / "baseline.json"
    key = load_key(key_path)
    if key is None:
        raise BaselineError("HMAC key not found. Run fim init first.")
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineError(f"Baseline is corrupt and cannot be read: {exc}") from exc
    if not verify_sha256_sidecar(json_path):
        raise BaselineError("Baseline tampered or corrupt.")
    return _read_baseline_payload(data, key)


def get_theme_colours(theme: str) -> dict[str, str]:
    """Return the GUI colour map for a theme; pure logic, no display."""
    if theme == "dark":
        return {
            "background": "#1e1e1e",
            "surface": "#2b2b2b",
            "text": "#e8e8e8",
            "muted": "#a8a8a8",
            "field": "#333333",
            "heading": "#3a3a3a",
            "selected": "#0e639c",
        }
    return {
        "background": "#f0f0f0",
        "surface": "#ffffff",
        "text": "#1a1a1a",
        "muted": "#555555",
        "field": "#ffffff",
        "heading": "#e0e0e0",
        "selected": "#0078d7",
    }


def save_config(config_path: Path, config: dict[str, Any]) -> None:
    """Write a config dict back to disk as sorted, readable JSON."""
    config_path = Path(config_path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    write_file_atomic(
        config_path,
        (json.dumps(config, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )


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
        connection.execute(
            "CREATE TABLE IF NOT EXISTS meta (" "key TEXT PRIMARY KEY, value TEXT)"
        )
        connection.commit()


def _store_meta(database_path: Path, values: dict[str, str]) -> None:
    """Store small baseline metadata (path, created time) in SQLite."""
    with DB_WRITE_LOCK, sqlite3.connect(str(database_path)) as connection:
        connection.executemany(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
            list(values.items()),
        )
        connection.commit()


def _read_meta(database_path: Path) -> dict[str, str]:
    """Read baseline metadata from SQLite, or {} if it is absent."""
    if not Path(database_path).exists():
        return {}
    try:
        with sqlite3.connect(str(database_path)) as connection:
            rows = connection.execute("SELECT key, value FROM meta").fetchall()
        return {str(k): str(v) for k, v in rows}
    except Exception:  # noqa: BLE001 - old DBs have no meta table
        return {}


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
    created_utc = _utc_now_iso()
    _store_meta(
        database_path,
        {"monitored_path": str(root), "created_utc": created_utc},
    )
    payload: dict[str, Any] = {
        "version": BASELINE_VERSION,
        "created_utc": created_utc,
        "monitored_path": str(root),
        "files": [record.to_dict() for record in result.records],
    }
    json_path = baseline_dir / "baseline.json"
    # Encrypted at rest (see _write_baseline_json). Note the SQLite
    # baseline.db still holds the same records in plain form; protect
    # it with OS file permissions, as documented in the README.
    _write_baseline_json(json_path, payload, key)
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
    if not verify_sha256_sidecar(json_path):
        raise BaselineError("Baseline tampered or corrupt.")
    payload = _read_baseline_payload(data, key)
    files = payload.get("files")
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
        changes=changes,
        counts=counts,
        scanned_at_utc=_utc_now_iso(),
        records=list(result.records),
    )
    verify_result.mass_change = is_mass_change(
        verify_result.changes, counts.get("total", 0)
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
    # baseline.json is encrypted in v1.1, so path/created come from the
    # SQLite meta table (written by create_baseline), not from the JSON.
    meta = _read_meta(database_path)
    with sqlite3.connect(str(database_path)) as connection:
        count = connection.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        row = connection.execute(
            "SELECT scanned_utc, total, added, deleted, modified, renamed "
            "FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
    status: dict[str, Any] = {
        "monitored_path": meta.get("monitored_path", ""),
        "created_utc": meta.get("created_utc", ""),
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
        "mass_change": result.mass_change,
        "changes": [c.to_dict() for c in result.changes],
    }
    json_path = _unique_report_path(report_dir, stem, ".json")
    write_file_atomic(
        json_path, json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    )
    text_path = json_path.with_suffix(".txt")
    lines = [
        "File Integrity Monitor - verification report",
        f"Scanned at (UTC): {result.scanned_at_utc}",
        f"Monitored path: {sanitize_for_report(str(root))}",
        f"Counts: {result.counts}",
        "",
    ]
    if result.mass_change:
        lines.append(
            "[CRITICAL] MASS CHANGE DETECTED: "
            f"{len(result.changes)} files changed in one scan."
        )
        lines.append("")
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


def export_scan_results(
    report_dir: Path, root: Path, result: VerifyResult
) -> tuple[Path, Path]:
    """Export one verification (ALL files, not just changes) as JSON + CSV.

    This reuses the same timestamped naming as write_report, so exports
    never overwrite each other. Returns (json_path, csv_path).
    """
    report_dir = Path(report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y-%m-%d_%H-%M-%S")
    stem = f"fim-export-{stamp}"
    changed_by_path = {c.relative_path: c.kind for c in result.changes}
    rows: list[dict[str, Any]] = []
    for record in result.records:
        rows.append(
            {
                "relative_path": record.relative_path,
                "status": changed_by_path.get(record.relative_path, "OK"),
                "sha256": record.sha256,
                "size": record.size,
                "mtime_utc": record.mtime_utc,
            }
        )
    for change in result.changes:
        if change.relative_path not in {r.relative_path for r in result.records}:
            rows.append(
                {
                    "relative_path": change.relative_path,
                    "status": change.kind,
                    "sha256": change.new_record.sha256 if change.new_record else "",
                    "size": change.new_record.size if change.new_record else 0,
                    "mtime_utc": "",
                }
            )
    rows.sort(key=lambda row: row["relative_path"])
    payload = {
        "app": "file-integrity-monitor",
        "version": VERSION,
        "scanned_at_utc": result.scanned_at_utc,
        "monitored_path": str(root),
        "counts": result.counts,
        "files": rows,
    }
    json_path = _unique_report_path(report_dir, stem, ".json")
    write_file_atomic(
        json_path, json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    )
    csv_path = json_path.with_suffix(".csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["relative_path", "status", "sha256", "size", "mtime_utc"])
        for row in rows:
            writer.writerow(
                [
                    row["relative_path"],
                    row["status"],
                    row["sha256"],
                    row["size"],
                    row["mtime_utc"],
                ]
            )
    return json_path, csv_path


def send_alert(change: Change, config: dict[str, Any], log_dir: Path) -> None:
    """Send one change through every enabled alert channel, never crashing."""
    channels = config.get("alert_channels", ["console", "log"])
    now_utc = _utc_now_iso()
    local_now = datetime.now().astimezone().isoformat()
    message = (
        f"[ALERT] [{change.kind}] {change.relative_path} - "
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


def _send_email(subject: str, message: str) -> bool:
    """Send one email from SMTP settings in the environment, or False."""
    host = os.environ.get("FIM_SMTP_HOST", "")
    user = os.environ.get("FIM_SMTP_USER", "")
    password = os.environ.get("FIM_SMTP_PASSWORD", "")
    recipient = os.environ.get("FIM_ALERT_EMAIL", "")
    if not all([host, user, password, recipient]):
        LOGGER.info("Email alerts disabled: SMTP settings are not configured.")
        return False
    try:
        email = EmailMessage()
        email["Subject"] = subject
        email["From"] = user
        email["To"] = recipient
        email.set_content(message)
        with smtplib.SMTP(host, int(os.environ.get("FIM_SMTP_PORT", "587"))) as server:
            server.starttls()
            server.login(user, password)
            server.send_message(email)
        return True
    except Exception:
        LOGGER.exception("Email alert failed.")
        return False


def _send_email_alert(change: Change, message: str) -> None:
    """Send an email alert only when SMTP settings come from the environment."""
    _send_email(f"FIM alert: {change.kind} {change.relative_path}", message)


def is_mass_change(
    changes: list[Change],
    total_files: int,
    config: dict[str, Any] | None = None,
) -> bool:
    """Return True when a scan trips the mass-change rule.

    Rule (documented in the README): at least mass_change_threshold
    files changed (default 10) OR at least mass_change_percent of
    the files changed (default 20%), with at least 3 files changed
    for the percentage branch - so a single changed file in a tiny
    folder is not a "mass change". Either condition is enough.
    """
    if not changes:
        return False
    cfg = config or {}
    threshold = int(cfg.get("mass_change_threshold", 10))
    percent = int(cfg.get("mass_change_percent", 20))
    if len(changes) >= threshold:
        return True
    return bool(
        len(changes) >= 3
        and total_files > 0
        and len(changes) * 100 / total_files >= percent
    )


def _alert_mass_change(
    changes: list[Change],
    config: dict[str, Any],
    log_dir: Path,
    total_files: int,
    monitored_path: str = "",
) -> None:
    """Send one [CRITICAL] mass-change alert through every channel."""
    percent = (len(changes) * 100 / total_files) if total_files else 0
    message = (
        f"[CRITICAL] MASS CHANGE DETECTED: {len(changes)} of {total_files} "
        f"files changed ({percent:.0f}%)"
        + (f" in {monitored_path}" if monitored_path else "")
        + " - possible ransomware or mass tampering. "
        "Baseline NOT updated; review the changes before running update."
    )
    channels = config.get("alert_channels", ["console", "log"])
    if "console" in channels:
        print(f"{_utc_now_iso()} {message}")
    if "log" in channels:
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            with open(log_dir / "alerts.log", "a", encoding="utf-8") as handle:
                handle.write(f"{_utc_now_iso()} {message}\n")
        except OSError:
            LOGGER.exception("Could not write alerts.log.")
    if "desktop" in channels:
        try:
            from plyer import notification

            notification.notify(
                title="File Integrity Monitor - CRITICAL",
                message=message,
                timeout=10,
            )
        except Exception:
            LOGGER.debug("Desktop notification failed; continuing.", exc_info=True)
    if "webhook" in channels:
        send_webhook_alert(
            changes, config, monitored_path=monitored_path, mass_change=True
        )
    if "email" in channels:
        _send_email("FIM CRITICAL: mass change detected", message)


def alert_for_changes(
    changes: list[Change],
    config: dict[str, Any],
    log_dir: Path,
    result: VerifyResult | None = None,
    monitored_path: str = "",
) -> None:
    """Send alerts for every change in a verification result."""
    for change in changes:
        send_alert(change, config, log_dir)
    total = int(result.counts.get("total", 0)) if result is not None else 0
    mass_change = (
        bool(result.mass_change)
        if result is not None
        else is_mass_change(changes, total, config)
    )
    if mass_change:
        # The mass-change alert sends its own (flagged) webhook post.
        _alert_mass_change(changes, config, log_dir, total, monitored_path)
    elif changes and "webhook" in config.get("alert_channels", []):
        # One webhook post per verification, not one per changed file.
        send_webhook_alert(changes, config, monitored_path=monitored_path)


def mask_webhook_url(url: str) -> str:
    """Return a webhook URL with its path and query hidden for logging."""
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return "<invalid webhook url>"
    if not parsed.scheme or not parsed.netloc:
        return "<invalid webhook url>"
    masked_path = "/***" if parsed.path else ""
    return f"{parsed.scheme}://{parsed.netloc}{masked_path}"


def get_webhook_url(config: dict[str, Any]) -> str:
    """Return the webhook URL, with FIM_WEBHOOK_URL winning over config."""
    override = os.environ.get("FIM_WEBHOOK_URL", "").strip()
    if override:
        return override
    return str(config.get("webhook_url", "") or "").strip()


def validate_webhook_url(url: str) -> str:
    """Validate a webhook URL; return it stripped, or raise ConfigError.

    Only http/https URLs are accepted. A URL with embedded credentials
    is rejected. A localhost URL is allowed for local testing, but the
    caller is warned about it in the log.
    """
    cleaned = str(url or "").strip()
    if not cleaned:
        return ""
    parsed = urllib.parse.urlparse(cleaned)
    if parsed.scheme not in ("http", "https"):
        raise ConfigError(
            "Invalid config: webhook_url must start with http:// or https://."
        )
    if not parsed.netloc or parsed.username or parsed.password:
        raise ConfigError(
            "Invalid config: webhook_url must be a plain http(s) URL "
            "without embedded credentials."
        )
    host = (parsed.hostname or "").lower()
    if host in ("localhost", "127.0.0.1", "::1"):
        LOGGER.warning(
            "Webhook URL points at localhost (%s); use it for testing only.",
            mask_webhook_url(cleaned),
        )
    return cleaned


def build_webhook_payload(
    changes: list[Change],
    config: dict[str, Any],
    scanned_at_utc: str = "",
    monitored_path: str = "",
    mass_change: bool = False,
) -> dict[str, Any]:
    """Build the JSON payload for one verification, per webhook type."""
    webhook_type = str(config.get("webhook_type", "discord") or "discord")
    lines = [
        f"[{c.kind}] {c.relative_path}" + (f" (was {c.old_path})" if c.old_path else "")
        for c in changes
    ]
    summary = f"File Integrity Monitor: {len(changes)} change(s) detected"
    if mass_change:
        summary = "MASS CHANGE DETECTED: " + summary
    if monitored_path:
        summary += f" in {monitored_path}"
    change_dicts = [c.to_dict() for c in changes]
    if webhook_type == "slack":
        return {
            "text": summary,
            "blocks": [
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": summary},
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "\n".join(lines) or "No changes.",
                    },
                },
            ],
        }
    if webhook_type == "generic":
        return {
            "app": "file-integrity-monitor",
            "version": VERSION,
            "scanned_at_utc": scanned_at_utc or _utc_now_iso(),
            "monitored_path": monitored_path,
            "change_count": len(changes),
            "mass_change": mass_change,
            "changes": change_dicts,
        }
    # Discord (default): an embed with one line per change.
    return {
        "content": summary,
        "embeds": [
            {
                "title": "File Integrity Monitor",
                "description": "\n".join(lines) or "No changes.",
                "color": 15158332,
            }
        ],
    }


def send_webhook_alert(
    changes: list[Change],
    config: dict[str, Any],
    scanned_at_utc: str = "",
    monitored_path: str = "",
    mass_change: bool = False,
) -> bool:
    """POST one webhook alert; return True on success, False on any failure.

    Failures are logged (with the URL masked) and never raise, so a
    dead webhook can never crash a scan.
    """
    url = validate_webhook_url(get_webhook_url(config))
    if not url:
        LOGGER.info("Webhook alerts disabled: no webhook_url is configured.")
        return False
    payload = build_webhook_payload(
        changes, config, scanned_at_utc, monitored_path, mass_change=mass_change
    )
    try:
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "User-Agent": f"FileIntegrityMonitor/{VERSION}",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read()
        LOGGER.info("Webhook alert sent to %s.", mask_webhook_url(url))
        return True
    except Exception:  # noqa: BLE001 - webhook failure must never crash a scan
        LOGGER.warning(
            "Webhook alert failed for %s; continuing.", mask_webhook_url(url)
        )
        return False


def _parse_version(text: str) -> tuple[int, ...]:
    """Parse "1.1.0" (or "v1.1.0") into a tuple for comparison."""
    cleaned = str(text or "").strip().lstrip("vV")
    parts: list[int] = []
    for piece in cleaned.split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts) if parts else (0,)


def check_for_update(
    current_version: str = VERSION,
    timeout: int = 10,
) -> dict[str, Any]:
    """Ask the GitHub Releases API for the latest release.

    Returns a dict with current_version, latest_version,
    is_update_available, download_url and release_url - or an "error"
    key when the network or the API fails. It never raises.
    """
    try:
        request = urllib.request.Request(
            UPDATE_API_URL,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": f"FileIntegrityMonitor/{current_version}",
            },
            method="GET",
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - network failure is a friendly message
        return {
            "current_version": current_version,
            "latest_version": "",
            "is_update_available": False,
            "download_url": "",
            "release_url": "",
            "error": str(exc),
        }
    if not isinstance(data, dict):
        return {
            "current_version": current_version,
            "latest_version": "",
            "is_update_available": False,
            "download_url": "",
            "release_url": "",
            "error": "Unexpected response from the GitHub API.",
        }
    latest = str(data.get("tag_name", "") or "").strip()
    assets = data.get("assets") or []
    download_url = ""
    if isinstance(assets, list):
        for asset in assets:
            if isinstance(asset, dict) and str(asset.get("name", "")).endswith(".exe"):
                download_url = str(asset.get("browser_download_url", "") or "")
                break
    return {
        "current_version": current_version,
        "latest_version": latest,
        "is_update_available": bool(
            latest and _parse_version(latest) > _parse_version(current_version)
        ),
        "download_url": download_url,
        "release_url": str(data.get("html_url", "") or ""),
    }


def load_config(config_path: Path | None) -> dict[str, Any]:
    """Load and validate a config file; missing file means defaults."""
    config: dict[str, Any] = dict(DEFAULT_CONFIG)
    if config_path is None:
        return config
    path = Path(config_path)
    if not path.exists():
        LOGGER.warning("Config file not found: %s - using defaults.", path)
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
    # FIM_WEBHOOK_URL wins over the config file, and is never written back.
    env_webhook = os.environ.get("FIM_WEBHOOK_URL", "").strip()
    if env_webhook:
        config["webhook_url"] = env_webhook
    webhook_url = str(config.get("webhook_url", "") or "")
    config["webhook_url"] = validate_webhook_url(webhook_url)
    webhook_type = str(config.get("webhook_type", "discord") or "discord")
    if webhook_type not in WEBHOOK_TYPES:
        raise ConfigError(
            "Invalid config: webhook_type must be one of "
            f"{', '.join(WEBHOOK_TYPES)}."
        )
    config["webhook_type"] = webhook_type
    channels = config.get("alert_channels", ["console", "log"])
    if not isinstance(channels, list) or any(
        str(c) not in ALERT_CHANNELS for c in channels
    ):
        raise ConfigError(
            "Invalid config: alert_channels must only contain "
            f"{', '.join(ALERT_CHANNELS)}."
        )
    if "webhook" in channels and not config["webhook_url"]:
        LOGGER.warning(
            "alert_channels includes 'webhook' but no webhook_url is set; "
            "webhook alerts will be skipped."
        )
    threshold = config.get("mass_change_threshold", 10)
    if (
        not isinstance(threshold, int)
        or isinstance(threshold, bool)
        or threshold < 1
        or threshold > 10000
    ):
        raise ConfigError(
            "Invalid config: mass_change_threshold must be an integer "
            "between 1 and 10000."
        )
    percent = config.get("mass_change_percent", 20)
    if (
        not isinstance(percent, int)
        or isinstance(percent, bool)
        or percent < 1
        or percent > 100
    ):
        raise ConfigError(
            "Invalid config: mass_change_percent must be an integer "
            "between 1 and 100."
        )
    theme = str(config.get("gui_theme", "light") or "light")
    if theme not in ("light", "dark"):
        raise ConfigError('Invalid config: gui_theme must be "light" or "dark".')
    config["gui_theme"] = theme
    if not isinstance(config.get("check_for_updates", True), bool):
        raise ConfigError("Invalid config: check_for_updates must be true or false.")
    scheduled = config.get("scheduled_scan_interval_minutes", 0)
    if (
        not isinstance(scheduled, int)
        or isinstance(scheduled, bool)
        or scheduled < 0
        or (scheduled != 0 and scheduled < 5)
        or scheduled > 1440
    ):
        raise ConfigError(
            "Invalid config: scheduled_scan_interval_minutes must be 0 (off) "
            "or between 5 and 1440 minutes."
        )
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
    print("File Integrity Monitor - summary")
    print(f"  Total:              {counts.get('total', 0)}")
    print(f"  Unchanged:          {counts.get('unchanged', 0)}")
    print(f"  Added:              {counts.get('added', 0)}")
    print(f"  Deleted:            {counts.get('deleted', 0)}")
    print(f"  Modified:           {counts.get('modified', 0)}")
    print(f"  Renamed:            {counts.get('renamed', 0)}")
    print(f"  Permission changed: {counts.get('permission_changed', 0)}")
    print(f"  Errors:             {counts.get('errors', 0)}")
    if result.mass_change:
        print(
            "[CRITICAL] MASS CHANGE DETECTED: "
            f"{len(result.changes)} files changed in one scan. "
            "Baseline NOT updated."
        )
    if result.changes:
        print("Changes:")
        for change in result.changes:
            print(f"  [{change.kind}] {change.relative_path}")
    else:
        print("No changes detected.")
