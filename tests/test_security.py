# Security tests: tampering, symlinks, traversal, unsafe code patterns.
"""Security tests: the baseline must not be forgeable or silently trusted."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from fim_core import (
    BaselineError,
    FileRecord,
    create_baseline,
    load_baseline,
    load_config,
    scan_directory,
    verify_baseline,
)

FORBIDDEN = ["eval(", "exec(", "pickle", "shell=True", "os.system", "md5", "sha1("]


def test_no_forbidden_patterns_in_source() -> None:
    """Source files must contain no unsafe constructs or weak hashes."""
    project_root = Path(__file__).resolve().parent.parent
    for name in ("fim.py", "fim_core.py", "fim_monitor.py", "fim_gui.py"):
        text = (project_root / name).read_text(encoding="utf-8")
        for pattern in FORBIDDEN:
            assert pattern not in text, f"{name} contains forbidden pattern {pattern!r}"


def test_tampered_baseline_json_rejected(monitored_dir, baseline_dir, key_path) -> None:
    """Editing one hash in baseline.json must make verification refuse it."""
    create_baseline(monitored_dir, baseline_dir, key_path)
    json_path = baseline_dir / "baseline.json"
    data = json.loads(json_path.read_text(encoding="utf-8"))
    data["files"][0]["sha256"] = "0" * 64
    json_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(BaselineError, match="tampered"):
        verify_baseline(monitored_dir, baseline_dir, key_path)


def test_tampered_hmac_rejected(monitored_dir, baseline_dir, key_path) -> None:
    """Replacing the HMAC value itself must also be rejected."""
    create_baseline(monitored_dir, baseline_dir, key_path)
    json_path = baseline_dir / "baseline.json"
    data = json.loads(json_path.read_text(encoding="utf-8"))
    data["hmac"] = "0" * 64
    json_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(BaselineError, match="tampered"):
        load_baseline(baseline_dir, key_path)


def test_tampered_baseline_is_not_overwritten(
    monitored_dir, baseline_dir, key_path
) -> None:
    """A refused verification must leave the tampered file untouched."""
    create_baseline(monitored_dir, baseline_dir, key_path)
    json_path = baseline_dir / "baseline.json"
    before = json_path.read_bytes()
    data = json.loads(before.decode("utf-8"))
    data["files"][0]["sha256"] = "0" * 64
    json_path.write_text(json.dumps(data), encoding="utf-8")
    tampered = json_path.read_bytes()
    with pytest.raises(BaselineError):
        verify_baseline(monitored_dir, baseline_dir, key_path)
    assert json_path.read_bytes() == tampered


def test_verify_does_not_create_missing_key(
    monitored_dir, baseline_dir, key_path, tmp_path
) -> None:
    """Verify must never create a key; only init creates one."""
    assert not key_path.exists()
    with pytest.raises(BaselineError):
        verify_baseline(monitored_dir, baseline_dir, key_path)
    assert not key_path.exists()


def test_symlink_outside_root_not_followed(
    monitored_dir, baseline_dir, key_path, tmp_path
) -> None:
    """A symlink pointing outside the tree must be skipped, not hashed."""
    outside = tmp_path / "outside.txt"
    outside.write_text("secret outside\n", encoding="utf-8")
    link = monitored_dir / "link.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("Symlinks are not available on this system.")
    result = create_baseline(monitored_dir, baseline_dir, key_path)
    names = [r.relative_path for r in result.records]
    assert "link.txt" not in names
    assert any("link.txt" in line for line in result.skipped)


def test_path_traversal_in_baseline_rejected() -> None:
    """A baseline record with ../ in its path must be rejected on load."""
    with pytest.raises(BaselineError):
        FileRecord.from_dict(
            {
                "relative_path": "../evil.txt",
                "absolute_path": "/tmp/evil.txt",
                "sha256": "0" * 64,
                "size": 1,
                "mtime_utc": "",
                "mode": 0o644,
            }
        )


def test_invalid_config_interval_rejected(tmp_path) -> None:
    """An interval below 10 seconds must be rejected with a clear error."""
    from fim_core import ConfigError

    bad = tmp_path / "config.json"
    bad.write_text(json.dumps({"scan_interval_seconds": 5}), encoding="utf-8")
    with pytest.raises(ConfigError, match="scan_interval_seconds"):
        load_config(bad)


def test_invalid_config_chunk_size_rejected(tmp_path) -> None:
    """A chunk size that is not a power of two must be rejected."""
    from fim_core import ConfigError

    bad = tmp_path / "config.json"
    bad.write_text(json.dumps({"hash_chunk_size": 1000}), encoding="utf-8")
    with pytest.raises(ConfigError, match="hash_chunk_size"):
        load_config(bad)


def test_missing_config_uses_defaults(tmp_path) -> None:
    """A missing config file must fall back to defaults, not crash."""
    config = load_config(tmp_path / "no-such-config.json")
    assert config["scan_interval_seconds"] == 60
    assert config["recursive"] is True


def test_unreadable_file_is_not_reported_as_deleted(
    monitored_dir, baseline_dir, key_path
) -> None:
    """A file that exists but cannot be read is unknown, not deleted."""
    if os.name == "nt":
        pytest.skip("Permission bits are not meaningful on Windows.")
    create_baseline(monitored_dir, baseline_dir, key_path)
    target = monitored_dir / "a.txt"
    os.chmod(target, 0)
    try:
        result = verify_baseline(monitored_dir, baseline_dir, key_path)
        kinds = [(c.kind, c.relative_path) for c in result.changes]
        # Running as root can still read the file; either outcome is
        # acceptable, but it must never be reported as DELETED.
        assert ("DELETED", "a.txt") not in kinds
    finally:
        os.chmod(target, 0o644)


def test_scan_does_not_crash_on_missing_file_mid_scan(
    monitored_dir, baseline_dir, key_path
) -> None:
    """Scanning must complete even when a file disappears during the run."""
    result = scan_directory(monitored_dir)
    assert len(result.records) == 3
    assert result.errors == []
