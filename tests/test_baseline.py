# Tests for baseline creation, storage and loading.
"""Baseline tests: init, signed JSON, sidecar, status and history."""

from __future__ import annotations

import json

import pytest

from fim_core import (
    BaselineError,
    create_baseline,
    get_history,
    get_status,
    load_baseline,
    load_or_create_key,
    verify_sha256_sidecar,
)


def test_create_baseline_writes_db_and_signed_json(
    monitored_dir, baseline_dir, key_path
) -> None:
    """Init must create baseline.db, a signed baseline.json and a sidecar."""
    result = create_baseline(monitored_dir, baseline_dir, key_path)
    assert len(result.records) == 3
    assert (baseline_dir / "baseline.db").exists()
    assert (baseline_dir / "baseline.json").exists()
    assert (baseline_dir / "baseline.json.sha256").exists()
    assert verify_sha256_sidecar(baseline_dir / "baseline.json")


def test_baseline_json_is_signed(monitored_dir, baseline_dir, key_path) -> None:
    """The exported JSON must carry an HMAC field that is not the key."""
    create_baseline(monitored_dir, baseline_dir, key_path)
    data = json.loads((baseline_dir / "baseline.json").read_text(encoding="utf-8"))
    assert "hmac" in data
    assert len(data["hmac"]) == 64
    assert data["version"] == 1
    assert key_path.read_bytes().hex() not in (
        baseline_dir / "baseline.json"
    ).read_text(encoding="utf-8")


def test_key_is_32_random_bytes(key_path) -> None:
    """The key must be 32 bytes, and two fresh keys must differ."""
    first = load_or_create_key(key_path)
    assert len(first) == 32
    second_path = key_path.parent / "other.key"
    second = load_or_create_key(second_path)
    assert len(second) == 32
    assert first != second
    # Loading again returns the same key, it does not create a new one.
    assert load_or_create_key(key_path) == first


def test_load_baseline_round_trip(monitored_dir, baseline_dir, key_path) -> None:
    """A baseline written by init must load back with the same records."""
    created = create_baseline(monitored_dir, baseline_dir, key_path)
    loaded = load_baseline(baseline_dir, key_path)
    assert [r.relative_path for r in loaded] == [
        r.relative_path for r in created.records
    ]
    assert [r.sha256 for r in loaded] == [r.sha256 for r in created.records]


def test_verify_without_baseline_raises(baseline_dir, key_path) -> None:
    """Loading a baseline that was never created must raise BaselineError."""
    with pytest.raises(BaselineError, match="Run fim init first"):
        load_baseline(baseline_dir, key_path)


def test_status_reports_file_count(monitored_dir, baseline_dir, key_path) -> None:
    """Status must report the monitored path and the file count."""
    create_baseline(monitored_dir, baseline_dir, key_path)
    status = get_status(baseline_dir)
    assert status["file_count"] == 3
    assert status["monitored_path"] == str(monitored_dir.resolve())
    assert status["created_utc"]


def test_history_is_empty_before_any_verify(
    monitored_dir, baseline_dir, key_path
) -> None:
    """History is empty until at least one verification has run."""
    create_baseline(monitored_dir, baseline_dir, key_path)
    assert get_history(baseline_dir) == []


def test_exclude_pattern_skips_files(monitored_dir, baseline_dir, key_path) -> None:
    """Excluded patterns must keep a file out of the baseline."""
    (monitored_dir / "notes.tmp").write_text("temporary\n", encoding="utf-8")
    result = create_baseline(monitored_dir, baseline_dir, key_path, exclude=["*.tmp"])
    names = [r.relative_path for r in result.records]
    assert "notes.tmp" not in names
    assert len(result.records) == 3


def test_include_pattern_limits_files(monitored_dir, baseline_dir, key_path) -> None:
    """An include pattern must limit the baseline to matching files."""
    result = create_baseline(monitored_dir, baseline_dir, key_path, include=["*.txt"])
    assert len(result.records) == 3
    result = create_baseline(monitored_dir, baseline_dir, key_path, include=["a.txt"])
    assert [r.relative_path for r in result.records] == ["a.txt"]


def test_max_size_skips_large_files(monitored_dir, baseline_dir, key_path) -> None:
    """Files over max_size_mb must be skipped with a reason, not hashed."""
    big = monitored_dir / "big.bin"
    big.write_bytes(b"x" * (2 * 1024 * 1024))
    result = create_baseline(monitored_dir, baseline_dir, key_path, max_size_mb=1)
    names = [r.relative_path for r in result.records]
    assert "big.bin" not in names
    assert any("big.bin" in line for line in result.skipped)
