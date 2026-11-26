# Tests for verification: added, deleted, modified, renamed, permission.
"""Scan tests: every change class, exit-relevant counts, and reports."""

from __future__ import annotations

import json
import os

import pytest

from fim_core import create_baseline, get_history, update_baseline, verify_baseline


def _verify(monitored_dir, baseline_dir, key_path, report_dir=None):
    """Run a verification with the test baseline and key."""
    return verify_baseline(monitored_dir, baseline_dir, key_path, report_dir=report_dir)


def test_clean_verify_has_no_changes(monitored_dir, baseline_dir, key_path) -> None:
    """Verifying an unchanged tree must report zero changes."""
    create_baseline(monitored_dir, baseline_dir, key_path)
    result = _verify(monitored_dir, baseline_dir, key_path)
    assert result.changes == []
    assert result.counts["unchanged"] == 3
    assert result.counts["total"] == 3


def test_modified_file_detected(monitored_dir, baseline_dir, key_path) -> None:
    """Changing one byte must be reported as MODIFIED with old and new hashes."""
    create_baseline(monitored_dir, baseline_dir, key_path)
    (monitored_dir / "a.txt").write_text("hello world, changed\n", encoding="utf-8")
    result = _verify(monitored_dir, baseline_dir, key_path)
    kinds = [(c.kind, c.relative_path) for c in result.changes]
    assert ("MODIFIED", "a.txt") in kinds
    assert result.counts["modified"] == 1
    modified = next(c for c in result.changes if c.kind == "MODIFIED")
    assert modified.old_record is not None and modified.new_record is not None
    assert modified.old_record.sha256 != modified.new_record.sha256
    assert modified.old_record.size != modified.new_record.size


def test_added_file_detected(monitored_dir, baseline_dir, key_path) -> None:
    """A new file must be reported as ADDED."""
    create_baseline(monitored_dir, baseline_dir, key_path)
    (monitored_dir / "new.txt").write_text("brand new\n", encoding="utf-8")
    result = _verify(monitored_dir, baseline_dir, key_path)
    assert ("ADDED", "new.txt") in [(c.kind, c.relative_path) for c in result.changes]
    assert result.counts["added"] == 1


def test_deleted_file_detected(monitored_dir, baseline_dir, key_path) -> None:
    """Removing a file must be reported as DELETED."""
    create_baseline(monitored_dir, baseline_dir, key_path)
    (monitored_dir / "a.txt").unlink()
    result = _verify(monitored_dir, baseline_dir, key_path)
    assert ("DELETED", "a.txt") in [(c.kind, c.relative_path) for c in result.changes]
    assert result.counts["deleted"] == 1


def test_renamed_file_detected_not_added_plus_deleted(
    monitored_dir, baseline_dir, key_path
) -> None:
    """Moving a file must be reported as one RENAMED, not ADDED + DELETED."""
    create_baseline(monitored_dir, baseline_dir, key_path)
    (monitored_dir / "a.txt").rename(monitored_dir / "renamed.txt")
    result = _verify(monitored_dir, baseline_dir, key_path)
    kinds = [(c.kind, c.relative_path) for c in result.changes]
    assert ("RENAMED", "renamed.txt") in kinds
    assert result.counts["renamed"] == 1
    assert result.counts["added"] == 0
    assert result.counts["deleted"] == 0


def test_permission_change_detected(monitored_dir, baseline_dir, key_path) -> None:
    """Changing only permissions must be reported as PERMISSION_CHANGED."""
    if os.name == "nt":
        pytest.skip("Permission bits are not meaningful on Windows.")
    create_baseline(monitored_dir, baseline_dir, key_path)
    os.chmod(monitored_dir / "a.txt", 0o600)
    result = _verify(monitored_dir, baseline_dir, key_path)
    assert ("PERMISSION_CHANGED", "a.txt") in [
        (c.kind, c.relative_path) for c in result.changes
    ]
    assert result.counts["permission_changed"] == 1


def test_empty_file_in_baseline(monitored_dir, baseline_dir, key_path) -> None:
    """An empty file must be in the baseline and verify as unchanged."""
    from fim_core import EMPTY_SHA256

    result = create_baseline(monitored_dir, baseline_dir, key_path)
    empty = next(r for r in result.records if r.relative_path == "empty.txt")
    assert empty.sha256 == EMPTY_SHA256
    assert empty.size == 0
    verify = _verify(monitored_dir, baseline_dir, key_path)
    assert verify.changes == []


def test_update_after_change_clears_it(monitored_dir, baseline_dir, key_path) -> None:
    """After update --force, the next verify must be clean."""
    create_baseline(monitored_dir, baseline_dir, key_path)
    (monitored_dir / "a.txt").write_text("changed\n", encoding="utf-8")
    assert _verify(monitored_dir, baseline_dir, key_path).changes
    update_baseline(monitored_dir, baseline_dir, key_path)
    assert _verify(monitored_dir, baseline_dir, key_path).changes == []


def test_verify_writes_report(
    monitored_dir, baseline_dir, key_path, report_dir
) -> None:
    """Verify must write a JSON report and record the scan in history."""
    create_baseline(monitored_dir, baseline_dir, key_path)
    (monitored_dir / "a.txt").write_text("changed\n", encoding="utf-8")
    _verify(monitored_dir, baseline_dir, key_path, report_dir=report_dir)
    reports = sorted(report_dir.glob("fim-report-*.json"))
    assert len(reports) == 1
    data = json.loads(reports[0].read_text(encoding="utf-8"))
    assert data["counts"]["modified"] == 1
    assert (report_dir / reports[0].name.replace(".json", ".txt")).exists()
    assert (report_dir / reports[0].name.replace(".json", ".csv")).exists()
    assert len(get_history(baseline_dir)) == 1


def test_verify_on_missing_folder_raises(tmp_path, baseline_dir, key_path) -> None:
    """Verifying a folder that does not exist must raise an error."""
    from fim_core import FimError

    create_baseline(tmp_path / "real", baseline_dir, key_path) if False else None
    with pytest.raises(FimError):
        verify_baseline(tmp_path / "does-not-exist", baseline_dir, key_path)


def test_multiple_changes_in_one_run(monitored_dir, baseline_dir, key_path) -> None:
    """Modify, add and delete in one run must all be classified correctly."""
    create_baseline(monitored_dir, baseline_dir, key_path)
    (monitored_dir / "a.txt").write_text("modified\n", encoding="utf-8")
    (monitored_dir / "sub" / "b.txt").unlink()
    (monitored_dir / "new.txt").write_text("new\n", encoding="utf-8")
    result = _verify(monitored_dir, baseline_dir, key_path)
    kinds = {c.kind for c in result.changes}
    assert kinds == {"MODIFIED", "DELETED", "ADDED"}
