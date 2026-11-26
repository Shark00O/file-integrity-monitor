# Shared fixtures for the File Integrity Monitor tests.
# Every test uses a fresh temporary directory, so tests never touch
# a real baseline, a real key file, or each other's files.
"""Pytest fixtures: a small monitored tree plus isolated baseline/key paths."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture()
def monitored_dir(tmp_path: Path) -> Path:
    """A small tree: two text files, one nested file, one empty file."""
    root = tmp_path / "monitored"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_text("hello world\n", encoding="utf-8")
    (root / "sub" / "b.txt").write_text("second file\n", encoding="utf-8")
    (root / "empty.txt").write_text("", encoding="utf-8")
    return root


@pytest.fixture()
def baseline_dir(tmp_path: Path) -> Path:
    """An empty directory that will hold a test baseline."""
    directory = tmp_path / "baseline"
    directory.mkdir()
    return directory


@pytest.fixture()
def key_path(tmp_path: Path) -> Path:
    """A key path inside the temporary directory, never the real one."""
    return tmp_path / "fim.key"


@pytest.fixture()
def report_dir(tmp_path: Path) -> Path:
    """An empty directory that will hold test reports."""
    directory = tmp_path / "reports"
    directory.mkdir()
    return directory


@pytest.fixture()
def log_dir(tmp_path: Path) -> Path:
    """An empty directory that will hold test logs."""
    directory = tmp_path / "logs"
    directory.mkdir()
    return directory
