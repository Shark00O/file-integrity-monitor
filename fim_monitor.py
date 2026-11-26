# File Integrity Monitor — real-time monitoring.
# Polling is the default; watchdog is used only when it is installed.
"""Polling and watchdog monitoring for the File Integrity Monitor.

This module is deliberately separate from fim_core: the core knows how
to hash and compare, this module knows how to watch a tree over time.
A monitor run never updates the baseline on its own — it only reports.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

from fim_core import (
    alert_for_changes,
    get_project_root,
    verify_baseline,
)

LOGGER = logging.getLogger("fim_monitor")
_STOP_REQUESTED = threading.Event()


def _handle_signal(signum: int, frame: Any) -> None:
    """Ask the polling loop to stop cleanly on Ctrl+C or terminate."""
    _STOP_REQUESTED.set()


def _watchdog_available() -> bool:
    """Return True only when the watchdog package can be imported."""
    try:
        import watchdog  # noqa: F401

        return True
    except ImportError:
        return False


def run_monitor(
    root: Path,
    baseline_dir: Path,
    key_path: Path,
    config: dict[str, Any],
    interval: int = 60,
    use_watchdog: bool = True,
    max_cycles: int | None = None,
    on_change: Any = None,
) -> int:
    """Monitor a tree, alerting on every change, until stopped.

    Returns the total number of changes detected. max_cycles is used
    by tests and by short supervised runs; None means run forever.
    """
    if not 10 <= interval <= 3600:
        raise ValueError("interval must be between 10 and 3600 seconds")
    _STOP_REQUESTED.clear()
    try:
        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)
    except (ValueError, OSError):
        LOGGER.debug("Could not install signal handlers (not the main thread).")
    total_changes = 0
    if use_watchdog and _watchdog_available():
        total_changes = _run_watchdog(
            root, baseline_dir, key_path, config, interval, max_cycles, on_change
        )
    else:
        if use_watchdog:
            print("Watchdog is not installed; falling back to polling.")
            LOGGER.info("Watchdog is not installed; falling back to polling.")
        total_changes = _run_polling(
            root, baseline_dir, key_path, config, interval, max_cycles, on_change
        )
    return total_changes


def _run_polling(
    root: Path,
    baseline_dir: Path,
    key_path: Path,
    config: dict[str, Any],
    interval: int,
    max_cycles: int | None,
    on_change: Any,
) -> int:
    """Re-verify on a timer; each cycle alerts in the same cycle."""
    total_changes = 0
    cycles = 0
    log_dir = get_project_root() / "logs"
    while not _STOP_REQUESTED.is_set():
        try:
            result = verify_baseline(
                root,
                baseline_dir,
                key_path,
                recursive=config.get("recursive", True),
                include=config.get("include_patterns", []),
                exclude=config.get("exclude_patterns", []),
                max_size_mb=config.get("max_file_size_mb", 0),
                chunk_size=config.get("hash_chunk_size", 65536),
                report_dir=get_project_root()
                / str(config.get("report_dir", "reports")),
            )
        except Exception as exc:
            LOGGER.error("Monitor scan failed: %s", exc)
            cycles += 1
            if max_cycles is not None and cycles >= max_cycles:
                break
            _STOP_REQUESTED.wait(interval)
            continue
        if result.changes:
            total_changes += len(result.changes)
            alert_for_changes(result.changes, config, log_dir)
            if on_change is not None:
                on_change(result.changes)
        cycles += 1
        if max_cycles is not None and cycles >= max_cycles:
            break
        _STOP_REQUESTED.wait(interval)
    return total_changes


def _run_watchdog(
    root: Path,
    baseline_dir: Path,
    key_path: Path,
    config: dict[str, Any],
    interval: int,
    max_cycles: int | None,
    on_change: Any,
) -> int:
    """Use watchdog events to trigger a verify, with polling as a safety net."""
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    log_dir = get_project_root() / "logs"
    state: dict[str, Any] = {"changes": 0, "cycles": 0, "dirty": True}

    class ChangeHandler(FileSystemEventHandler):
        """Mark the tree dirty on any filesystem event."""

        def on_any_event(self, event: Any) -> None:
            state["dirty"] = True

    observer = Observer()
    observer.schedule(
        ChangeHandler(), str(root), recursive=config.get("recursive", True)
    )
    observer.start()
    try:
        while not _STOP_REQUESTED.is_set():
            if state["dirty"]:
                state["dirty"] = False
                try:
                    result = verify_baseline(
                        root,
                        baseline_dir,
                        key_path,
                        recursive=config.get("recursive", True),
                        include=config.get("include_patterns", []),
                        exclude=config.get("exclude_patterns", []),
                        max_size_mb=config.get("max_file_size_mb", 0),
                        chunk_size=config.get("hash_chunk_size", 65536),
                        report_dir=get_project_root()
                        / str(config.get("report_dir", "reports")),
                    )
                except Exception as exc:
                    LOGGER.error("Monitor scan failed: %s", exc)
                    result = None
                if result is not None and result.changes:
                    state["changes"] += len(result.changes)
                    alert_for_changes(result.changes, config, log_dir)
                    if on_change is not None:
                        on_change(result.changes)
                state["cycles"] += 1
                if max_cycles is not None and state["cycles"] >= max_cycles:
                    break
            _STOP_REQUESTED.wait(min(interval, 5))
            if max_cycles is not None and state["cycles"] >= max_cycles:
                break
    finally:
        observer.stop()
        observer.join(timeout=5)
    return int(state["changes"])


def start_daemon(root: Path, interval: int = 60) -> subprocess.Popen:
    """Start a detached background monitor process and return it."""
    project_root = get_project_root()
    if getattr(sys, "frozen", False):
        # Frozen .exe: run the exe itself, there is no fim.py to launch.
        command = [
            sys.executable,
            "monitor",
            "--path",
            str(root),
            "--interval",
            str(interval),
        ]
    else:
        command = [
            sys.executable,
            str(project_root / "fim.py"),
            "monitor",
            "--path",
            str(root),
            "--interval",
            str(interval),
        ]
    if os.name == "nt":
        creation_flags = 0x00000008  # DETACHED_PROCESS, documented Windows flag.
        return subprocess.Popen(
            command,
            creationflags=creation_flags,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
    return subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )


def stop_monitor() -> None:
    """Request a running monitor loop in this process to stop."""
    _STOP_REQUESTED.set()
