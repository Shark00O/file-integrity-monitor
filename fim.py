# File Integrity Monitor - command-line interface.
# Thin wrapper: every real decision lives in fim_core / fim_monitor.
"""Command-line entry point for the File Integrity Monitor.

Usage examples are in README.md. Every command returns one of the
documented exit codes: 0 = no changes, 1 = changes detected, 2 = error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fim_core import (
    EXIT_CHANGES,
    EXIT_ERROR,
    EXIT_OK,
    VERSION,
    BaselineError,
    ConfigError,
    FimError,
    alert_for_changes,
    check_for_update,
    create_baseline,
    enable_windows_colours,
    find_baseline_dir,
    get_history,
    get_project_root,
    get_status,
    load_config,
    print_summary,
    resolve_baseline_dir,
    rotate_baseline_key,
    setup_logging,
    update_baseline,
    validate_path,
    verify_baseline,
)
from fim_monitor import run_monitor, start_daemon


def _split_patterns(value: str | None) -> list[str]:
    """Split a comma-separated pattern list, dropping empty items."""
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _project_root() -> Path:
    """Return the directory containing this file (or the .exe, when frozen)."""
    return get_project_root()


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the flags shared by init, verify, update and monitor."""
    parser.add_argument(
        "--path",
        dest="paths",
        action="append",
        default=None,
        help="Directory to monitor; repeat --path for several folders, "
        "or give a comma-separated list",
    )
    parser.add_argument("--config", default="", help="Path to config.json")
    parser.add_argument("--baseline-dir", default="", help="Baseline directory")
    parser.add_argument("--recursive", action="store_true", default=True)
    parser.add_argument("--no-recursive", dest="recursive", action="store_false")
    parser.add_argument(
        "--include", default="", help="Comma-separated glob patterns to include"
    )
    parser.add_argument(
        "--exclude", default="", help="Comma-separated glob patterns to exclude"
    )
    parser.add_argument(
        "--max-size",
        type=int,
        default=0,
        help="Skip files over this many MB (0 = no limit)",
    )
    parser.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="Follow symlinks (off by default)",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")


def _collect_paths(args: argparse.Namespace, config: dict) -> list[str]:
    """Collect monitored paths: repeatable --path wins, else config."""
    cli: list[str] = []
    for item in getattr(args, "paths", None) or []:
        cli.extend(part.strip() for part in str(item).split(",") if part.strip())
    if cli:
        seen: list[str] = []
        for item in cli:
            if item not in seen:
                seen.append(item)
        return seen
    configured = [str(item) for item in config.get("monitored_paths", []) if str(item)]
    return configured


def _scan_kwargs(config: dict, args: argparse.Namespace) -> dict:
    """Keyword arguments shared by create/verify/update calls."""
    return {
        "recursive": config["recursive"],
        "include": config["include_patterns"],
        "exclude": config["exclude_patterns"],
        "max_size_mb": config["max_file_size_mb"],
        "follow_symlinks": args.follow_symlinks,
        "chunk_size": config["hash_chunk_size"],
    }


def _resolve_settings(
    args: argparse.Namespace,
) -> tuple[dict, list[tuple[Path, Path]], Path]:
    """Merge config and CLI flags; CLI wins.

    Returns (config, [(root, baseline_dir), ...], key_path). One folder
    uses baseline/ itself (v1.0 layout); several folders each get
    baseline/<name>_<hash>/ (see resolve_baseline_dir).
    """
    root_dir = _project_root()
    config_path = Path(args.config) if args.config else root_dir / "config.json"
    config = load_config(config_path if config_path.exists() else None)
    if args.verbose:
        config["log_level"] = "DEBUG"
    if args.include:
        config["include_patterns"] = _split_patterns(args.include)
    if args.exclude:
        config["exclude_patterns"] = _split_patterns(args.exclude)
    if args.max_size:
        config["max_file_size_mb"] = args.max_size
    if args.recursive is False:
        config["recursive"] = False
    paths = _collect_paths(args, config)
    if not paths:
        raise ConfigError(
            "No monitored path given. Use --path or set monitored_paths "
            "in config.json."
        )
    roots = [validate_path(Path(item)) for item in paths]
    base = (
        Path(args.baseline_dir)
        if args.baseline_dir
        else root_dir / str(config.get("baseline_path", "baseline"))
    )
    pairs = [
        (
            root,
            (
                find_baseline_dir(base, root)
                if len(roots) == 1
                else resolve_baseline_dir(base, root, single_folder=False)
            ),
        )
        for root in roots
    ]
    from fim_core import get_key_path

    key_path = get_key_path()
    setup_logging(root_dir / "logs", str(config.get("log_level", "INFO")))
    return config, pairs, key_path


def _command_init(args: argparse.Namespace) -> int:
    """Create a baseline for every monitored folder."""
    config, pairs, key_path = _resolve_settings(args)
    for root, baseline_dir in pairs:
        json_path = baseline_dir / "baseline.json"
        if json_path.exists() and not args.force:
            answer = (
                input(f"Baseline already exists at {json_path}. Overwrite it? [y/N] ")
                .strip()
                .lower()
            )
            if answer != "y":
                print(f"Baseline creation cancelled for {root}.")
                continue
        result = create_baseline(
            root, baseline_dir, key_path, **_scan_kwargs(config, args)
        )
        print(f"Baseline created: {len(result.records)} files under {root}")
        if result.skipped:
            print(f"Skipped: {len(result.skipped)} (see logs/fim.log for reasons)")
        if result.errors:
            print(f"Errors: {len(result.errors)}")
    return EXIT_OK


def _command_verify(args: argparse.Namespace) -> int:
    """Verify every monitored folder against its baseline."""
    config, pairs, key_path = _resolve_settings(args)
    any_changes = False
    for root, baseline_dir in pairs:
        if len(pairs) > 1:
            print(f"Folder: {root}")
        result = verify_baseline(
            root,
            baseline_dir,
            key_path,
            report_dir=_project_root() / str(config.get("report_dir", "reports")),
            **_scan_kwargs(config, args),
        )
        print_summary(result)
        if result.changes:
            alert_for_changes(
                result.changes,
                config,
                _project_root() / "logs",
                result,
                str(root),
            )
            any_changes = True
    return EXIT_CHANGES if any_changes else EXIT_OK


def _command_update(args: argparse.Namespace) -> int:
    """Rebuild the baseline for every monitored folder, after review."""
    config, pairs, key_path = _resolve_settings(args)
    for root, baseline_dir in pairs:
        if not args.force:
            answer = (
                input(f"Update the baseline for {root} to the current files? [y/N] ")
                .strip()
                .lower()
            )
            if answer != "y":
                print(f"Baseline update cancelled for {root}.")
                continue
        result = update_baseline(
            root, baseline_dir, key_path, **_scan_kwargs(config, args)
        )
        print(f"Baseline updated: {len(result.records)} files under {root}")
    return EXIT_OK


def _command_rotate_key(args: argparse.Namespace) -> int:
    """Re-encrypt/re-sign each baseline with a fresh 32-byte key."""
    _config, pairs, key_path = _resolve_settings(args)
    for root, baseline_dir in pairs:
        count = rotate_baseline_key(baseline_dir, key_path)
        print(f"Key rotated for {root}: {count} files re-encrypted.")
    print("Old key no longer verifies the baseline; keep the new key safe.")
    return EXIT_OK


def _status_baseline_dirs(args: argparse.Namespace) -> list[Path]:
    """Baseline dirs for status/history: per --path, else the base dir."""
    root_dir = _project_root()
    base = (
        Path(args.baseline_dir)
        if getattr(args, "baseline_dir", "")
        else root_dir / "baseline"
    )
    paths = getattr(args, "paths", None) or []
    if not paths:
        return [base]
    roots = [validate_path(Path(item)) for item in paths]
    return [
        (
            find_baseline_dir(base, root)
            if len(roots) == 1
            else resolve_baseline_dir(base, root, single_folder=False)
        )
        for root in roots
    ]


def _command_status(args: argparse.Namespace) -> int:
    """Show baseline metadata and the last scan, per folder."""
    for baseline_dir in _status_baseline_dirs(args):
        status = get_status(baseline_dir)
        print("File Integrity Monitor - status")
        print(f"  Monitored path: {status['monitored_path']}")
        print(f"  Baseline created: {status['created_utc']}")
        print(f"  Files in baseline: {status['file_count']}")
        print(f"  Last scan: {status['last_scan_utc'] or 'never'}")
        print(
            f"  Last scan - total: {status['last_total']}, added: {status['last_added']}, deleted: {status['last_deleted']}, modified: {status['last_modified']}, renamed: {status['last_renamed']}"
        )
    return EXIT_OK


def _command_history(args: argparse.Namespace) -> int:
    """List the most recent scans from the history table, per folder."""
    for baseline_dir in _status_baseline_dirs(args):
        rows = get_history(baseline_dir, limit=20)
        if not rows:
            print(f"No scans recorded yet for {baseline_dir}.")
            continue
        for row in rows:
            print(
                f"{row['scanned_utc']} | total {row['total']} | unchanged {row['unchanged']} | "
                f"added {row['added']} | deleted {row['deleted']} | modified {row['modified']} | "
                f"renamed {row['renamed']} | errors {row['errors']}"
            )
    return EXIT_OK


def _command_check_update(args: argparse.Namespace) -> int:
    """Ask GitHub Releases for the latest version and compare it."""
    root_dir = _project_root()
    config_path = Path(args.config) if args.config else root_dir / "config.json"
    config = load_config(config_path if config_path.exists() else None)
    if not config.get("check_for_updates", True) and not args.force:
        print(
            "Update checks are disabled in config (check_for_updates=false). "
            "Run with --force to check anyway."
        )
        return EXIT_OK
    result = check_for_update(VERSION)
    if result.get("error"):
        print(f"Could not check for updates: {result['error']}")
        print("Check your network connection and try again later.")
        return EXIT_OK
    latest = result.get("latest_version", "")
    print(f"You are on v{VERSION}. Latest release is {latest or 'unknown'}.")
    if result.get("is_update_available"):
        print("An update is available.")
        if result.get("download_url"):
            print(f"Download: {result['download_url']}")
        elif result.get("release_url"):
            print(f"Release page: {result['release_url']}")
    else:
        print("You are up to date.")
    return EXIT_OK


def _command_schedule(args: argparse.Namespace) -> int:
    """Verify every monitored folder on a timer, until interrupted.

    This never updates the baseline; it only reports changes.
    """
    import time

    config, pairs, key_path = _resolve_settings(args)
    minutes = args.interval_minutes or int(
        config.get("scheduled_scan_interval_minutes", 0)
    )
    if minutes <= 0:
        raise ConfigError(
            "No scheduled interval given. Use --interval-minutes or set "
            "scheduled_scan_interval_minutes in config.json (5-1440)."
        )
    if minutes < 5 or minutes > 1440:
        raise ConfigError("Scheduled interval must be between 5 and 1440 minutes.")
    print(
        f"Scheduled scans every {minutes} minute(s) for "
        f"{', '.join(str(r) for r, _ in pairs)}. Press Ctrl+C to stop."
    )
    while True:
        for root, baseline_dir in pairs:
            result = verify_baseline(
                root,
                baseline_dir,
                key_path,
                report_dir=_project_root() / str(config.get("report_dir", "reports")),
                **_scan_kwargs(config, args),
            )
            print(f"Folder: {root}")
            print_summary(result)
            if result.changes:
                alert_for_changes(
                    result.changes,
                    config,
                    _project_root() / "logs",
                    result,
                    str(root),
                )
        try:
            time.sleep(minutes * 60)
        except KeyboardInterrupt:
            print("\nScheduled scans stopped.")
            return EXIT_OK


def _command_monitor(args: argparse.Namespace) -> int:
    """Run polling or watchdog monitoring until interrupted."""
    import threading

    config, pairs, key_path = _resolve_settings(args)
    if args.interval:
        if not 10 <= args.interval <= 3600:
            raise ConfigError("scan interval must be between 10 and 3600 seconds.")
        config["scan_interval_seconds"] = args.interval
    if len(pairs) == 1:
        root, baseline_dir = pairs[0]
        if args.daemon:
            start_daemon(root, config["scan_interval_seconds"])
            print("Monitor started in the background.")
            return EXIT_OK
        print(
            f"Monitoring {root} every {config['scan_interval_seconds']} seconds. "
            "Press Ctrl+C to stop."
        )
        changes = run_monitor(
            root,
            baseline_dir,
            key_path,
            config,
            interval=config["scan_interval_seconds"],
            use_watchdog=not args.no_watchdog,
        )
        print(f"Monitoring stopped. Changes detected: {changes}")
        return EXIT_CHANGES if changes else EXIT_OK
    if args.daemon:
        raise ConfigError("Background daemon mode supports one folder only.")
    print(
        f"Monitoring {len(pairs)} folders every "
        f"{config['scan_interval_seconds']} seconds. Press Ctrl+C to stop."
    )
    totals: dict[str, int] = {}
    threads = []
    for root, baseline_dir in pairs:

        def _run(root=root, baseline_dir=baseline_dir):
            totals[str(root)] = run_monitor(
                root,
                baseline_dir,
                key_path,
                config,
                interval=config["scan_interval_seconds"],
                use_watchdog=not args.no_watchdog,
            )

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        threads.append(thread)
    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
    total = sum(totals.values())
    print(f"Monitoring stopped. Changes detected: {total}")
    return EXIT_CHANGES if total else EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for every subcommand."""
    parser = argparse.ArgumentParser(
        prog="fim",
        description="File Integrity Monitor - SHA-256 baseline, verify and monitor.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"File Integrity Monitor {VERSION}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser(
        "check-update", help="Check GitHub Releases for a newer version"
    )
    check_parser.add_argument("--config", default="", help="Path to config.json")
    check_parser.add_argument(
        "--force",
        action="store_true",
        help="Check even if check_for_updates is false in config",
    )
    check_parser.set_defaults(func=_command_check_update)

    schedule_parser = subparsers.add_parser(
        "schedule", help="Verify on a timer, every N minutes, until stopped"
    )
    _add_common_arguments(schedule_parser)
    schedule_parser.add_argument(
        "--interval-minutes",
        type=int,
        default=0,
        help="Minutes between scans (5-1440); 0 uses scheduled_scan_interval_minutes from config",
    )
    schedule_parser.set_defaults(func=_command_schedule)

    init_parser = subparsers.add_parser(
        "init", help="Create a signed baseline for a directory"
    )
    _add_common_arguments(init_parser)
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing baseline without asking",
    )
    init_parser.set_defaults(func=_command_init)

    verify_parser = subparsers.add_parser(
        "verify", help="Verify a directory against its baseline"
    )
    _add_common_arguments(verify_parser)
    verify_parser.set_defaults(func=_command_verify)
    scan_parser = subparsers.add_parser("scan", help="Alias for verify")
    _add_common_arguments(scan_parser)
    scan_parser.set_defaults(func=_command_verify)

    update_parser = subparsers.add_parser(
        "update", help="Rebuild the baseline after reviewing changes"
    )
    _add_common_arguments(update_parser)
    update_parser.add_argument(
        "--force", action="store_true", help="Update without asking for confirmation"
    )
    update_parser.set_defaults(func=_command_update)

    status_parser = subparsers.add_parser("status", help="Show baseline information")
    status_parser.add_argument("--baseline-dir", default="")
    status_parser.add_argument(
        "--path",
        dest="paths",
        action="append",
        default=None,
        help="Folder to show status for; repeat for several folders",
    )
    status_parser.set_defaults(func=_command_status)

    history_parser = subparsers.add_parser("history", help="Show recent scans")
    history_parser.add_argument("--baseline-dir", default="")
    history_parser.add_argument(
        "--path",
        dest="paths",
        action="append",
        default=None,
        help="Folder to show history for; repeat for several folders",
    )
    history_parser.set_defaults(func=_command_history)
    list_parser = subparsers.add_parser("list", help="Alias for history")
    list_parser.add_argument("--baseline-dir", default="")
    list_parser.add_argument(
        "--path",
        dest="paths",
        action="append",
        default=None,
        help="Folder to show history for; repeat for several folders",
    )
    list_parser.set_defaults(func=_command_history)

    rotate_parser = subparsers.add_parser(
        "rotate-key",
        help="Re-encrypt/re-sign each baseline with a fresh 32-byte key",
    )
    _add_common_arguments(rotate_parser)
    rotate_parser.set_defaults(func=_command_rotate_key)

    monitor_parser = subparsers.add_parser(
        "monitor", help="Monitor a directory in real time"
    )
    _add_common_arguments(monitor_parser)
    monitor_parser.add_argument(
        "--interval", type=int, default=0, help="Seconds between scans (10-3600)"
    )
    monitor_parser.add_argument(
        "--daemon", action="store_true", help="Run in the background"
    )
    monitor_parser.add_argument(
        "--no-watchdog",
        action="store_true",
        help="Use polling even if watchdog is installed",
    )
    monitor_parser.set_defaults(func=_command_monitor)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, run the chosen command, and return its exit code."""
    enable_windows_colours()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except BaselineError as exc:
        print(f"[CRITICAL] {exc}" if "tampered" in str(exc) else f"Error: {exc}")
        print(
            "Run 'fim init --force' to rebuild the baseline, only after you have checked why it changed."
        )
        return EXIT_ERROR
    except (FimError, ConfigError) as exc:
        print(f"Error: {exc}")
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\nInterrupted. Shutting down cleanly.")
        return EXIT_OK
    except FileNotFoundError as exc:
        print(f"Error: {exc}")
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
