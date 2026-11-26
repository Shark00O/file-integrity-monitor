# File Integrity Monitor — command-line interface.
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
    BaselineError,
    ConfigError,
    FimError,
    alert_for_changes,
    create_baseline,
    enable_windows_colours,
    get_history,
    get_project_root,
    get_status,
    load_config,
    print_summary,
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
    parser.add_argument("--path", default="", help="Directory to monitor")
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


def _resolve_settings(args: argparse.Namespace) -> tuple[dict, Path, Path, Path]:
    """Merge config file and CLI flags; CLI wins. Returns config, root, baseline dir, key path."""
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
    monitored = args.path or (config.get("monitored_paths") or [""])[0]
    if not monitored:
        raise ConfigError(
            "No monitored path given. Use --path or set monitored_paths in config.json."
        )
    root = validate_path(Path(monitored))
    baseline_dir = (
        Path(args.baseline_dir)
        if args.baseline_dir
        else root_dir / str(config.get("baseline_path", "baseline"))
    )
    from fim_core import get_key_path

    key_path = get_key_path()
    setup_logging(root_dir / "logs", str(config.get("log_level", "INFO")))
    return config, root, baseline_dir, key_path


def _command_init(args: argparse.Namespace) -> int:
    """Create a baseline, asking first when one already exists."""
    config, root, baseline_dir, key_path = _resolve_settings(args)
    json_path = baseline_dir / "baseline.json"
    if json_path.exists() and not args.force:
        answer = (
            input(f"Baseline already exists at {json_path}. Overwrite it? [y/N] ")
            .strip()
            .lower()
        )
        if answer != "y":
            print("Baseline creation cancelled.")
            return EXIT_OK
    result = create_baseline(
        root,
        baseline_dir,
        key_path,
        recursive=config["recursive"],
        include=config["include_patterns"],
        exclude=config["exclude_patterns"],
        max_size_mb=config["max_file_size_mb"],
        follow_symlinks=args.follow_symlinks,
        chunk_size=config["hash_chunk_size"],
    )
    print(f"Baseline created: {len(result.records)} files under {root}")
    if result.skipped:
        print(f"Skipped: {len(result.skipped)} (see logs/fim.log for reasons)")
    if result.errors:
        print(f"Errors: {len(result.errors)}")
    return EXIT_OK


def _command_verify(args: argparse.Namespace) -> int:
    """Verify a tree against its baseline and report the exit code."""
    config, root, baseline_dir, key_path = _resolve_settings(args)
    result = verify_baseline(
        root,
        baseline_dir,
        key_path,
        recursive=config["recursive"],
        include=config["include_patterns"],
        exclude=config["exclude_patterns"],
        max_size_mb=config["max_file_size_mb"],
        follow_symlinks=args.follow_symlinks,
        chunk_size=config["hash_chunk_size"],
        report_dir=_project_root() / str(config.get("report_dir", "reports")),
    )
    print_summary(result)
    if result.changes:
        alert_for_changes(result.changes, config, _project_root() / "logs")
        return EXIT_CHANGES
    return EXIT_OK


def _command_update(args: argparse.Namespace) -> int:
    """Rebuild the baseline after the user has reviewed the changes."""
    config, root, baseline_dir, key_path = _resolve_settings(args)
    if not args.force:
        answer = (
            input(f"Update the baseline for {root} to the current files? [y/N] ")
            .strip()
            .lower()
        )
        if answer != "y":
            print("Baseline update cancelled.")
            return EXIT_OK
    result = update_baseline(
        root,
        baseline_dir,
        key_path,
        recursive=config["recursive"],
        include=config["include_patterns"],
        exclude=config["exclude_patterns"],
        max_size_mb=config["max_file_size_mb"],
        follow_symlinks=args.follow_symlinks,
        chunk_size=config["hash_chunk_size"],
    )
    print(f"Baseline updated: {len(result.records)} files under {root}")
    return EXIT_OK


def _command_status(args: argparse.Namespace) -> int:
    """Show baseline metadata and the last scan."""
    root_dir = _project_root()
    baseline_dir = (
        Path(args.baseline_dir) if args.baseline_dir else root_dir / "baseline"
    )
    status = get_status(baseline_dir)
    print("File Integrity Monitor — status")
    print(f"  Monitored path: {status['monitored_path']}")
    print(f"  Baseline created: {status['created_utc']}")
    print(f"  Files in baseline: {status['file_count']}")
    print(f"  Last scan: {status['last_scan_utc'] or 'never'}")
    print(
        f"  Last scan — total: {status['last_total']}, added: {status['last_added']}, deleted: {status['last_deleted']}, modified: {status['last_modified']}, renamed: {status['last_renamed']}"
    )
    return EXIT_OK


def _command_history(args: argparse.Namespace) -> int:
    """List the most recent scans from the history table."""
    root_dir = _project_root()
    baseline_dir = (
        Path(args.baseline_dir) if args.baseline_dir else root_dir / "baseline"
    )
    rows = get_history(baseline_dir, limit=20)
    if not rows:
        print("No scans recorded yet.")
        return EXIT_OK
    for row in rows:
        print(
            f"{row['scanned_utc']} | total {row['total']} | unchanged {row['unchanged']} | "
            f"added {row['added']} | deleted {row['deleted']} | modified {row['modified']} | "
            f"renamed {row['renamed']} | errors {row['errors']}"
        )
    return EXIT_OK


def _command_monitor(args: argparse.Namespace) -> int:
    """Run polling or watchdog monitoring until interrupted."""
    config, root, baseline_dir, key_path = _resolve_settings(args)
    if args.interval:
        if not 10 <= args.interval <= 3600:
            raise ConfigError("scan interval must be between 10 and 3600 seconds.")
        config["scan_interval_seconds"] = args.interval
    if args.daemon:
        start_daemon(root, config["scan_interval_seconds"])
        print("Monitor started in the background.")
        return EXIT_OK
    print(
        f"Monitoring {root} every {config['scan_interval_seconds']} seconds. Press Ctrl+C to stop."
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


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for every subcommand."""
    parser = argparse.ArgumentParser(
        prog="fim",
        description="File Integrity Monitor — SHA-256 baseline, verify and monitor.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

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
    status_parser.set_defaults(func=_command_status)

    history_parser = subparsers.add_parser("history", help="Show recent scans")
    history_parser.add_argument("--baseline-dir", default="")
    history_parser.set_defaults(func=_command_history)
    list_parser = subparsers.add_parser("list", help="Alias for history")
    list_parser.add_argument("--baseline-dir", default="")
    list_parser.set_defaults(func=_command_history)

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
