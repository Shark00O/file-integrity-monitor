# File Integrity Monitor - desktop GUI.
# Tkinter only. All hashing and baseline work comes from fim_core.
"""Tkinter GUI for the File Integrity Monitor.

The window never runs a scan on the main thread: every scan runs in a
worker thread and posts its results back with `after`, so the GUI
stays responsive while files are being hashed.
"""

from __future__ import annotations

import logging
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

LOGGER = logging.getLogger("fim_gui")

from fim_core import (
    VERSION,
    check_for_update,
    create_baseline,
    export_scan_results,
    find_baseline_dir,
    get_history,
    get_key_path,
    get_project_root,
    get_status,
    get_theme_colours,
    load_config,
    resolve_baseline_dir,
    rotate_baseline_key,
    save_config,
    setup_logging,
    update_baseline,
    verify_baseline,
)
from fim_tray import TrayController, tray_available

STATUS_COLOURS = {
    "OK": "green",
    "MODIFIED": "red",
    "DELETED": "red",
    "ADDED": "yellow",
    "RENAMED": "orange",
    "PERMISSION_CHANGED": "orange",
}


class FimGui:
    """Main window for the File Integrity Monitor."""

    def __init__(self, root: tk.Tk) -> None:
        """Build the window, its buttons, table and status bar."""
        self.root = root
        self.root.title(f"File Integrity Monitor v{VERSION}")
        self.root.geometry("1000x600")
        self.project_root = get_project_root()
        self.config = load_config(self.project_root / "config.json")
        setup_logging(
            self.project_root / "logs", str(self.config.get("log_level", "INFO"))
        )
        self.monitored_path = tk.StringVar(value="")
        self.folders: list[str] = [
            str(item) for item in self.config.get("monitored_paths", []) if str(item)
        ]
        self.monitoring = False
        self._monitor_stop = threading.Event()
        self._results: queue.Queue = queue.Queue()
        self._last_result = None
        self._last_root = None
        self._history_window = None
        self._history_tree = None
        self._schedule_minutes = tk.StringVar(
            value=str(int(self.config.get("scheduled_scan_interval_minutes", 0)))
        )
        self._schedule_stop = threading.Event()
        self._schedule_thread = None
        self._build_widgets()
        self._apply_theme(str(self.config.get("gui_theme", "light")))
        self._tray = TrayController(
            on_show=lambda: self.root.after(0, self._show_window),
            on_verify=lambda: self.root.after(0, self._verify_from_tray),
            on_start_monitoring=lambda: self.root.after(0, self._start_monitoring),
            on_stop_monitoring=lambda: self.root.after(0, self._stop_monitoring),
            on_quit=lambda: self.root.after(0, self._quit_from_tray),
        )
        if self._tray.start():
            self.status_var.set(f"Ready. Tray icon is running. v{VERSION}.")
        elif not tray_available():
            self.status_var.set(
                "Ready. Select a folder, then Create Baseline. "
                "(Tray not available: install pystray and Pillow to enable it.)"
            )
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(100, self._drain_results)

    def _build_widgets(self) -> None:
        """Create the path row, buttons, results table and status bar."""
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill=tk.X)
        ttk.Label(top, text="Folder:").pack(side=tk.LEFT)
        ttk.Entry(top, textvariable=self.monitored_path, width=60).pack(
            side=tk.LEFT, padx=5, expand=True, fill=tk.X
        )
        ttk.Button(top, text="Select Folder", command=self._select_folder).pack(
            side=tk.LEFT
        )
        ttk.Button(top, text="Add Folder", command=self._add_folder).pack(
            side=tk.LEFT, padx=3
        )

        folder_frame = ttk.Frame(self.root, padding=(10, 0, 10, 0))
        folder_frame.pack(fill=tk.X)
        ttk.Label(folder_frame, text="Folders:").pack(side=tk.LEFT)
        self.folder_listbox = tk.Listbox(folder_frame, height=3)
        self.folder_listbox.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        for folder in self.folders:
            self.folder_listbox.insert(tk.END, folder)
        ttk.Button(
            folder_frame, text="Remove Selected", command=self._remove_folder
        ).pack(side=tk.LEFT)

        buttons = ttk.Frame(self.root, padding=10)
        buttons.pack(fill=tk.X)
        ttk.Button(
            buttons, text="Create Baseline", command=lambda: self._run_in_thread("init")
        ).pack(side=tk.LEFT, padx=3)
        ttk.Button(
            buttons, text="Verify Now", command=lambda: self._run_in_thread("verify")
        ).pack(side=tk.LEFT, padx=3)
        ttk.Button(
            buttons, text="Start Monitoring", command=self._start_monitoring
        ).pack(side=tk.LEFT, padx=3)
        ttk.Button(buttons, text="Stop Monitoring", command=self._stop_monitoring).pack(
            side=tk.LEFT, padx=3
        )
        ttk.Button(buttons, text="View Report", command=self._view_report).pack(
            side=tk.LEFT, padx=3
        )
        ttk.Button(
            buttons,
            text="Update Baseline",
            command=lambda: self._run_in_thread("update"),
        ).pack(side=tk.LEFT, padx=3)
        ttk.Button(buttons, text="View History", command=self._show_history).pack(
            side=tk.LEFT, padx=3
        )
        ttk.Button(
            buttons,
            text="Export Report",
            command=lambda: self._run_in_thread("export"),
        ).pack(side=tk.LEFT, padx=3)
        ttk.Button(
            buttons, text="Check for Updates", command=self._check_for_updates
        ).pack(side=tk.LEFT, padx=3)
        ttk.Button(
            buttons,
            text="Rotate Key",
            command=lambda: self._run_in_thread("rotate-key"),
        ).pack(side=tk.LEFT, padx=3)
        self.theme_button = ttk.Button(
            buttons, text="Dark Mode", command=self._toggle_theme
        )
        self.theme_button.pack(side=tk.LEFT, padx=3)

        schedule = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        schedule.pack(fill=tk.X)
        ttk.Label(schedule, text="Scheduled scan every").pack(side=tk.LEFT)
        ttk.Entry(schedule, textvariable=self._schedule_minutes, width=6).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Label(schedule, text="min (0 = off)").pack(side=tk.LEFT)
        ttk.Button(schedule, text="Apply Schedule", command=self._apply_schedule).pack(
            side=tk.LEFT, padx=5
        )

        columns = ("folder", "file", "status", "size", "last_checked")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")
        for column, heading in zip(
            columns, ("Folder", "File", "Status", "Size", "Last Checked")
        ):
            self.tree.heading(column, text=heading)
        self.tree.column("folder", width=150)
        self.tree.column("file", width=350)
        self.tree.column("status", width=140)
        self.tree.column("size", width=100)
        self.tree.column("last_checked", width=180)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10)
        for name, colour in STATUS_COLOURS.items():
            self.tree.tag_configure(name, foreground=colour)
        self.tree.tag_configure("UNCHANGED", foreground="grey")

        self.status_var = tk.StringVar(
            value="Ready. Select a folder, then Create Baseline."
        )
        ttk.Label(
            self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W
        ).pack(fill=tk.X, side=tk.BOTTOM)

    def _select_folder(self) -> None:
        """Let the user pick the folder to monitor."""
        chosen = filedialog.askdirectory(title="Select folder to monitor")
        if chosen:
            self.monitored_path.set(chosen)

    def _folders(self) -> list[Path]:
        """Return the monitored folders: the listbox, plus the entry."""
        folders = list(self.folders)
        entry = self.monitored_path.get().strip()
        if entry and entry not in folders:
            folders.append(entry)
        return [Path(item) for item in folders]

    def _add_folder(self) -> None:
        """Add the folder in the entry box to the monitored list."""
        folder = self.monitored_path.get().strip()
        if not folder:
            messagebox.showwarning("No folder", "Type or select a folder first.")
            return
        if folder not in self.folders:
            self.folders.append(folder)
            self.folder_listbox.insert(tk.END, folder)
            self.config["monitored_paths"] = list(self.folders)

    def _remove_folder(self) -> None:
        """Remove the selected folder from the monitored list."""
        selection = self.folder_listbox.curselection()
        if not selection:
            return
        index = selection[0]
        del self.folders[index]
        self.folder_listbox.delete(index)
        self.config["monitored_paths"] = list(self.folders)

    def _baseline_dir(self, root: Path | None = None) -> Path:
        """Return the baseline directory for one folder (or the first)."""
        base = self.project_root / str(self.config.get("baseline_path", "baseline"))
        folders = self._folders()
        if root is None:
            if not folders:
                return base
            root = folders[0]
        if len(folders) <= 1:
            return find_baseline_dir(base, root)
        return resolve_baseline_dir(base, root, single_folder=False)

    def _apply_theme(self, theme: str) -> None:
        """Apply the light or dark theme to the window and its widgets."""
        colours = get_theme_colours(theme)
        self.root.configure(background=colours["background"])
        try:
            style = ttk.Style(self.root)
            style.theme_use("clam")
            style.configure(
                ".", background=colours["background"], foreground=colours["text"]
            )
            style.configure("TFrame", background=colours["background"])
            style.configure(
                "TLabel", background=colours["background"], foreground=colours["text"]
            )
            style.configure(
                "TButton", background=colours["surface"], foreground=colours["text"]
            )
            style.configure(
                "TEntry", fieldbackground=colours["field"], foreground=colours["text"]
            )
            style.configure(
                "Treeview",
                background=colours["surface"],
                foreground=colours["text"],
                fieldbackground=colours["surface"],
            )
            style.configure(
                "Treeview.Heading",
                background=colours["heading"],
                foreground=colours["text"],
            )
            style.map(
                "Treeview",
                background=[("selected", colours["selected"])],
                foreground=[("selected", colours["text"])],
            )
        except Exception:
            # A theme that cannot be applied must never stop the GUI.
            LOGGER.warning("Could not apply theme %r; keeping defaults.", theme)
        if hasattr(self, "theme_button"):
            self.theme_button.configure(
                text="Light Mode" if theme == "dark" else "Dark Mode"
            )

    def _toggle_theme(self) -> None:
        """Flip light/dark and persist the choice in config.json."""
        current = str(self.config.get("gui_theme", "light") or "light")
        new_theme = "dark" if current == "light" else "light"
        self.config["gui_theme"] = new_theme
        self._apply_theme(new_theme)
        try:
            save_config(self.project_root / "config.json", self.config)
        except Exception:
            LOGGER.warning("Could not save the theme choice to config.json.")

    def _run_in_thread(self, action: str) -> None:
        """Run a blocking action in a worker thread so the GUI never freezes."""
        folders = self._folders()
        if not folders:
            messagebox.showwarning("No folder", "Select a folder first.")
            return
        if action in ("init", "verify", "update", "rotate-key"):
            thread = threading.Thread(
                target=self._do_multi_action, args=(action, folders), daemon=True
            )
        else:
            thread = threading.Thread(
                target=self._do_action, args=(action, folders[0]), daemon=True
            )
        thread.start()

    def _do_multi_action(self, action: str, roots: list[Path]) -> None:
        """Run init/verify/update/rotate-key for every folder, once."""
        all_rows: list[tuple] = []
        total_checked = 0
        total_changes = 0
        mass = False
        try:
            for root in roots:
                baseline_dir = self._baseline_dir(root)
                key_path = get_key_path()
                folder_name = root.name or str(root)
                if action == "init":
                    result = create_baseline(root, baseline_dir, key_path)
                    all_rows.extend(
                        (folder_name, r.relative_path, "OK", str(r.size), r.mtime_utc)
                        for r in result.records
                    )
                    total_checked += len(result.records)
                elif action == "verify":
                    result = verify_baseline(root, baseline_dir, key_path)
                    self._last_result = result
                    self._last_root = root
                    total_checked += int(result.counts.get("total", 0))
                    total_changes += len(result.changes)
                    mass = mass or bool(result.mass_change)
                    changed = {c.relative_path: c.kind for c in result.changes}
                    for record in result.records:
                        all_rows.append(
                            (
                                folder_name,
                                record.relative_path,
                                changed.get(record.relative_path, "OK"),
                                str(record.size),
                                result.scanned_at_utc,
                            )
                        )
                    for change in result.changes:
                        if change.relative_path not in {
                            r.relative_path for r in result.records
                        }:
                            size = change.new_record.size if change.new_record else 0
                            all_rows.append(
                                (
                                    folder_name,
                                    change.relative_path,
                                    change.kind,
                                    str(size),
                                    result.scanned_at_utc,
                                )
                            )
                    if result.changes:
                        self._results.put(
                            ("alert", f"{len(result.changes)} change(s) in {root}.")
                        )
                elif action == "update":
                    result = update_baseline(root, baseline_dir, key_path)
                    all_rows.extend(
                        (folder_name, r.relative_path, "OK", str(r.size), r.mtime_utc)
                        for r in result.records
                    )
                    total_checked += len(result.records)
                elif action == "rotate-key":
                    count = rotate_baseline_key(baseline_dir, key_path)
                    total_checked += count
            all_rows.sort(key=lambda row: (row[0], row[1]))
            if action == "verify":
                status = (
                    f"Last scan: checked {total_checked} | " f"changes {total_changes}"
                )
                if mass:
                    status += " | MASS CHANGE DETECTED"
                self._results.put(("status", status))
            elif action == "rotate-key":
                self._results.put(
                    ("status", f"Key rotated: {total_checked} files re-encrypted.")
                )
            elif action == "init":
                self._results.put(
                    ("status", f"Baseline created: {total_checked} files.")
                )
            elif action == "update":
                self._results.put(
                    ("status", f"Baseline updated: {total_checked} files.")
                )
            self._results.put(("rows", all_rows))
        except Exception as exc:
            self._results.put(("status", f"Error: {exc}"))
            self._results.put(("alert", str(exc)))

    def _do_action(self, action: str, root: Path) -> None:
        """Do the work for one button, then post the outcome to the GUI."""
        baseline_dir = self._baseline_dir(root)
        key_path = get_key_path()
        try:
            if action == "init":
                result = create_baseline(root, baseline_dir, key_path)
                self._results.put(
                    ("status", f"Baseline created: {len(result.records)} files.")
                )
                self._results.put(
                    (
                        "rows",
                        [
                            (root.name, r.relative_path, "OK", str(r.size), r.mtime_utc)
                            for r in result.records
                        ],
                    )
                )
            elif action == "verify":
                result = verify_baseline(root, baseline_dir, key_path)
                self._last_result = result
                self._last_root = root
                # Show ALL files: unchanged as OK, changed with their kind.
                changed_by_path = {c.relative_path: c.kind for c in result.changes}
                rows = []
                for record in result.records:
                    rows.append(
                        (
                            root.name,
                            record.relative_path,
                            changed_by_path.get(record.relative_path, "OK"),
                            str(record.size),
                            result.scanned_at_utc,
                        )
                    )
                for change in result.changes:
                    if change.relative_path not in {
                        r.relative_path for r in result.records
                    }:
                        size = change.new_record.size if change.new_record else 0
                        rows.append(
                            (
                                root.name,
                                change.relative_path,
                                change.kind,
                                str(size),
                                result.scanned_at_utc,
                            )
                        )
                rows.sort(key=lambda row: row[1])
                status = (
                    f"Last scan: {result.scanned_at_utc} | checked "
                    f"{result.counts.get('total', 0)} | changes {len(result.changes)}"
                )
                if result.mass_change:
                    status += " | MASS CHANGE DETECTED"
                self._results.put(("status", status))
                self._results.put(("rows", rows))
                if result.changes:
                    self._results.put(
                        ("alert", f"{len(result.changes)} change(s) detected.")
                    )
            elif action == "update":
                result = update_baseline(root, baseline_dir, key_path)
                self._results.put(
                    ("status", f"Baseline updated: {len(result.records)} files.")
                )
                self._results.put(
                    (
                        "rows",
                        [
                            (root.name, r.relative_path, "OK", str(r.size), r.mtime_utc)
                            for r in result.records
                        ],
                    )
                )
            elif action == "rotate-key":
                count = rotate_baseline_key(baseline_dir, key_path)
                self._results.put(
                    ("status", f"Key rotated: {count} files re-encrypted.")
                )
            elif action == "export":
                if self._last_result is None or self._last_root is None:
                    self._results.put(
                        ("status", "Nothing to export yet. Run Verify Now first.")
                    )
                    return
                report_dir = self.project_root / str(
                    self.config.get("report_dir", "reports")
                )
                json_path, csv_path = export_scan_results(
                    report_dir, self._last_root, self._last_result
                )
                self._results.put(
                    ("status", f"Exported: {json_path.name} and {csv_path.name}")
                )
            elif action == "history":
                rows = get_history(baseline_dir, limit=20)
                self._results.put(("history_rows", rows))
        except Exception as exc:
            self._results.put(("status", f"Error: {exc}"))
            self._results.put(("alert", str(exc)))

    def _drain_results(self) -> None:
        """Apply results posted by worker threads, on the GUI thread."""
        try:
            while True:
                kind, payload = self._results.get_nowait()
                if kind == "status":
                    self.status_var.set(str(payload))
                elif kind == "rows":
                    for item in self.tree.get_children():
                        self.tree.delete(item)
                    for row in payload:
                        status = str(row[2]) if len(row) > 2 else str(row[1])
                        tag = status if status in STATUS_COLOURS else "UNCHANGED"
                        self.tree.insert("", tk.END, values=row, tags=(tag,))
                elif kind == "alert":
                    messagebox.showwarning("File Integrity Monitor", str(payload))
                elif kind == "history_rows":
                    self._populate_history(payload)
                elif kind == "update_result":
                    self._show_update_result(payload)
        except queue.Empty:
            pass
        self.root.after(100, self._drain_results)

    def _start_monitoring(self) -> None:
        """Start a background polling monitor in a worker thread."""
        if self.monitoring:
            return
        path = self.monitored_path.get().strip()
        if not path:
            messagebox.showwarning("No folder", "Select a folder first.")
            return
        self.monitoring = True
        self._monitor_stop.clear()
        self.status_var.set("Monitoring started.")
        thread = threading.Thread(
            target=self._monitor_loop, args=(Path(path),), daemon=True
        )
        thread.start()

    def _monitor_loop(self, root: Path) -> None:
        """Poll in a worker thread until Stop Monitoring is pressed."""
        from fim_monitor import run_monitor

        interval = int(self.config.get("scan_interval_seconds", 60))
        run_monitor(
            root,
            self._baseline_dir(),
            get_key_path(),
            self.config,
            interval=interval,
            use_watchdog=False,
            max_cycles=None,
        )
        self._results.put(("status", "Monitoring stopped."))

    def _stop_monitoring(self) -> None:
        """Stop the background monitor."""
        from fim_monitor import stop_monitor

        self.monitoring = False
        stop_monitor()
        self.status_var.set("Stopping monitor...")

    def _show_history(self) -> None:
        """Open the scan-history window and load its rows in a thread."""
        if self._history_window is not None and self._history_window.winfo_exists():
            self._history_window.lift()
            self._load_history()
            return
        window = tk.Toplevel(self.root)
        window.title("Scan History - File Integrity Monitor")
        window.geometry("900x400")
        self._history_window = window
        columns = (
            "date",
            "total",
            "unchanged",
            "added",
            "deleted",
            "modified",
            "renamed",
            "errors",
        )
        tree = ttk.Treeview(window, columns=columns, show="headings")
        headings = (
            "Date",
            "Total",
            "Unchanged",
            "Added",
            "Deleted",
            "Modified",
            "Renamed",
            "Errors",
        )
        for column, heading in zip(columns, headings):
            tree.heading(column, text=heading)
            tree.column(column, width=100)
        tree.column("date", width=220)
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self._history_tree = tree
        ttk.Button(window, text="Refresh", command=self._load_history).pack(pady=5)
        self._load_history()

    def _load_history(self) -> None:
        """Load history rows in a worker thread (never on the GUI thread)."""
        path = self.monitored_path.get().strip()
        if not path:
            messagebox.showwarning(
                "No folder", "Select a folder first to view its history."
            )
            return
        thread = threading.Thread(
            target=self._do_action, args=("history", Path(path)), daemon=True
        )
        thread.start()

    def _populate_history(self, rows: list) -> None:
        """Fill the history window with rows posted by a worker thread."""
        if self._history_tree is None or not self._history_tree.winfo_exists():
            return
        for item in self._history_tree.get_children():
            self._history_tree.delete(item)
        for row in rows:
            self._history_tree.insert(
                "",
                tk.END,
                values=(
                    row.get("scanned_utc", ""),
                    row.get("total", 0),
                    row.get("unchanged", 0),
                    row.get("added", 0),
                    row.get("deleted", 0),
                    row.get("modified", 0),
                    row.get("renamed", 0),
                    row.get("errors", 0),
                ),
            )

    def _check_for_updates(self) -> None:
        """Check GitHub Releases in a worker thread, never blocking the GUI."""
        if not self.config.get("check_for_updates", True):
            messagebox.showinfo(
                "Check for Updates",
                "Update checks are disabled in config " "(check_for_updates=false).",
            )
            return
        thread = threading.Thread(target=self._do_update_check, daemon=True)
        thread.start()

    def _do_update_check(self) -> None:
        """Run the update check off the GUI thread and post the result."""
        self._results.put(("update_result", check_for_update(VERSION)))

    def _show_update_result(self, result: dict) -> None:
        """Show the update-check outcome in a message box."""
        if result.get("error"):
            messagebox.showwarning(
                "Check for Updates",
                f"Could not check for updates: {result['error']}\n"
                "Check your network connection and try again later.",
            )
            return
        latest = result.get("latest_version", "")
        if result.get("is_update_available"):
            messagebox.showinfo(
                "Check for Updates",
                f"You are on v{VERSION}. Latest release is {latest}.\n"
                "An update is available - see the Releases page on GitHub.",
            )
        else:
            messagebox.showinfo(
                "Check for Updates",
                f"You are on v{VERSION}. Latest release is {latest or 'unknown'}.\n"
                "You are up to date.",
            )

    def _apply_schedule(self) -> None:
        """Start or stop the in-app scheduled-scan timer."""
        try:
            minutes = int(self._schedule_minutes.get().strip())
        except ValueError:
            messagebox.showwarning(
                "Scheduled scan", "Enter a whole number of minutes (0 = off)."
            )
            return
        if minutes != 0 and (minutes < 5 or minutes > 1440):
            messagebox.showwarning(
                "Scheduled scan",
                "Scheduled interval must be 0 (off) or between 5 and 1440 minutes.",
            )
            return
        self.config["scheduled_scan_interval_minutes"] = minutes
        self._schedule_stop.set()
        if self._schedule_thread is not None:
            self._schedule_thread.join(timeout=1)
        if minutes == 0:
            self.status_var.set("Scheduled scans off.")
            return
        self._schedule_stop.clear()
        self._schedule_thread = threading.Thread(
            target=self._schedule_loop, args=(minutes,), daemon=True
        )
        self._schedule_thread.start()
        self.status_var.set(f"Scheduled scans every {minutes} minute(s).")

    def _schedule_loop(self, minutes: int) -> None:
        """Wait, then verify, on a timer - never on the GUI thread."""
        while not self._schedule_stop.wait(minutes * 60):
            path = self.monitored_path.get().strip()
            if path:
                self._run_in_thread("verify")

    def _show_window(self) -> None:
        """Restore the main window from the tray."""
        self.root.deiconify()
        self.root.lift()

    def _verify_from_tray(self) -> None:
        """Run Verify Now from a tray-menu click."""
        self._show_window()
        self._run_in_thread("verify")

    def _quit_from_tray(self) -> None:
        """Quit for real from the tray menu."""
        self._tray.stop()
        self.root.destroy()

    def _on_close(self) -> None:
        """Close to the tray when it is running; otherwise quit."""
        if self._tray.running:
            self.root.withdraw()
            return
        self._tray.stop()
        self.root.destroy()

    def _view_report(self) -> None:
        """Show the newest report, or the baseline status if there is none."""
        try:
            status = get_status(self._baseline_dir())
            messagebox.showinfo(
                "Status",
                f"Monitored path: {status['monitored_path']}\n"
                f"Files in baseline: {status['file_count']}\n"
                f"Last scan: {status['last_scan_utc'] or 'never'}",
            )
        except Exception as exc:
            messagebox.showerror("File Integrity Monitor", str(exc))


def main() -> None:
    """Open the main window."""
    root = tk.Tk()
    FimGui(root)
    root.mainloop()


if __name__ == "__main__":
    main()
