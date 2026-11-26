# File Integrity Monitor — desktop GUI.
# Tkinter only. All hashing and baseline work comes from fim_core.
"""Tkinter GUI for the File Integrity Monitor.

The window never runs a scan on the main thread: every scan runs in a
worker thread and posts its results back with `after`, so the GUI
stays responsive while files are being hashed.
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from fim_core import (
    create_baseline,
    get_key_path,
    get_project_root,
    get_status,
    load_config,
    setup_logging,
    update_baseline,
    verify_baseline,
)

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
        self.root.title("File Integrity Monitor")
        self.root.geometry("900x550")
        self.project_root = get_project_root()
        self.config = load_config(self.project_root / "config.json")
        setup_logging(
            self.project_root / "logs", str(self.config.get("log_level", "INFO"))
        )
        self.monitored_path = tk.StringVar(value="")
        self.monitoring = False
        self._monitor_stop = threading.Event()
        self._results: queue.Queue = queue.Queue()
        self._build_widgets()
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

        columns = ("file", "status", "size", "last_checked")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")
        for column, heading in zip(columns, ("File", "Status", "Size", "Last Checked")):
            self.tree.heading(column, text=heading)
        self.tree.column("file", width=450)
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

    def _baseline_dir(self) -> Path:
        """Return the baseline directory for this project."""
        return self.project_root / str(self.config.get("baseline_path", "baseline"))

    def _run_in_thread(self, action: str) -> None:
        """Run a blocking action in a worker thread so the GUI never freezes."""
        path = self.monitored_path.get().strip()
        if not path:
            messagebox.showwarning("No folder", "Select a folder first.")
            return
        thread = threading.Thread(
            target=self._do_action, args=(action, Path(path)), daemon=True
        )
        thread.start()

    def _do_action(self, action: str, root: Path) -> None:
        """Do the work for one button, then post the outcome to the GUI."""
        baseline_dir = self._baseline_dir()
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
                            (r.relative_path, "OK", str(r.size), r.mtime_utc)
                            for r in result.records
                        ],
                    )
                )
            elif action == "verify":
                result = verify_baseline(root, baseline_dir, key_path)
                rows = []
                for change in result.changes:
                    size = change.new_record.size if change.new_record else 0
                    rows.append(
                        (
                            change.relative_path,
                            change.kind,
                            str(size),
                            result.scanned_at_utc,
                        )
                    )
                self._results.put(
                    (
                        "status",
                        f"Last scan: {result.scanned_at_utc} | checked {result.counts.get('total', 0)} | changes {len(result.changes)}",
                    )
                )
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
                        status = str(row[1])
                        tag = status if status in STATUS_COLOURS else "UNCHANGED"
                        self.tree.insert("", tk.END, values=row, tags=(tag,))
                elif kind == "alert":
                    messagebox.showwarning("File Integrity Monitor", str(payload))
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
