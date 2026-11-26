# File Integrity Monitor

A small, honest security tool. It hashes your files with SHA-256, saves a
signed baseline, and tells you when something changes — added, deleted,
modified, renamed, or a permission change.

I built it because I wanted a tool I actually understand, not a black box.
It is the kind of thing Tripwire and AIDE do, written in plain Python so
you can read every line and see how the checking works.

## How it works

1. `init` walks a folder, hashes every file in 64 KB chunks, and writes
   the results to `baseline/baseline.db` plus a signed `baseline.json`.
2. `verify` hashes the folder again and compares it with the baseline.
3. If a file changed, you get an alert on the console, in `logs/`, and
   (if installed) as a desktop notification. A report is saved in `reports/`.
4. `update` rebuilds the baseline — but only after you confirm the
   changes are expected. Verifying never updates the baseline on its own.

Why SHA-256? Because it is the standard for this job: a one-byte change
gives a completely different hash, and there is no practical way to fake
one file's hash with different content. Older hashes are not used here.

The baseline is protected with HMAC-SHA256. The signing key is 32 random
bytes, stored separately from the baseline (`%APPDATA%\FIM\fim.key` on
Windows, `~/.config/fim/fim.key` on Linux). Before every verify, the
signature is checked. If someone edits the baseline, verification
refuses to run and exits with code 2 instead of trusting a forged file.

## Install

### Windows .exe (no Python needed)

Download `FileIntegrityMonitor.exe` from the
[Releases](https://github.com/Shark00O/file-integrity-monitor/releases)
page, put it in its own folder, and double-click it. It keeps its
baseline, logs and reports in the same folder as the .exe. The CLI
version is `fim.exe` in the same release.

To build the .exe yourself on Windows 11, in the project folder:

```bat
venv\Scripts\activate
build_exe.bat
```

That runs PyInstaller and puts the .exe files in `dist/`. Test the
built .exe on a test folder first, then upload it to a GitHub Release.

### From source

You need Python 3.11 or 3.12.

Windows:

```bat
git clone https://github.com/Shark00O/file-integrity-monitor.git
cd file-integrity-monitor
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Linux / macOS:

```bash
git clone https://github.com/Shark00O/file-integrity-monitor.git
cd file-integrity-monitor
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

The core needs no extra packages. `watchdog` (real-time monitoring)
and `plyer` (desktop notifications) are optional — without them the
tool falls back to polling and console/log alerts, and says so.

## Quick start — 5 commands

Run these in a test folder first, not on your whole drive.

```bat
mkdir C:\Users\Shaikh\fim-test
echo hello > C:\Users\Shaikh\fim-test\a.txt
python fim.py init --path C:\Users\Shaikh\fim-test --force
python fim.py verify --path C:\Users\Shaikh\fim-test
echo tampered>> C:\Users\Shaikh\fim-test\a.txt
python fim.py verify --path C:\Users\Shaikh\fim-test
echo %ERRORLEVEL%
```

What you should see: the first verify prints no changes and exits 0.
The second verify prints `[MODIFIED] a.txt`, saves a report in
`reports/`, and exits 1. `echo %ERRORLEVEL%` prints 1.
On Linux/macOS use `echo $?` instead of `echo %ERRORLEVEL%`.

## Commands

All commands take `--path`, `--config`, `--baseline-dir`, `--include`,
`--exclude`, `--max-size`, `--follow-symlinks` and `--verbose`.
Run `python fim.py <command> --help` for the full list.

| Command | What it does |
| --- | --- |
| `python fim.py init --path <folder> [--force]` | Create a signed baseline. Asks before overwriting unless `--force` is given. |
| `python fim.py verify --path <folder>` | Compare the folder with the baseline. Exit 0 = clean, 1 = changes, 2 = error. `scan` is an alias. |
| `python fim.py monitor --path <folder> --interval 60` | Watch the folder. Polling by default; watchdog if installed. Ctrl+C stops it cleanly. Add `--daemon` to run in the background. |
| `python fim.py update --path <folder> [--force]` | Rebuild the baseline after you have reviewed the changes. Asks first unless `--force` is given. |
| `python fim.py status` | Show the monitored path, file count, and last scan. |
| `python fim.py history` | Show the last 20 scans. `list` is an alias. |
| `python fim_gui.py` | Open the desktop GUI (Tkinter, no install needed). |

Exit codes: 0 = no changes, 1 = changes detected, 2 = error
(baseline missing or tampered, path missing, bad config).

## GUI

Run `python fim_gui.py`. The window has buttons for Select Folder,
Create Baseline, Verify Now, Start Monitoring, Stop Monitoring,
View Report and Update Baseline. Results appear in a table with
File, Status, Size and Last Checked. Colours: green = OK, red =
MODIFIED / DELETED, yellow = ADDED, grey = unchanged. Scans run in
a background thread, so the window does not freeze.

## Config — `config.json`

Copy `config.example.json` to `config.json` and edit it. CLI flags
always override the config file.

| Field | Meaning | Default |
| --- | --- | --- |
| `monitored_paths` | List of folders to watch | `[]` |
| `recursive` | Walk subfolders | `true` |
| `include_patterns` | Only hash files matching these globs | `[]` (all files) |
| `exclude_patterns` | Skip files matching these globs | `["*.tmp", "*.log", "__pycache__", "*.bak"]` |
| `hash_chunk_size` | Bytes read per chunk, power of two | `65536` |
| `scan_interval_seconds` | Seconds between monitor scans, 10–3600 | `60` |
| `alert_channels` | `console`, `log`, `desktop`, `email` | `["console", "log"]` |
| `log_level` | `DEBUG`, `INFO`, `WARNING`, `ERROR` | `"INFO"` |
| `baseline_path` | Where the baseline lives | `"baseline"` |
| `report_dir` | Where reports are written | `"reports"` |
| `max_file_size_mb` | Skip files over this size, 0 = no limit | `0` |

An invalid config is rejected with the exact field named, and the
program exits with code 2. A missing config file falls back to
defaults with a warning.

Email alerts are off by default. To turn them on, add `"email"` to
`alert_channels` and set `FIM_SMTP_HOST`, `FIM_SMTP_PORT`,
`FIM_SMTP_USER`, `FIM_SMTP_PASSWORD` and `FIM_ALERT_EMAIL` in your
environment (see `.env.example`). Never put a password in the config
file or in the code.

## Security model — what it can and cannot do

Can detect: a file edited, replaced, added, deleted or renamed;
ransomware encrypting files in a monitored folder; a config file
changed by another program; someone tampering with the baseline
itself (the HMAC check fails first).

Cannot detect: an attacker who steals *both* the baseline and the
HMAC key and forges a new signed baseline; a kernel-level rootkit
that lies to the operating system about file contents; changes in
folders you never told it to monitor. No file monitor can fix those
on its own — that is why the key is kept separate and why you should
back it up somewhere safe, and re-run `init` if you lose it.

## Troubleshooting

- **"Baseline not found. Run fim init first."** — you ran `verify`
  before `init`, or you used a different `--baseline-dir`.
- **"[CRITICAL] Baseline tampered or corrupt."** — the baseline was
  edited, or the key is missing/wrong. Check what changed, then
  rebuild with `fim init --force` only if you are sure it is safe.
- **Permission denied on a file** — the file is logged as an error
  and the scan carries on. Run from an account that can read the
  folder; the tool does not need Administrator/root for normal use.
- **Long paths on Windows** — paths over 260 characters are handled
  with the `\\?\` prefix where possible. Keep monitored folders
  reasonably shallow if you hit errors.
- **A file is locked by another program** — it is logged and skipped
  for that scan, not treated as deleted.
- **"Watchdog is not installed; falling back to polling."** —
  install it with `pip install watchdog`, or keep polling; polling
  works fine, it just checks on a timer instead of instantly.
- **GUI does not open** — Tkinter ships with standard Python on
  Windows. On Linux you may need your distribution's `tk` package.

## Project layout

```
file-integrity-monitor/
├── fim.py                  CLI entry point
├── fim_core.py             hashing, baseline, HMAC, scan, alerts, reports
├── fim_monitor.py          polling + watchdog monitor
├── fim_gui.py              Tkinter GUI (uses fim_core, no copied logic)
├── config.json, config.example.json, requirements.txt
├── pyproject.toml, .env.example, .gitignore, LICENSE
├── baseline/ reports/ logs/
└── tests/                  pytest tests
```

## Tests

```bash
python -m pytest -q
python -m pytest tests/test_security.py -q
```

The suite covers the SHA-256 "hello" vector, chunked hashing,
baseline create/verify, MODIFIED / ADDED / DELETED / RENAMED /
permission changes, HMAC tampering, symlinks outside the root,
path traversal, empty files and unreadable files.

## License

MIT — see `LICENSE`.
