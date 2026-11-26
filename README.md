# File Integrity Monitor

I built this because I wanted a file checker I actually understand. It
hashes your files with SHA-256, saves a signed baseline, and tells you
when something changes: added, deleted, modified, renamed, or a
permission change.

It is the kind of thing Tripwire and AIDE do, just written in plain
Python so you can read every line. I am a cybersecurity student, and
this started as a way to learn how file integrity checking really
works, not just read about it.

## How it works

1. `init` walks a folder, hashes every file in 64 KB chunks, and writes
   the results to `baseline/baseline.db` plus a signed, encrypted
   `baseline.json`.
2. `verify` hashes the folder again and compares it with the baseline.
3. If a file changed, you get an alert on the console, in `logs/`, and
   (if it is set up) as a desktop notification. A report is saved in
   `reports/`.
4. `update` rebuilds the baseline, but only after you confirm the
   changes are expected. Verifying never updates the baseline on its
   own.

Why SHA-256? A one-byte change gives a completely different hash, and
there is no practical way to fake one file's hash with different
content. Older hashes like MD5 and SHA-1 are not used here.

The baseline is protected with HMAC-SHA256. The signing key is 32
random bytes, stored separately from the baseline
(`%APPDATA%\FIM\fim.key` on Windows, `~/.config/fim/fim.key` on
Linux). Before every verify, the signature is checked. If someone
edits the baseline, verification refuses to run and exits with code
2 instead of trusting a forged file.

Since v1.1, `baseline.json` is also encrypted. It uses an
HMAC-SHA256 counter-mode stream cipher, with the key derived from the
HMAC key. That is not AES-256, and I am not going to pretend it is.
`baseline.db` is still plaintext and relies on OS file permissions.
`fim.py rotate-key` replaces the key.

## What is new in v1.1

Version 1.1.0 adds eight things on top of v1.0.0. Nothing from v1.0
was removed, and a single-folder baseline from v1.0 still works.

1. Webhook alerts. Set `webhook_url` in `config.json`, or use the
   `FIM_WEBHOOK_URL` environment variable, and set `webhook_type` to
   `discord`, `slack` or `generic`. Then add `"webhook"` to
   `alert_channels`. It posts JSON with stdlib `urllib` only, 10
   second timeout. A dead webhook is logged and never crashes a scan.
   Only `http://` and `https://` URLs are accepted. Never commit a
   real webhook URL, use the environment variable.
2. Better GUI. Verify Now shows all files now, not just the changed
   ones. Unchanged files show as OK. There is a View History button
   (last 20 scans) and an Export Report button that saves the current
   scan to `reports/` as CSV and JSON.
3. Windows installer and auto-update. After building the .exe, run
   `build_installer.bat` to copy the exes into
   `%LOCALAPPDATA%\FileIntegrityMonitor\` and make a Start Menu
   shortcut. There is no MSI, it is just a batch file copy.
   `fim.py check-update` asks the GitHub Releases API for the latest
   release and tells you if a newer version is out. A network failure
   just prints a friendly message.
4. System tray and scheduled scans. The GUI puts an icon in the
   system tray when `pystray` is installed. Closing the window
   minimises to the tray instead of quitting. If `pystray` is not
   installed, the GUI still works and logs that the tray is not
   available. You can also set a scheduled scan interval in config
   (`scheduled_scan_interval_minutes`, 0 means off, 5 to 1440), or
   use `fim.py schedule --path <folder> --interval-minutes 60`. On
   Windows, `setup_scheduled_scan.bat` makes a daily 09:00 Task
   Scheduler task. It needs Admin.
5. Mass-change alert. If one scan changes at least 10 files, or at
   least 20 percent of the files (and at least 3 files, so one
   changed file in a tiny folder does not count), the result is
   flagged as a mass change and sent through every alert channel.
   The baseline is not auto-updated. You have to review the changes
   and run `update --force` yourself.
6. Several folders at once. `monitored_paths` in config is a list,
   and the CLI, GUI and monitor now use all of it. On the CLI, repeat
   `--path` or pass a comma-separated list. Each folder gets its own
   baseline subfolder under `baseline/`, named after the folder plus
   the first 12 hex characters of the SHA-256 of its absolute path.
   A single folder still uses `baseline/` itself, like in v1.0.
   Switching between one folder and several needs `init` run again
   for the folders involved.
7. Dark mode. The GUI has a Dark Mode / Light Mode toggle button.
   The choice is saved in config as `gui_theme` (`light` or
   `dark`, default `light`).
8. Encrypted baseline and key rotation. `baseline.json` is encrypted
   at rest, as described above. `fim.py rotate-key --path <folder>`
   (or the Rotate Key button in the GUI) checks the old baseline
   first, then re-encrypts and re-signs it with a fresh 32-byte key.
   It refuses if the old baseline was tampered with. A v1.0
   unencrypted baseline still loads, and it is moved to the
   encrypted format on the next `update` or `init`.

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
and `plyer` (desktop notifications) are optional. Without them the
tool falls back to polling and console/log alerts, and says so.

## Quick start: 5 commands

Run these in a test folder first, not on your whole drive.

```bat
mkdir C:\Users\you\fim-test
echo hello > C:\Users\you\fim-test\a.txt
python fim.py init --path C:\Users\you\fim-test --force
python fim.py verify --path C:\Users\you\fim-test
echo tampered>> C:\Users\you\fim-test\a.txt
python fim.py verify --path C:\Users\you\fim-test
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
| `python fim.py check-update [--force]` | Check GitHub Releases for a newer version. |
| `python fim.py schedule --path <folder> --interval-minutes 60` | Run verify every N minutes until stopped. |
| `python fim.py rotate-key --path <folder>` | Re-encrypt and re-sign the baseline with a fresh key. |
| `python fim_gui.py` | Open the desktop GUI (Tkinter, no install needed). |

Exit codes: 0 = no changes, 1 = changes detected, 2 = error
(baseline missing or tampered, path missing, bad config).

## GUI

Run `python fim_gui.py`. The window has buttons for Select Folder,
Add Folder, Remove Selected, Create Baseline, Verify Now, Start
Monitoring, Stop Monitoring, View Report, Update Baseline, View
History, Export Report, Check for Updates and Rotate Key, plus a
Dark Mode toggle and a scheduled scan control (Apply Schedule).
Results appear in a table with Folder, File, Status, Size and Last
Checked, and Verify Now lists every file. Unchanged files show as
OK in grey, changed files show with their status colour. Colours:
green = OK, red = MODIFIED / DELETED, yellow = ADDED, orange =
RENAMED / PERMISSION_CHANGED, grey = unchanged. Scans run in a
background thread, so the window does not freeze. Closing the window
minimises to the system tray when pystray is installed, otherwise
it quits.

## Config: `config.json`

Copy `config.example.json` to `config.json` and edit it. CLI flags
always override the config file.

| Field | Meaning | Default |
| --- | --- | --- |
| `monitored_paths` | List of folders to watch | `[]` |
| `recursive` | Walk subfolders | `true` |
| `include_patterns` | Only hash files matching these globs | `[]` (all files) |
| `exclude_patterns` | Skip files matching these globs | `["*.tmp", "*.log", "__pycache__", "*.bak"]` |
| `hash_chunk_size` | Bytes read per chunk, power of two | `65536` |
| `scan_interval_seconds` | Seconds between monitor scans, 10-3600 | `60` |
| `alert_channels` | `console`, `log`, `desktop`, `email`, `webhook` | `["console", "log"]` |
| `webhook_url` | Discord/Slack/generic webhook URL (empty = off) | `""` |
| `webhook_type` | `discord`, `slack`, `generic` | `"discord"` |
| `check_for_updates` | Allow update checks | `true` |
| `scheduled_scan_interval_minutes` | In-app scheduled scan, 0 = off, 5-1440 | `0` |
| `mass_change_threshold` | Files changed that trips a mass-change alert | `10` |
| `mass_change_percent` | Percent changed that trips it (needs 3 or more files) | `20` |
| `gui_theme` | GUI theme, `light` or `dark` | `"light"` |
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

## Security model: what it can and cannot do

Can detect: a file edited, replaced, added, deleted or renamed;
ransomware encrypting files in a monitored folder; a config file
changed by another program; someone tampering with the baseline
itself (the HMAC check fails first).

Cannot detect: an attacker who steals both the baseline and the
HMAC key and forges a new signed baseline; a kernel-level rootkit
that lies to the operating system about file contents; changes in
folders you never told it to monitor. No file monitor fixes those
on its own. That is why the key is kept separate, and why you should
back it up somewhere safe and re-run `init` if you lose it.

## Things that are not perfect yet

I would rather list the gaps than hide them.

- The Windows .exe, tray icon, installer and Task Scheduler script
  have been built and tested on Linux only so far. They still need
  a real run on Windows 11.
- The webhook code has only been tested with mocked network calls.
  I have not sent a real alert to a Discord or Slack webhook yet.
- The GUI has only been tested headless on Linux (the theme logic).
  I have not clicked through the real window on Windows yet, dark
  mode included.
- The encryption on `baseline.json` is not AES-256. If the HMAC key
  leaks, an attacker can decrypt the baseline. `baseline.db` is
  still plaintext.
- The mass-change rule (10 files, or 20 percent) is a guess I picked.
  It will miss slow ransomware that changes a few files at a time.
- Big folders have not been benchmarked. I have not tried a 10 GB
  scan, and I do not know how slow it gets.
- Email alerts and the watchdog real-time path have not been tested
  end to end yet.

## Troubleshooting

- **"Baseline not found. Run fim init first."** You ran `verify`
  before `init`, or you used a different `--baseline-dir`.
- **"[CRITICAL] Baseline tampered or corrupt."** The baseline was
  edited, or the key is missing or wrong. Check what changed, then
  rebuild with `fim init --force` only if you are sure it is safe.
- **Permission denied on a file.** The file is logged as an error
  and the scan carries on. Run from an account that can read the
  folder. The tool does not need Administrator or root for normal use.
- **Long paths on Windows.** Paths over 260 characters are handled
  with the `\\?\` prefix where possible. Keep monitored folders
  reasonably shallow if you hit errors.
- **A file is locked by another program.** It is logged and skipped
  for that scan, not treated as deleted.
- **"Watchdog is not installed; falling back to polling."**
  Install it with `pip install watchdog`, or keep polling. Polling
  works fine, it just checks on a timer instead of instantly.
- **GUI does not open.** Tkinter ships with standard Python on
  Windows. On Linux you may need your distribution's `tk` package.

## Project layout

```
file-integrity-monitor/
├── fim.py                  CLI entry point
├── fim_core.py             hashing, baseline, HMAC, scan, alerts, reports
├── fim_monitor.py          polling + watchdog monitor
├── fim_gui.py              Tkinter GUI (uses fim_core, no copied logic)
├── fim_tray.py             optional system-tray icon (pystray)
├── install.bat, build_installer.bat   Windows installer (copy + shortcut)
├── setup_scheduled_scan.bat  Windows Task Scheduler daily scan
├── config.json, config.example.json, requirements.txt
├── pyproject.toml, .env.example, .gitignore, LICENSE
├── baseline/ reports/ logs/
└── tests/                  pytest tests (72 tests)
```

## Tests

```bash
python -m pytest -q
python -m pytest tests/test_security.py -q
```

The suite covers the SHA-256 "hello" vector, chunked hashing,
baseline create and verify, MODIFIED / ADDED / DELETED / RENAMED /
permission changes, HMAC tampering, symlinks outside the root,
path traversal, empty files and unreadable files, plus v1.1:
webhook payloads (Discord, Slack, generic, mocked network, invalid
URL rejection, failure never raising), update checks (newer,
current, older, network failure, mocked), mass-change rules,
multi-folder init and verify, dark-mode theme logic, encrypted
baseline, old plain baseline loading, key rotation (old key fails,
new key works, tampered baseline refused), export of all files,
and the tray fallback when pystray is missing. GUI window tests
are not run headless, only the theme logic is tested without a
display.

## License

MIT, see `LICENSE`.
