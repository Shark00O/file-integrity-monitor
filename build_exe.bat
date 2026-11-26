@echo off
REM Build Windows .exe files with PyInstaller. Run this on Windows 11,
REM in the project folder, with the venv activated.
REM Output: dist\FileIntegrityMonitor.exe (GUI) and dist\fim.exe (CLI).
REM The .exe files keep their baseline, logs and reports next to the
REM .exe, not in a temp folder (see get_project_root in fim_core.py).

pip install pyinstaller pystray pillow
pyinstaller --noconfirm --clean --onefile --windowed --name FileIntegrityMonitor --add-data "config.json;." --collect-all pystray --hidden-import PIL fim_gui.py
pyinstaller --noconfirm --clean --onefile --name fim --add-data "config.json;." fim.py
REM Note: the Windows .exe was not built on Linux and is not claimed
REM to have been built here. Build it on Windows 11 with this script.

echo.
echo Built:
echo   dist\FileIntegrityMonitor.exe
echo   dist\fim.exe
echo Test them in a copy of a test folder before uploading to GitHub Releases.
pause
