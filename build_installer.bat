@echo off
REM Build the .exe files and then install them (no MSI, no NSIS).
REM Run this on Windows 11, in the project folder, with the venv activated.
REM Step 1 builds dist\*.exe, step 2 installs them to
REM %LOCALAPPDATA%\FileIntegrityMonitor\ with a Start Menu shortcut.
call build_exe.bat
call install.bat
