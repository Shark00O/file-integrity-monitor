@echo off
REM Install the built .exe files (no MSI, no NSIS).
REM Run this on Windows 11, in the project folder, AFTER build_exe.bat.
REM It copies the .exe files and config.example.json into
REM %LOCALAPPDATA%\FileIntegrityMonitor\ and creates a Start Menu shortcut.
REM Nothing is installed anywhere else. To uninstall, delete that folder
REM and the Start Menu shortcut.

set INSTALL_DIR=%LOCALAPPDATA%\FileIntegrityMonitor
if not exist "dist\FileIntegrityMonitor.exe" (
  echo ERROR: dist\FileIntegrityMonitor.exe not found. Run build_exe.bat first.
  pause
  exit /b 1
)
if not exist "dist\fim.exe" (
  echo ERROR: dist\fim.exe not found. Run build_exe.bat first.
  pause
  exit /b 1
)
mkdir "%INSTALL_DIR%" 2>nul
copy /Y "dist\FileIntegrityMonitor.exe" "%INSTALL_DIR%\"
copy /Y "dist\fim.exe" "%INSTALL_DIR%\"
if not exist "%INSTALL_DIR%\config.json" copy /Y "config.example.json" "%INSTALL_DIR%\config.json"

powershell -NoProfile -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%APPDATA%\Microsoft\Windows\Start Menu\Programs\File Integrity Monitor.lnk'); $s.TargetPath = '%INSTALL_DIR%\FileIntegrityMonitor.exe'; $s.WorkingDirectory = '%INSTALL_DIR%'; $s.Description = 'File Integrity Monitor'; $s.Save()"

echo.
echo Installed to %INSTALL_DIR%
echo Start Menu shortcut created: File Integrity Monitor
echo Your baseline, logs and reports will be kept in that folder.
pause
