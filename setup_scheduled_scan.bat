@echo off
REM Create a daily Windows Task Scheduler task that runs fim.exe verify.
REM Run this on Windows 11 as Administrator, in the folder that holds
REM fim.exe (the installed folder, or the project dist\ folder).
REM Usage: setup_scheduled_scan.bat "C:\Users\Shaikh\Documents\Important"
REM If no folder is given, you will be asked for one.
REM To remove the task later: schtasks /delete /tn "FileIntegrityMonitor Daily Scan" /f

set FOLDER=%~1
if "%FOLDER%"=="" set /p FOLDER=Folder to scan daily:
if "%FOLDER%"=="" (
  echo ERROR: no folder given.
  pause
  exit /b 1
)
if not exist "%~dp0fim.exe" (
  echo ERROR: fim.exe not found next to this script.
  echo Copy this script into the folder that holds fim.exe and run it again.
  pause
  exit /b 1
)
schtasks /create /tn "FileIntegrityMonitor Daily Scan" /tr "\"%~dp0fim.exe\" verify --path \"%FOLDER%\"" /sc daily /st 09:00 /f
if errorlevel 1 (
  echo.
  echo Task creation failed. Right-click this script and choose "Run as administrator", then try again.
  pause
  exit /b 1
)
echo.
echo Scheduled daily scan created: 09:00 every day, folder "%FOLDER%"
echo To check it: schtasks /query /tn "FileIntegrityMonitor Daily Scan"
pause
