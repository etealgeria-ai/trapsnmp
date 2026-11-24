@echo off
net session >nul 2>&1
if not %ERRORLEVEL%==0 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-autorun.ps1"
if errorlevel 1 (
  echo Install failed.
  pause
  exit /b 1
)
pause
