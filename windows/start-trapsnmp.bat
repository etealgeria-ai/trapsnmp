@echo off
setlocal
cd /d "%~dp0.."
if not exist "data" mkdir "data"
set "TRAPSNMP_DATA=%CD%\data"
set "PYTHONUNBUFFERED=1"
set "LOG=%TRAPSNMP_DATA%\trapsnmp.log"

set "PYEXE="
if exist "%~dp0python.path" set /p PYEXE=<"%~dp0python.path"
if defined PYEXE if exist "%PYEXE%" goto run

where py >nul 2>&1
if %ERRORLEVEL%==0 (
  for /f "delims=" %%P in ('py -3 -c "import sys; print(sys.executable)"') do set "PYEXE=%%P"
)
if not defined PYEXE (
  for /f "delims=" %%P in ('where python 2^>nul') do (
    set "PYEXE=%%P"
    goto run
  )
)
if not defined PYEXE (
  echo trapsnmp: Python was not found.>> "%LOG%"
  exit /b 1
)

:run
echo trapsnmp starting %DATE% %TIME%>> "%LOG%"
"%PYEXE%" -m trapsnmp >> "%LOG%" 2>&1
exit /b %ERRORLEVEL%
