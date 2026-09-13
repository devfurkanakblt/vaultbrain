@echo off
setlocal
cd /d "%~dp0.."
call npm.cmd run tauri:dev
set "exitCode=%errorlevel%"
if not "%exitCode%"=="0" (
  echo.
  echo Vault Brain desktop failed with exit code %exitCode%.
  pause
)
endlocal
exit /b %exitCode%
