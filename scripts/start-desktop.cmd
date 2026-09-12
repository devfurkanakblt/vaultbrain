@echo off
setlocal
cd /d "%~dp0.."
call npm.cmd run tauri:dev
endlocal
