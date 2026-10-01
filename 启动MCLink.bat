@echo off
chcp 65001 >nul
cd /d "%~dp0"
set PY=%USERPROFILE%\.workbuddy\binaries\python\versions\3.13.12\python.exe
python mclink_desktop.py 2>nul || "%PY%" mclink_desktop.py
if errorlevel 1 pause
