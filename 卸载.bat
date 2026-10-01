@echo off
chcp 65001 >nul
title 薛朗的联机工具 - 卸载
set DEST=%LOCALAPPDATA%\XueLangLink
echo 正在卸载薛朗的联机工具...
taskkill /F /IM xuelang-link.exe >nul 2>&1
powershell -NoProfile -Command "Remove-Item -LiteralPath ([Environment]::GetFolderPath('Desktop') + '\薛朗的联机工具.lnk') -ErrorAction SilentlyContinue"
powershell -NoProfile -Command "Remove-Item -LiteralPath ([Environment]::GetFolderPath('StartMenu') + '\Programs\薛朗的联机工具.lnk') -ErrorAction SilentlyContinue"
rmdir /S /Q "%DEST%" >nul 2>&1
echo 卸载完成。
pause
