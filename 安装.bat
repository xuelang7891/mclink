@echo off
chcp 65001 >nul
title 薛朗的联机工具 - 安装
set DEST=%LOCALAPPDATA%\XueLangLink
echo ============================================
echo   薛朗的联机工具 - 安装
echo   我的世界 Java 版 P2P 联机（免服务器）
echo ============================================
echo.
if not exist "%~dp0xuelang-link\xuelang-link.exe" (
  echo [错误] 没找到 xuelang-link 文件夹，请解压完整安装包后再运行本脚本。
  pause
  exit /b 1
)
echo [1/2] 复制程序到 %DEST% ...
xcopy /E /I /Y "%~dp0xuelang-link" "%DEST%\xuelang-link" >nul
if errorlevel 1 (
  echo [错误] 复制失败，请先关闭正在运行的联机工具再重试。
  pause
  exit /b 1
)
echo [2/2] 创建桌面和开始菜单快捷方式...
powershell -NoProfile -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut([Environment]::GetFolderPath('Desktop') + '\薛朗的联机工具.lnk'); $s.TargetPath = '%DEST%\xuelang-link\xuelang-link.exe'; $s.WorkingDirectory = '%DEST%\xuelang-link'; $s.Save()"
powershell -NoProfile -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut([Environment]::GetFolderPath('StartMenu') + '\Programs\薛朗的联机工具.lnk'); $s.TargetPath = '%DEST%\xuelang-link\xuelang-link.exe'; $s.Save()"
echo.
echo 安装完成！桌面已创建「薛朗的联机工具」快捷方式。
echo 双击快捷方式即可使用（会自动打开控制台网页）。
echo.
choice /C YN /M "现在就打开程序吗"
if errorlevel 2 exit /b 0
start "" "%DEST%\xuelang-link\xuelang-link.exe"
exit /b 0
