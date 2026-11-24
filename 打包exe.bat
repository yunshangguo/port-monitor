@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ========================================
echo   打包端口监控工具为 exe
echo ========================================
echo.

echo [1/3] 清理旧构建...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist PortMonitor.spec del /q PortMonitor.spec

echo [2/3] 开始打包（单文件、无控制台）...
python -m PyInstaller --noconfirm --onefile --windowed ^
  --name "端口监控" ^
  --icon "app.ico" ^
  --add-data "port_monitor\web_page.html;port_monitor" ^
  --add-data "port_monitor\server.crt;port_monitor" ^
  --add-data "port_monitor\server.key;port_monitor" ^
  --hidden-import pystray._win32 ^
  --hidden-import PIL.Image ^
  --hidden-import PIL.ImageDraw ^
  main.py

echo [3/3] 打包完成！
echo.
echo exe 位置: %~dp0dist\端口监控.exe
echo.
pause
