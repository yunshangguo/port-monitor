@echo off
chcp 65001 >nul
cd /d "%~dp0"
python -c "import psutil,pystray,PIL" >nul 2>nul
if errorlevel 1 (
  echo Installing dependencies, please wait...
  python -m pip install -r "%~dp0requirements.txt"
)
start "" pythonw "%~dp0main.py" --mode tray
