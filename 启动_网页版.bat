@echo off
chcp 65001 >nul
cd /d "%~dp0"
python -c "import psutil" >nul 2>nul
if errorlevel 1 (
  echo Installing dependencies, please wait...
  python -m pip install psutil
)
echo Starting web service...
python "%~dp0main.py" --mode web
pause
