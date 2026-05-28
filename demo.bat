@echo off
setlocal

cd /d "%~dp0"

if exist "venv\Scripts\activate.bat" (
  call "venv\Scripts\activate.bat"
)

echo Starting WAF demo site on http://127.0.0.1:5000
py demo_site/app.py
