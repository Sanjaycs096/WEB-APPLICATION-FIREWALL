@echo off
echo ============================================
echo   Transformer WAF - Quick Start
echo ============================================
echo.

REM Start Backend API in new window
echo Starting Backend API Server...
start "WAF Backend API" cmd /k "cd /d %~dp0 && set WAF_DEVICE=cpu&& py -m api.waf_api"

REM Wait a moment for backend to initialize
timeout /t 3 /nobreak >nul

REM Start Frontend Dashboard in new window
echo Starting Frontend Dashboard...
start "WAF Frontend Dashboard" cmd /k "cd /d %~dp0frontend && npm run dev"

echo.
echo ============================================
echo   Services Starting...
echo ============================================
echo.
echo Backend API will be available at:
echo   http://localhost:8000
echo.
echo Frontend Dashboard will be available at:
echo   http://localhost:3000
echo.
echo Please wait 30-40 seconds for model to load
echo.
echo Press any key to open dashboard in browser...
pause >nul

REM Open dashboard in default browser
start http://localhost:3000/dashboard

echo.
echo Dashboard opened in browser!
echo.
echo To stop the services, close the two terminal windows.
echo.
