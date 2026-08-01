@echo off
cd /d "%~dp0"
if not exist venv (
    py -m venv venv
    call venv\Scripts\activate.bat
    pip install -r requirements.txt
    pip install psutil
) else (
    call venv\Scripts\activate.bat
)

echo Starting SentinelAI Mock Backend with SQLite...
start "SentinelAI Backend" py mock_backend.py

timeout /t 2 /nobreak >nul

echo Starting SentinelAI Live Telemetry Agent...
start "SentinelAI Telemetry Agent" py sentinel_agent.py

echo Starting SentinelAI Desktop App...
py main.py

pause
