@echo off
cd /d "%~dp0"
if not exist venv (
    py -m venv venv
    call venv\Scripts\activate.bat
    pip install -r requirements.txt
) else (
    call venv\Scripts\activate.bat
)
start "SentinelAI Mock Backend" py mock_backend.py
py main.py
pause
