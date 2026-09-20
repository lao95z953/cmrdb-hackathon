@echo off
setlocal

cd /d "%~dp0"

:: 1. Check and create .env
if not exist ".env" (
    echo [1/3] Generating .env from .env.example...
    copy ".env.example" ".env" > nul
)

:: 2. Check virtual environment
if not exist ".venv\Scripts\python.exe" (
    echo [2/3] Setting up Python virtual environment and SLM dependencies...
    where uv >nul 2>nul
    if %errorlevel% equ 0 (
        echo Using uv to create virtual environment...
        uv venv .venv --python 3.12
        uv pip install -r requirements-slm.txt
    ) else if exist "%USERPROFILE%\.local\bin\uv.exe" (
        echo Using %USERPROFILE%\.local\bin\uv.exe to create virtual environment...
        "%USERPROFILE%\.local\bin\uv.exe" venv .venv --python 3.12
        "%USERPROFILE%\.local\bin\uv.exe" pip install -r requirements-slm.txt
    ) else (
        echo Using system python to create virtual environment...
        python -m venv .venv
        call .venv\Scripts\pip install -r requirements-slm.txt
    )
)

:: 3. Start server
echo [3/3] Starting MailGuard server at http://127.0.0.1:8000...
call .venv\Scripts\python -m uvicorn mail_guard.api:app --host 127.0.0.1 --port 8000 --reload
pause
