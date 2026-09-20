@echo off
setlocal

cd /d "%~dp0"
if errorlevel 1 goto :error

if not exist ".env" (
    echo [1/4] Generating .env from .env.example...
    copy ".env.example" ".env" >nul
    if errorlevel 1 goto :error
) else (
    echo [1/4] Using existing .env...
)

set "PYTHON=.venv\Scripts\python.exe"
set "UV="
where uv >nul 2>nul
if not errorlevel 1 set "UV=uv"
if not defined UV if exist "%USERPROFILE%\.local\bin\uv.exe" set "UV=%USERPROFILE%\.local\bin\uv.exe"

if defined UV goto :setup_uv
goto :setup_python

:setup_uv
echo [2/4] Synchronizing the Python 3.12 environment with uv...
"%UV%" sync --locked --python 3.12
if errorlevel 1 goto :error
goto :validate

:setup_python
echo [2/4] Synchronizing the environment with pip...
if exist "%PYTHON%" goto :pip_install

where py >nul 2>nul
if not errorlevel 1 (
    py -3.12 -m venv .venv
    if errorlevel 1 goto :error
    goto :pip_install
)

where python >nul 2>nul
if errorlevel 1 (
    echo Python 3.12 is required. Install Python or uv, then run this script again.
    goto :error
)
python -m venv .venv
if errorlevel 1 goto :error

:pip_install
"%PYTHON%" -m pip install -r requirements-slm.txt
if errorlevel 1 goto :error

:validate
echo [3/4] Checking runtime imports...
"%PYTHON%" -c "import fastapi, torch, transformers, uvicorn"
if errorlevel 1 goto :error

:start
echo [4/4] Starting MailGuard at http://127.0.0.1:8000...
"%PYTHON%" -m uvicorn mail_guard.api:app --host 127.0.0.1 --port 8000
if errorlevel 1 goto :error
exit /b 0

:error
echo.
echo MailGuard setup or startup failed. Review the error above.
pause
exit /b 1
