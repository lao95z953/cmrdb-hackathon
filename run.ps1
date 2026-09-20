# run.ps1 - MailGuard One-Click Startup Script
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

# 1. Check and create .env
if (-not (Test-Path ".env")) {
    Write-Host "[1/3] Generating .env from .env.example..." -ForegroundColor Cyan
    Copy-Item ".env.example" ".env"
}

# 2. Check virtual environment
if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "[2/3] Setting up Python virtual environment and SLM dependencies..." -ForegroundColor Cyan
    $uvPath = (Get-Command uv -ErrorAction SilentlyContinue).Source
    if (-not $uvPath -and (Test-Path "$env:USERPROFILE\.local\bin\uv.exe")) {
        $uvPath = "$env:USERPROFILE\.local\bin\uv.exe"
    }

    if ($uvPath) {
        Write-Host "Using uv to create virtual environment (Python 3.12)..." -ForegroundColor Gray
        & $uvPath venv .venv --python 3.12
        & $uvPath pip install -r requirements-slm.txt
    } else {
        Write-Host "Using system python to create virtual environment..." -ForegroundColor Gray
        python -m venv .venv
        .\.venv\Scripts\pip install -r requirements-slm.txt
    }
}

# 3. Start server
Write-Host "[3/3] Starting MailGuard server at http://127.0.0.1:8000..." -ForegroundColor Green
.\.venv\Scripts\python -m uvicorn mail_guard.api:app --host 127.0.0.1 --port 8000 --reload
