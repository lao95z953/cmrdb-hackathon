# MailGuard one-click startup for Windows PowerShell.
$ErrorActionPreference = "Stop"

function Assert-NativeSuccess([string]$Message) {
    if ($LASTEXITCODE -ne 0) {
        throw "$Message (exit code $LASTEXITCODE)"
    }
}

try {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    Set-Location $scriptDir

    if (-not (Test-Path ".env")) {
        Write-Host "[1/4] Generating .env from .env.example..." -ForegroundColor Cyan
        Copy-Item ".env.example" ".env"
    } else {
        Write-Host "[1/4] Using existing .env..." -ForegroundColor Gray
    }

    $pythonPath = Join-Path $scriptDir ".venv\Scripts\python.exe"
    $uvCommand = Get-Command uv -ErrorAction SilentlyContinue
    $uvPath = if ($uvCommand) { $uvCommand.Source } else { $null }
    $fallbackUv = Join-Path $env:USERPROFILE ".local\bin\uv.exe"
    if (-not $uvPath -and (Test-Path $fallbackUv)) {
        $uvPath = $fallbackUv
    }

    if ($uvPath) {
        Write-Host "[2/4] Synchronizing the Python 3.12 environment with uv..." -ForegroundColor Cyan
        & $uvPath sync --locked --python 3.12
        Assert-NativeSuccess "uv could not synchronize dependencies"
    } else {
        Write-Host "[2/4] Synchronizing the environment with pip..." -ForegroundColor Cyan
        if (-not (Test-Path $pythonPath)) {
            $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
            $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
            if ($pyLauncher) {
                & $pyLauncher.Source -3.12 -m venv .venv
                Assert-NativeSuccess "Python 3.12 could not create the virtual environment"
            } elseif ($pythonCommand) {
                & $pythonCommand.Source -m venv .venv
                Assert-NativeSuccess "Python could not create the virtual environment"
            } else {
                throw "Python 3.12 is required. Install Python or uv, then run this script again."
            }
        }
        & $pythonPath -m pip install -r requirements-slm.txt
        Assert-NativeSuccess "pip could not install the SLM dependencies"
    }

    Write-Host "[3/4] Checking runtime imports..." -ForegroundColor Cyan
    & $pythonPath -c "import fastapi, torch, transformers, uvicorn"
    Assert-NativeSuccess "The Python runtime check failed"

    Write-Host "[4/4] Starting MailGuard at http://127.0.0.1:8000..." -ForegroundColor Green
    & $pythonPath -m uvicorn mail_guard.api:app --host 127.0.0.1 --port 8000
    Assert-NativeSuccess "MailGuard stopped with an error"
} catch {
    Write-Host "MailGuard setup or startup failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
