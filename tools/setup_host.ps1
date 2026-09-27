param([string]$PythonVersion = "3.12")
$ErrorActionPreference = "Stop"
$LabRoot = Split-Path -Parent $PSScriptRoot
Push-Location $LabRoot
try {
    if (-not (Test-Path ".venv\Scripts\python.exe")) {
        & py "-$PythonVersion" -m venv .venv
        if ($LASTEXITCODE -ne 0) { throw "Install Python $PythonVersion with the Windows py launcher first." }
    }
    & .\.venv\Scripts\python.exe -m pip install -e . -c requirements-tested.txt
    if ($LASTEXITCODE -ne 0) { throw "Host dependency installation failed." }
    & .\.venv\Scripts\python.exe tools\doctor.py
    if ($LASTEXITCODE -ne 0) { throw "Host environment check failed." }
    Write-Host "Ready. Use .\.venv\Scripts\python.exe -m ids_update_lab --help"
} finally { Pop-Location }
