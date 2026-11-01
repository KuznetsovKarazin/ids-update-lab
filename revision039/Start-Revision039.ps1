# Original software author: Oleksandr Kuznetsov.
[CmdletBinding()]
param(
    [ValidateSet('Inspect','Prepare','PC','MCU','All','Analyze','Status','Pack')]
    [string]$Mode = 'Inspect',
    [string]$Workspace = 'E:\ids-update-lab',
    [string]$DataRoot = '',
    [string]$PriorRun = '',
    [string]$Output = '',
    [string]$Port = 'COM13',
    [string]$BoardId = 'esp32s3-a0f262ebb558'
)
$ErrorActionPreference = 'Stop'
$KitRoot = Split-Path -Parent $PSScriptRoot
$VenvRoot = Join-Path $Workspace '.venv039'
$PythonExe = Join-Path $VenvRoot 'Scripts\python.exe'
if (-not (Test-Path -LiteralPath $PythonExe)) {
    $ChosenVersion = $null
    foreach ($Candidate in @('-3.13','-3.12','-3.11')) {
        try {
            & py $Candidate -c 'import sys; print(sys.version)' 2>$null
            if ($LASTEXITCODE -eq 0) { $ChosenVersion = $Candidate; break }
        } catch { continue }
    }
    if (-not $ChosenVersion) { throw 'Python 3.11, 3.12 or 3.13 is required.' }
    & py $ChosenVersion -m venv $VenvRoot
    if ($LASTEXITCODE -ne 0) { throw 'Could not create .venv039' }
}
$Requirements = Join-Path $PSScriptRoot 'requirements.txt'
$DependencyStamp = Join-Path $VenvRoot 'revision039-requirements.sha256'
$RequirementHash = (Get-FileHash -LiteralPath $Requirements -Algorithm SHA256).Hash
$InstallNeeded = -not (Test-Path -LiteralPath $DependencyStamp)
if (-not $InstallNeeded) { $InstallNeeded = ((Get-Content -LiteralPath $DependencyStamp -Raw).Trim() -ne $RequirementHash) }
if ($InstallNeeded) {
    & $PythonExe -m pip install -r $Requirements
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed; no board was accessed.' }
    [System.IO.File]::WriteAllText($DependencyStamp, $RequirementHash)
}
$env:PYTHONUTF8 = '1'
$env:PYTHONUNBUFFERED = '1'
$Arguments = @((Join-Path $PSScriptRoot 'run_revision039.py'), $Mode.ToLowerInvariant(), '--workspace', $Workspace)
if ($DataRoot) { $Arguments += @('--data-root', $DataRoot) }
if ($PriorRun) { $Arguments += @('--prior-run', $PriorRun) }
if ($Output) { $Arguments += @('--output', $Output) }
if ($Mode -in @('MCU','All')) { $Arguments += @('--port', $Port, '--board-id', $BoardId) }
& $PythonExe @Arguments
exit $LASTEXITCODE
