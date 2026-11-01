# Original software author: Oleksandr Kuznetsov.
[CmdletBinding()]
param(
    [ValidateSet('Inspect','Run')][string]$Mode = 'Inspect',
    [string]$Workspace = 'E:\ids-update-lab',
    [string]$Source = '',
    [string]$Output = '',
    [string]$Port = 'COM13',
    [string]$BoardId = 'esp32s3-a0f262ebb558'
)
$ErrorActionPreference = 'Stop'
$PythonExe = Join-Path $Workspace '.venv039\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $PythonExe)) {
    throw 'Existing .venv039 is required. No installation or board access was attempted.'
}
$env:PYTHONUTF8 = '1'
$env:PYTHONUNBUFFERED = '1'
$Arguments = @((Join-Path $PSScriptRoot 'recover039.py'), $Mode.ToLowerInvariant(), '--workspace', $Workspace, '--board-id', $BoardId)
if ($Source) { $Arguments += @('--source', $Source) }
if ($Output) { $Arguments += @('--output', $Output) }
if ($Mode -eq 'Run') { $Arguments += @('--port', $Port) }
& $PythonExe @Arguments
exit $LASTEXITCODE
