# Build the Praxis Lite standalone bundle on Windows.
#
#   powershell -ExecutionPolicy Bypass -File packaging\build.ps1
#
# Produces dist\artifacts\Praxis-Lite-windows.zip

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

$Py = if ($env:PYTHON) { $env:PYTHON } else { "python" }

Write-Host "==> Building Praxis Lite for Windows"

& $Py -m pip install --quiet --upgrade pyinstaller

if (Test-Path build\pyinstaller) { Remove-Item -Recurse -Force build\pyinstaller }
if (Test-Path dist\praxis) { Remove-Item -Recurse -Force dist\praxis }

& $Py -m PyInstaller packaging\praxis.spec --noconfirm --distpath dist --workpath build\pyinstaller

New-Item -ItemType Directory -Force -Path dist\artifacts | Out-Null
$Out = "dist\artifacts\Praxis-Lite-windows.zip"
if (Test-Path $Out) { Remove-Item $Out }
Compress-Archive -Path dist\praxis\* -DestinationPath $Out

Write-Host "==> Wrote $Out"
