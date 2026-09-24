# Praxis one-line installer for Windows (PowerShell).
#
#   irm https://raw.githubusercontent.com/praxisgaurdrails/praxis-lite/main/install.ps1 | iex
#
# Downloads the standalone Praxis Lite app (no Python or pip required),
# installs it under %LOCALAPPDATA%\Praxis, puts `praxis` on your PATH,
# picks a safe default policy, and connects it to your AI tools.

$ErrorActionPreference = "Stop"
$Repo    = "praxisgaurdrails/praxis-lite"
$AppDir  = Join-Path $env:LOCALAPPDATA "Praxis\app"
$BinDir  = Join-Path $env:LOCALAPPDATA "Praxis\bin"
$Asset   = "Praxis-Lite-windows.zip"
$Url     = "https://github.com/$Repo/releases/latest/download/$Asset"

Write-Host "Downloading Praxis for Windows..." -ForegroundColor Cyan
$Tmp = Join-Path $env:TEMP "praxis.zip"
Invoke-WebRequest -Uri $Url -OutFile $Tmp -UseBasicParsing

Write-Host "Installing to $AppDir ..." -ForegroundColor Cyan
if (Test-Path $AppDir) { Remove-Item -Recurse -Force $AppDir }
New-Item -ItemType Directory -Force -Path $AppDir | Out-Null
Expand-Archive -Path $Tmp -DestinationPath $AppDir -Force
Remove-Item $Tmp -Force

$Launcher = Join-Path $AppDir "praxis\praxis.exe"
if (-not (Test-Path $Launcher)) { throw "Install looks incomplete (no launcher at $Launcher)." }

# Put a `praxis` shim on PATH.
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
$Shim = Join-Path $BinDir "praxis.cmd"
"@echo off`r`n`"$Launcher`" %*" | Set-Content -Path $Shim -Encoding ASCII

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$BinDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$BinDir", "User")
    $env:Path = "$env:Path;$BinDir"
    $PathAdded = $true
}

Write-Host ""
Write-Host "Praxis installed." -ForegroundColor Green
& $Launcher --version

$Config = Join-Path $env:USERPROFILE ".praxis\config.toml"
if (-not (Test-Path $Config)) {
    Write-Host "`nSetting a safe default policy (balanced)..." -ForegroundColor Cyan
    & $Launcher init --strictness balanced --yes | Out-Null
}

Write-Host "`nConnecting Praxis to your AI tools..." -ForegroundColor Cyan
& $Launcher install

Write-Host ""
Write-Host "All set. Restart your AI tool (Claude, Cursor, ChatGPT/Codex...) to" -ForegroundColor Green
Write-Host "activate Praxis. Change strictness anytime:  praxis init" -ForegroundColor Green
if ($PathAdded) {
    Write-Host "`nOpen a NEW terminal so the 'praxis' command works." -ForegroundColor Yellow
}
