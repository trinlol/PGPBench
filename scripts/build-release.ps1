# Build reproducible release artifacts for PocketPGP.
#
# Produces in release\:
#   PocketPGP_<version>_x64-setup.exe   NSIS installer (per-user)
#   PocketPGP-<version>-win64-portable.zip  portable exe
#
# Usage: powershell -File scripts\build-release.ps1

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root

Write-Host "== building installer + portable exe ==" -ForegroundColor Cyan
npx tauri build 2>&1 | Select-String -Pattern "Finished|Built application|^error|bundling" | Write-Host
if ($LASTEXITCODE -ne 0) { Write-Host "build failed" -ForegroundColor Red; exit 1 }

$version = (Get-Content package.json -Raw | ConvertFrom-Json).version
$setup = Get-ChildItem "src-tauri\target\release\bundle\nsis\*-setup.exe" | Select-Object -First 1
$portable = "src-tauri\target\release\pocketpgp.exe"

if (-not $setup) { Write-Host "installer not found" -ForegroundColor Red; exit 1 }
if (-not (Test-Path $portable)) { Write-Host "portable exe not found" -ForegroundColor Red; exit 1 }

New-Item -ItemType Directory -Force -Path "release" | Out-Null
Copy-Item $setup.FullName "release\" -Force
$zip = "release\PocketPGP-$version-win64-portable.zip"
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path $portable -DestinationPath $zip -Force

Write-Host ""
Get-ChildItem "release" | Select-Object Name, @{N="SizeMB";E={[math]::Round($_.Length/1MB,2)}} | Format-Table -AutoSize | Out-String
Write-Host "Artifacts ready under release\ - attach both to the GitHub release." -ForegroundColor Green
Pop-Location
