# Full removal of amnezia-web-panel: container, image and (on request) the directory.
# Amnezia containers and data are NOT touched.
$ErrorActionPreference = "SilentlyContinue"
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $dir

if (Get-Command docker -ErrorAction SilentlyContinue) {
    docker compose down --remove-orphans
    if ($LASTEXITCODE -eq 0) { Write-Host "Container stopped and removed." } else { Write-Host "Container not found (ok)." }
    docker rmi amnezia-web-panel:latest | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Host "Image removed." } else { Write-Host "Image not found (ok)." }
} else {
    Write-Host "Docker not found - skipping container and image removal."
}

$ans = Read-Host "Remove .env (password hash, server address)? [y/N]"
if ($ans -match '^[Yy]') { Remove-Item -Force .env; Write-Host ".env removed." } else { Write-Host ".env kept." }

$ans = Read-Host "Remove the project directory $dir completely? [y/N]"
if ($ans -match '^[Yy]') {
    Set-Location ..
    Remove-Item -Recurse -Force $dir
    Write-Host "Directory $dir removed."
} else {
    Write-Host "Files kept in $dir"
}

Write-Host "Done. Amnezia services were not affected."
