# Back up the FreeLLMAPI data volume, then switch to the given version (Windows).
# Usage: .\upgrade.ps1 [-Version v0.16.26]
param([string]$Version = "v0.16.26")
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path .env)) {
  $bytes = New-Object byte[] 32
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  $key = -join ($bytes | ForEach-Object { $_.ToString("x2") })
  (Get-Content .env.example) -replace '^ENCRYPTION_KEY=.*', "ENCRYPTION_KEY=$key" | Set-Content .env
  Write-Host "Created .env with a new ENCRYPTION_KEY. Keep this file safe."
}

$existing = docker compose ps -aq freellmapi
if ($existing) {
  $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
  Write-Host "Stopping and backing up data to backups\$stamp ..."
  docker compose stop freellmapi
  New-Item -ItemType Directory -Force "backups\$stamp" | Out-Null
  docker compose cp freellmapi:/app/server/data "backups\$stamp\"
  if ($LASTEXITCODE -ne 0) { throw "Backup failed; not upgrading." }
  Copy-Item .env "backups\$stamp\.env"
}

$envLines = Get-Content .env
if ($envLines -match '^FREELLMAPI_VERSION=') {
  $envLines -replace '^FREELLMAPI_VERSION=.*', "FREELLMAPI_VERSION=$Version" | Set-Content .env
} else {
  Add-Content .env "FREELLMAPI_VERSION=$Version"
}

docker compose pull
docker compose up -d
Write-Host "Waiting for health check ..."
for ($i = 0; $i -lt 30; $i++) {
  $id = docker compose ps -q freellmapi
  $status = docker inspect -f '{{.State.Health.Status}}' $id 2>$null
  if ($status -eq "healthy") { Write-Host "FreeLLMAPI $Version is up: http://localhost:3001"; exit 0 }
  Start-Sleep 3
}
Write-Error "Not healthy yet. Check: docker compose logs -f freellmapi"
