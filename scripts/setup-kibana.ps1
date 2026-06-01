# Configure la Data View Kibana (une seule fois)
$ErrorActionPreference = "Stop"

$kibanaUrl = "http://localhost:5601"
$jsonPath = Join-Path $PSScriptRoot "kibana-dataview.json"

Write-Host "Verification Kibana..." -ForegroundColor Cyan
try {
    $null = Invoke-WebRequest -Uri $kibanaUrl -UseBasicParsing -TimeoutSec 10
} catch {
    Write-Host "Kibana inaccessible. Lancez: docker compose up -d" -ForegroundColor Red
    exit 1
}

$existing = curl.exe -s -H "kbn-xsrf: true" "$kibanaUrl/api/data_views" | ConvertFrom-Json
$found = $existing.data_view | Where-Object { $_.title -eq "honeypot-attacks-*" }

if ($found) {
    Write-Host "Data View deja presente: $($found.name)" -ForegroundColor Green
    Write-Host "Ouvrez Discover: $kibanaUrl/app/discover"
    exit 0
}

Write-Host "Creation de la Data View..." -ForegroundColor Cyan
$result = curl.exe -s -X POST -H "kbn-xsrf: true" -H "Content-Type: application/json" `
    -d "@$jsonPath" "$kibanaUrl/api/data_views/data_view"

if ($result -match "Duplicate") {
    Write-Host "Data View deja creee." -ForegroundColor Green
} elseif ($result -match '"id"') {
    Write-Host "Data View creee avec succes." -ForegroundColor Green
} else {
    Write-Host "Reponse: $result" -ForegroundColor Yellow
}

Write-Host "`nEtape suivante:" -ForegroundColor Cyan
Write-Host "1. Ouvrir $kibanaUrl/app/discover"
Write-Host "2. Choisir la vue: Honeypot Attacks"
Write-Host "3. Periode: Last 24 hours"
