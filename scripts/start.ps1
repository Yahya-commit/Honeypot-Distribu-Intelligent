# Démarrage de l'infrastructure honeypot
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot\..

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Fichier .env créé depuis .env.example"
}

Write-Host "Construction et démarrage des conteneurs…" -ForegroundColor Cyan
docker compose pull
docker compose up -d --build

Write-Host "`n=== Services ===" -ForegroundColor Green
Write-Host "Cowrie SSH    : ssh -p 2222 root@127.0.0.1"
Write-Host "Threat Dashboard : http://localhost:8080"
Write-Host "Kibana        : http://localhost:5601"
Write-Host "`nAttendre ~2 min pour Elasticsearch, puis créer la Data View 'honeypot-attacks-*' dans Kibana."
