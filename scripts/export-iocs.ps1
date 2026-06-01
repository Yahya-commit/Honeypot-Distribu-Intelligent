# Exporte la base IOC depuis le volume Docker
$outDir = Join-Path $PSScriptRoot "..\exports"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

docker cp hp-ioc-collector:/data/ioc/iocs.json "$outDir\iocs.json"
docker cp hp-ioc-collector:/data/ioc/iocs.csv "$outDir\iocs.csv"
docker cp hp-ioc-collector:/data/ioc/stats.json "$outDir\stats.json"

Write-Host "Export terminé : $outDir" -ForegroundColor Green
