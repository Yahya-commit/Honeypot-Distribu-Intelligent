# Ouvre Discover avec la bonne vue et une large plage de temps
$dataViewId = "b1392901-b701-4237-a1d6-67e942d67937"
$url = "http://localhost:5601/app/discover#/?_g=(filters:!(),refreshInterval:(pause:!t,value:60000),time:(from:now-30d,to:now))&_a=(columns:!(eventid,src_ip,username,password,message),filters:!(),index:$dataViewId,interval:auto,query:(language:kuery,query:''),sort:!(!('@timestamp',desc)))"
Write-Host "Ouverture Discover (30 derniers jours)..." -ForegroundColor Cyan
Start-Process $url
