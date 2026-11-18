# Uso: .\knock.ps1 -HostName vpn.ejemplo.es -Ports 48211,9337,29004
param(
  [Parameter(Mandatory)][string]$HostName,
  [Parameter(Mandatory)][int[]]$Ports
)
foreach ($p in $Ports) {
  $c = New-Object System.Net.Sockets.TcpClient
  $null = $c.ConnectAsync($HostName, $p).Wait(800)
  $c.Dispose()
  Write-Host "knock ${HostName}:$p"
  Start-Sleep -Milliseconds 500
}
Write-Host "hecho: tienes la ventana configurada en knockTime"
