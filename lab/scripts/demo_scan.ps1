$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

$loginBody = @{
  username = "admin"
  password = "Admin@123456"
} | ConvertTo-Json

Invoke-RestMethod `
  -Method Post `
  -Uri "http://localhost:5000/api/auth/login" `
  -WebSession $session `
  -ContentType "application/json" `
  -Body $loginBody | Out-Null

$scanBody = Get-Content "$PSScriptRoot\..\data\payloads\hybrid_scan.json" -Raw

Invoke-RestMethod `
  -Method Post `
  -Uri "http://localhost:5000/api/scan" `
  -WebSession $session `
  -ContentType "application/json" `
  -Body $scanBody | ConvertTo-Json -Depth 8

