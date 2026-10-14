[CmdletBinding()]
param(
    [string]$ApiUrl = "http://localhost:8000",
    [Parameter(Mandatory = $true)][string]$AccessToken,
    [string]$OutputPath = "./audit-export.json"
)

$headers = @{ Authorization = "Bearer $AccessToken" }
$events = Invoke-RestMethod -Method Get -Uri "$ApiUrl/api/audit" -Headers $headers
$events | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding utf8NoBOM
$resolved = Resolve-Path $OutputPath
Write-Host "Exported $($events.Count) tenant-scoped audit records to $resolved"
