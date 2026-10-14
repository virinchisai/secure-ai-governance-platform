[CmdletBinding()]
param(
    [string]$ApiUrl = "http://localhost:8000",
    [Parameter(Mandatory = $true)][string]$AccessToken,
    [string]$EventType
)

$headers = @{ Authorization = "Bearer $AccessToken" }
$events = Invoke-RestMethod -Method Get -Uri "$ApiUrl/api/audit" -Headers $headers
if ($EventType) { $events = $events | Where-Object event_type -eq $EventType }
$events | Select-Object timestamp, event_type, action, policy_decision, policy_id, result, risk_score, request_id | Format-Table -AutoSize
