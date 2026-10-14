[CmdletBinding()]
param([string]$GraphBaseUri = "https://graph.microsoft.com/v1.0")

$required = @("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET")
$missing = $required | Where-Object { -not [Environment]::GetEnvironmentVariable($_) }
if ($missing) { throw "Missing required environment variables: $($missing -join ', ')" }

$tenant = [Environment]::GetEnvironmentVariable("AZURE_TENANT_ID")
$body = @{
    client_id     = [Environment]::GetEnvironmentVariable("AZURE_CLIENT_ID")
    client_secret = [Environment]::GetEnvironmentVariable("AZURE_CLIENT_SECRET")
    scope         = "https://graph.microsoft.com/.default"
    grant_type    = "client_credentials"
}
$token = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -Body $body
$headers = @{ Authorization = "Bearer $($token.access_token)" }
$result = Invoke-RestMethod -Method Get -Uri "$GraphBaseUri/organization?`$select=id,displayName" -Headers $headers
$result.value | Select-Object id, displayName
