[CmdletBinding()]
param([string]$EnvFile = ".env")

$required = @("JWT_SECRET", "DATABASE_URL", "GRAPH_PROVIDER", "AI_PROVIDER")
$configured = @{}
if (Test-Path $EnvFile) {
    Get-Content $EnvFile | Where-Object { $_ -match '^[A-Z][A-Z0-9_]*=' } | ForEach-Object {
        $name = ($_ -split '=', 2)[0]
        $configured[$name] = $true
    }
}

$required | ForEach-Object {
    $present = [bool]([Environment]::GetEnvironmentVariable($_)) -or $configured.ContainsKey($_)
    [PSCustomObject]@{ Variable = $_; Configured = $present }
} | Format-Table -AutoSize

if ($configured.ContainsKey("AZURE_CLIENT_SECRET")) {
    Write-Warning "AZURE_CLIENT_SECRET is present in a file. Ensure the file is ignored and never commit it."
}
