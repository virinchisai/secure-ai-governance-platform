[CmdletBinding()]
param([string]$ApiUrl = "http://localhost:8000")

$health = Invoke-RestMethod -Method Get -Uri "$ApiUrl/health"
$checks = @(
    [PSCustomObject]@{ Check = "API health"; Passed = ($health.status -eq "ok"); Detail = $health.status },
    [PSCustomObject]@{ Check = "Local-safe Graph provider"; Passed = ($health.graph -eq "local"); Detail = $health.graph },
    [PSCustomObject]@{ Check = "Local-safe AI provider"; Passed = ($health.ai -in @("mock", "ollama")); Detail = $health.ai }
)
$checks | Format-Table -AutoSize
if ($checks.Passed -contains $false) { exit 1 }
