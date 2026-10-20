param(
    [string]$DatabaseUrl = "postgresql+psycopg://soc_lite:soc_lite_dev_password@localhost:5432/soc_lite",
    [switch]$Reset
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$env:PYTHONPATH = Join-Path $root "backend"
$env:DATABASE_URL = $DatabaseUrl

$argsList = @("-m", "app.seed")
if ($Reset) { $argsList += "--reset" }
Push-Location $root
try {
    python @argsList
} finally {
    Pop-Location
}
