$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$env:PYTHONPATH = Join-Path $root "backend"
$backend = Join-Path $root "backend"
$ai = Join-Path $root "ai-service"

Push-Location $root
try {
    Write-Host "== Backend ==" -ForegroundColor Cyan
    python -m unittest discover -s $backend -p "test_*.py" -v
    Write-Host "== Microservicio IA ==" -ForegroundColor Cyan
    $env:PYTHONPATH = $ai
    python -m unittest discover -s $ai -p "test_*.py" -v
} finally {
    Pop-Location
}
