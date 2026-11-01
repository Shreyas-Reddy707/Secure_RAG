# ============================================================================
# SecureRAG — Windows 11 Docker Teardown Script (stop.ps1)
# ============================================================================
$ErrorActionPreference = "Continue"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Stopping SecureRAG Multi-Agent Architecture Services     " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

docker compose down

if ($LASTEXITCODE -eq 0) {
    Write-Host "All SecureRAG containers and networks stopped cleanly." -ForegroundColor Green
} else {
    Write-Host "Attempting fallback with legacy docker-compose..." -ForegroundColor Yellow
    docker-compose down
}

Write-Host "Teardown complete." -ForegroundColor Gray
