# ============================================================================
# SecureRAG — Windows 11 One-Click Docker Launcher (start.ps1)
# ============================================================================
$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  SecureRAG: Multi-Agent Defense & Red-Team Benchmark     " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Ensure .env file exists
if (-not (Test-Path ".env")) {
    Write-Host "[1/4] Creating .env from .env.example..." -ForegroundColor Yellow
    Copy-Item ".env.example" ".env"
    Write-Host "      Created .env. Add your GEMINI_API_KEY in .env for live LLM mode (Deterministic mode works immediately)." -ForegroundColor Gray
} else {
    Write-Host "[1/4] Found existing .env configuration." -ForegroundColor Green
}

# 2. Check if Docker Desktop daemon is responsive
Write-Host "[2/4] Checking Docker Desktop (WSL2 engine)..." -ForegroundColor Yellow
docker info > $null 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Docker Desktop is not running. Please start Docker Desktop on Windows and re-run ./start.ps1" -ForegroundColor Red
    exit 1
}
Write-Host "      Docker Desktop is active." -ForegroundColor Green

# 3. Build and start containers
Write-Host "[3/4] Building and launching Qdrant, FastAPI Backend, and Next.js Frontend..." -ForegroundColor Yellow
docker compose up --build -d

# 4. Poll Backend Health & Corpus Seeding
Write-Host "[4/4] Waiting for FastAPI Backend & Qdrant Hybrid Corpus Indexing..." -ForegroundColor Yellow
$maxRetries = 30
$retryCount = 0
$backendReady = $false

while (-not $backendReady -and $retryCount -lt $maxRetries) {
    try {
        $resp = Invoke-RestMethod -Uri "http://localhost:8000/api/health" -Method Get -TimeoutSec 3
        if ($resp.status -eq "healthy") {
            $backendReady = $true
            Write-Host "      Backend Healthy! Indexed Chunks in Qdrant: $($resp.indexed_chunks)" -ForegroundColor Green
        }
    } catch {
        Start-Sleep -Seconds 2
        $retryCount++
        Write-Host "      Waiting for backend initialization... ($retryCount/$maxRetries)" -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "  SecureRAG Command Center is LIVE!                       " -ForegroundColor Green
Write-Host "  Frontend UI : http://localhost:3000                     " -ForegroundColor White
Write-Host "  Swagger API : http://localhost:8000/docs                " -ForegroundColor White
Write-Host "  Qdrant UI   : http://localhost:6333/dashboard           " -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Green

Start-Process "http://localhost:3000"

