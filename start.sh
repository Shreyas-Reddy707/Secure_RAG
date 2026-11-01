#!/usr/bin/env bash
# ==============================================================================
# SecureRAG — Linux / macOS One-Click Docker Launcher (start.sh)
# ==============================================================================
set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}==========================================================${NC}"
echo -e "${CYAN}  SecureRAG: Multi-Agent Defense & Red-Team Benchmark     ${NC}"
echo -e "${CYAN}==========================================================${NC}"

# 1. Ensure .env file exists
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}[1/4] Creating .env from .env.example...${NC}"
    cp .env.example .env
    echo -e "      Created .env. Configure GEMINI_API_KEY for live frontier LLMs (offline deterministic mode works automatically)."
else
    echo -e "${GREEN}[1/4] Found existing .env configuration.${NC}"
fi

# 2. Check if Docker daemon is running
echo -e "${YELLOW}[2/4] Verifying Docker daemon...${NC}"
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}ERROR: Docker is not running or accessible. Please start Docker and re-run ./start.sh${NC}"
    exit 1
fi
echo -e "${GREEN}      Docker daemon is active.${NC}"

# 3. Build and start containers
echo -e "${YELLOW}[3/4] Building and launching Qdrant, FastAPI Backend, and Next.js Frontend...${NC}"
if docker compose version > /dev/null 2>&1; then
    docker compose up --build -d
else
    docker-compose up --build -d
fi

# 4. Poll Backend Health & Corpus Seeding
echo -e "${YELLOW}[4/4] Waiting for FastAPI Backend & Qdrant Hybrid Corpus Indexing...${NC}"
MAX_RETRIES=30
RETRY_COUNT=0
BACKEND_READY=false

while [ "$BACKEND_READY" = false ] && [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -s -f http://localhost:8000/api/health > /dev/null 2>&1; then
        BACKEND_READY=true
        HEALTH_DATA=$(curl -s http://localhost:8000/api/health)
        echo -e "${GREEN}      Backend Healthy! Telemetry: ${HEALTH_DATA}${NC}"
    else
        sleep 2
        RETRY_COUNT=$((RETRY_COUNT + 1))
        echo -e "      Waiting for backend initialization... ($RETRY_COUNT/$MAX_RETRIES)"
    fi
done

echo ""
echo -e "${GREEN}==========================================================${NC}"
echo -e "${GREEN}  SecureRAG Command Center is LIVE!                       ${NC}"
echo -e "  Frontend UI : ${CYAN}http://localhost:3000${NC}"
echo -e "  Swagger API : ${CYAN}http://localhost:8000/docs${NC}"
echo -e "  Qdrant UI   : ${CYAN}http://localhost:6333/dashboard${NC}"
echo -e "${GREEN}==========================================================${NC}"

# Open browser if supported (macOS open or Linux xdg-open)
if command -v open > /dev/null 2>&1; then
    open "http://localhost:3000"
elif command -v xdg-open > /dev/null 2>&1; then
    xdg-open "http://localhost:3000" > /dev/null 2>&1 || true
fi

