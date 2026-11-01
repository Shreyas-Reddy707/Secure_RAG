#!/usr/bin/env bash
# ==============================================================================
# SecureRAG — Linux / macOS Docker Teardown Script (stop.sh)
# ==============================================================================
set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}==========================================================${NC}"
echo -e "${CYAN}  Stopping SecureRAG Multi-Agent Architecture Services     ${NC}"
echo -e "${CYAN}==========================================================${NC}"

if docker compose version > /dev/null 2>&1; then
    docker compose down
else
    docker-compose down
fi

echo -e "${GREEN}All SecureRAG containers and networks stopped cleanly.${NC}"

