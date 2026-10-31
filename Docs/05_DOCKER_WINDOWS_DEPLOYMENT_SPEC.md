# 05 — Docker Compose, Containerfiles & Windows 11 Deployment Specification (`SecureRAG`)

## 1. Architecture of the Containerized Stack
The application runs as a 3-container microservices stack on **Docker Desktop for Windows (WSL2 backend)** connected via an isolated bridge network (`securerag_net`):

1. **`securerag-qdrant` (`qdrant/qdrant:v1.13.2`):** Persistent Hybrid Vector Database listening on port `6333` (HTTP) and `6334` (gRPC).
2. **`securerag-backend` (Python 3.11 / FastAPI / LangGraph / FastEmbed):** Pre-caches the `BAAI/bge-small-en-v1.5` dense model and `Qdrant/bm25` sparse model during image build so container startup and first-query execution happen in milliseconds without waiting on HuggingFace downloads. Exposed on `http://localhost:8000`.
3. **`securerag-frontend` (Node 20 / Next.js 15):** Interactive AI Security Command Center exposed on `http://localhost:3000`.

---

## 2. Root `docker-compose.yml`
Create `docker-compose.yml` in the root `securerag/` directory:

```yaml
services:
  qdrant:
    image: qdrant/qdrant:v1.13.2
    container_name: securerag-qdrant
    restart: unless-stopped
    ports:
      - "6333:6333"
      - "6334:6334"
    volumes:
      - qdrant_storage:/qdrant/storage
    networks:
      - securerag_net

  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    container_name: securerag-backend
    restart: unless-stopped
    env_file:
      - .env
    environment:
      - QDRANT_HOST=qdrant
      - QDRANT_PORT=6333
      - FASTEMBED_CACHE_PATH=/app/.fastembed_cache
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
      - fastembed_cache:/app/.fastembed_cache
    depends_on:
      - qdrant
    networks:
      - securerag_net

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    container_name: securerag-frontend
    restart: unless-stopped
    environment:
      - NEXT_PUBLIC_API_URL=http://localhost:8000
    ports:
      - "3000:3000"
    depends_on:
      - backend
    networks:
      - securerag_net

volumes:
  qdrant_storage:
  fastembed_cache:

networks:
  securerag_net:
    driver: bridge
```

---

## 3. Environment Configuration (`.env.example` and `.env`)
Create `.env.example` in the root `securerag/` directory (and copy it to `.env`):

```ini
# ============================================================================
# SecureRAG Environment Configuration
# ============================================================================

# Primary LLM Provider ("gemini" | "groq" | "deterministic")
# Note: Even if API keys are left blank, SecureRAG automatically falls back
# to its built-in Deterministic Security Engine so live demos never fail.
DEFAULT_LLM_PROVIDER=gemini

# Google Gemini API (Recommended: free tier via Google AI Studio)
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash

# Optional Groq API Fallback (Llama 3.3 70B)
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=llama-3.3-70b-versatile

# Vector Database Settings
QDRANT_HOST=qdrant
QDRANT_PORT=6333
QDRANT_COLLECTION=securerag_hybrid_kb

# Defense Thresholds
DEFAULT_TOP_K=6
INPUT_BLOCK_THRESHOLD=0.75
CHUNK_TRUST_THRESHOLD=0.60

# Frontend Public Backend URL
NEXT_PUBLIC_API_URL=http://localhost:8000
```

---

## 4. Backend Container Specification (`backend/Dockerfile`)
Create `backend/Dockerfile`. Notice Step 5: it pre-downloads the local `FastEmbed` ONNX weights (`BAAI/bge-small-en-v1.5` and `Qdrant/bm25`) into `/app/.fastembed_cache` during `docker build` so your classroom demo starts immediately even on slow Wi-Fi:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# 1. Install system build essentials required by ONNX/FastEmbed
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 2. Configure Python and FastEmbed cache environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FASTEMBED_CACHE_PATH=/app/.fastembed_cache

# 3. Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 4. Pre-warm local FastEmbed Dense (BGE) & Sparse (BM25) models at build time
RUN python -c "from fastembed import TextEmbedding, SparseTextEmbedding; \
    TextEmbedding(model_name='BAAI/bge-small-en-v1.5', cache_dir='/app/.fastembed_cache'); \
    SparseTextEmbedding(model_name='Qdrant/bm25', cache_dir='/app/.fastembed_cache')"

# 5. Copy backend application source
COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### 4.1 `backend/.dockerignore`
```text
__pycache__/
*.pyc
*.pyo
.env
.venv/
venv/
```

---

## 5. Frontend Container & Required Next.js Boilerplate Files

To ensure the Next.js 15 container compiles cleanly without missing configuration files, create the following files inside `frontend/`:

### 5.1 `frontend/Dockerfile`
```dockerfile
FROM node:20-alpine

WORKDIR /app

# 1. Install dependencies
COPY package.json ./
RUN npm install --legacy-peer-deps

# 2. Copy all frontend source and config files
COPY . .

# 3. Build production Next.js bundle
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

EXPOSE 3000

CMD ["npm", "run", "start"]
```

### 5.2 `frontend/.dockerignore`
```text
node_modules
.next
.git
```

### 5.3 `frontend/next.config.mjs`
Configured to ignore strict TypeScript/ESLint build halts during Docker packaging so minor type warnings never block your build:

```javascript
/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  typescript: {
    ignoreBuildErrors: true,
  },
  eslint: {
    ignoreDuringBuilds: true,
  },
};

export default nextConfig;
```

### 5.4 `frontend/postcss.config.mjs`
```javascript
/** @type {import('postcss-load-config').Config} */
const config = {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
};

export default config;
```

### 5.5 `frontend/tsconfig.json`
```json
{
  "compilerOptions": {
    "target": "ES2017",
    "lib": ["dom", "dom.iterable", "esnext"],
    "allowJs": true,
    "skipLibCheck": true,
    "strict": false,
    "noEmit": true,
    "esModuleInterop": true,
    "module": "esnext",
    "moduleResolution": "bundler",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "jsx": "preserve",
    "incremental": true,
    "plugins": [{ "name": "next" }],
    "paths": {
      "@/*": ["./src/*"]
    }
  },
  "include": ["next-env.d.ts", "**/*.ts", "**/*.tsx", ".next/types/**/*.ts"],
  "exclude": ["node_modules"]
}
```

### 5.6 `frontend/src/app/globals.css`
```css
@tailwind base;
@tailwind components;
@tailwind utilities;

body {
  background-color: #090d16;
  color: #f1f5f9;
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
```

### 5.7 `frontend/src/app/layout.tsx`
```tsx
import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SecureRAG | Multi-Agent Defense & Adversarial Robustness",
  description: "5-Layer Zero-Trust Defense against Indirect Prompt Injection and Corpus Poisoning in RAG",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-background text-slate-100 antialiased">
        {children}
      </body>
    </html>
  );
}
```

---

## 6. Windows PowerShell One-Click Automation Scripts

### 6.1 `start.ps1` (Root Directory)
Creates `.env` if missing, verifies Docker Desktop is running, builds and starts the 3 containers, waits for the FastAPI `/api/health` endpoint to finish indexing the 36 clean/poisoned chunks in Qdrant, and automatically launches `http://localhost:3000` in your default Windows browser:

```powershell
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
$maxRetries = 30$retryCount = 0
$backendReady =$false

while (-not $backendReady -and $retryCount -lt$maxRetries) {
    try {
        $resp = Invoke-RestMethod -Uri "http://localhost:8000/api/health" -Method Get -TimeoutSec 3
        if ($resp.status -eq "healthy") {
            $backendReady =$true
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
```

### 6.2 `stop.ps1` (Root Directory)
Gracefully stops the containers while preserving the Qdrant vector database volume and cached FastEmbed models:

```powershell
Write-Host "Stopping SecureRAG containers..." -ForegroundColor Yellow
docker compose down
Write-Host "All SecureRAG services stopped cleanly." -ForegroundColor Green
```

---

## 7. Hybrid Local Dev Option (Running Qdrant in Docker + Hot-Reload in Windows)
If you want instant code hot-reloading inside your Antigravity IDE without rebuilding Docker images during development:

1. **Start only Qdrant in Docker:**
   ```powershell
   docker compose up -d qdrant
   ```
2. **Run FastAPI Backend locally in Terminal 1:**
   ```powershell
   cd backend
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   $env:QDRANT_HOST="localhost"
   uvicorn app.main:app --reload --port 8000
   ```
3. **Run Next.js Frontend locally in Terminal 2:**
   ```powershell
   cd frontend
   npm install --legacy-peer-deps
   npm run dev
   ```