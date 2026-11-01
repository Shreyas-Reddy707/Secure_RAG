# SecureRAG: System Requirements & Technical Specifications

This document defines the system, hardware, runtime, dependency, and network requirements for deploying and evaluating **SecureRAG** across local, containerized, and enterprise environments.

---

## 1. Operating System Compatibility

| Operating System | Supported Versions | Notes / Requirements |
| :--- | :--- | :--- |
| **Microsoft Windows** | Windows 10 / 11 (64-bit, Pro, Enterprise, or Home) | WSL2 backend enabled; Docker Desktop with WSL2 integration. `start.ps1` provided. |
| **Linux** | Ubuntu 22.04 LTS+, Debian 12+, RHEL/CentOS 9+, Fedora 39+, Arch Linux | Native Docker CE & Docker Compose v2+. `start.sh` provided. |
| **macOS** | macOS Ventura (13.x), Sonoma (14.x), Sequoia (15.x) | Native Apple Silicon (M1/M2/M3/M4) & Intel x86_64; Docker Desktop for Mac or OrbStack. |

---

## 2. Hardware Resource Specifications

| Component | Minimum Specification | Recommended Specification |
| :--- | :--- | :--- |
| **Processor (CPU)** | 4 Cores (x86_64 or ARM64) | 8 Cores (Modern Multi-threaded Architecture) |
| **System Memory (RAM)** | 8 GB RAM | 16 GB+ RAM |
| **Disk Space** | 10 GB free SSD storage | 25 GB+ high-speed NVMe SSD |
| **GPU / Acceleration** | Not required (Quantized embeddings run on CPU via FastEmbed) | Optional (CPU execution is optimized with ONNX Runtime) |
| **Network** | Broadband internet for Docker images and LLM APIs | Stable connection; outbound access to ports 443 (Gemini/Groq APIs) |

---

## 3. Runtime & Software Prerequisites

SecureRAG can run via **Docker Compose** (recommended, zero-install) or directly on bare-metal through **Local Python & Node.js runtimes**.

### Option A: Containerized Deployment (Recommended)
- **Docker Engine**: Version `24.0.0` or higher
- **Docker Compose**: Version `v2.20.0` or higher (`docker compose` command support)

### Option B: Bare-Metal / Native Development
If running outside of Docker:
- **Python**: Version `3.11.x` or `3.12.x` (64-bit)
- **Node.js**: Version `18.18.0`+ or `20.x` LTS
- **Package Managers**: `pip` (Python) and `npm` v9+ or `pnpm`
- **Qdrant Vector Database**: Standalone binary or local Docker instance running on port 6333

---

## 4. API Keys & LLM Provider Configuration

SecureRAG features a **Dynamic Self-Healing Multi-Provider AI Architecture**. It supports live frontier models while preserving full offline capabilities through deterministic security fallback.

| Provider | Environment Variable | Default Model | Fallback Models | Acquisition URL |
| :--- | :--- | :--- | :--- | :--- |
| **Google Gemini** | `GEMINI_API_KEY` | `gemini-3.8-flash` | `gemini-3.5-flash-lite`, `gemini-1.5-flash`, `gemini-pro` | [Google AI Studio](https://aistudio.google.com/) |
| **Groq Cloud** | `GROQ_API_KEY` | `openai/gpt-oss-120b` | `openai/gpt-oss-20b`, `qwen/qwen3.8-27b`, `llama-3.3-70b-versatile`, `llama-3.1-8b-instant` | [Groq Console](https://console.groq.com/) |
| **Deterministic Mode** | *None required* | `deterministic` | Built-in offline semantic rule engine | Zero external API calls required (runs 100% offline) |

> [!NOTE]
> Even if both `GEMINI_API_KEY` and `GROQ_API_KEY` are left blank, SecureRAG automatically falls back to its deterministic engine. Evaluators, students, and offline demonstrations can run full adversarial evaluations without an active API key or internet connection.

---

## 5. Software Dependencies Specification

### 5.1 Python Backend Dependencies (`backend/requirements.txt`)

| Package | Pinned Version | Layer / Functional Purpose |
| :--- | :--- | :--- |
| `fastapi` | `0.115.6` | High-performance asynchronous REST API framework |
| `uvicorn[standard]` | `0.34.0` | Production ASGI web server with event loop optimization |
| `pydantic` | `2.10.4` | Strict data schema validation and serialization |
| `pydantic-settings` | `2.7.0` | Hierarchical environment configuration loading |
| `python-dotenv` | `1.0.1` | Dynamic multi-source `.env` file parser |
| `langgraph` | `0.2.60` | Multi-agent DAG orchestration and conditional state routing |
| `langchain-core` | `0.3.28` | Agent state structures and standard message abstractions |
| `google-genai` | `0.8.0` | Official Google Gemini SDK with dynamic model fallback |
| `groq` | `0.15.0` | High-throughput ultra-low-latency Groq inference client |
| `qdrant-client[fastembed]` | `>=1.14.2` | Vector store client with built-in FastEmbed pipeline |
| `fastembed` | `>=0.5.1` | Local ONNX-optimized CPU embedding computation |
| `httpx` | `0.28.1` | Non-blocking HTTP client for model probing and auditing |
| `numpy` | `>=1.26.4` | High-dimensional similarity vector calculations |

### 5.2 Next.js Frontend Dependencies (`frontend/package.json`)

| Package | Version | Architectural Role |
| :--- | :--- | :--- |
| `next` | `15.1.0` | React framework with App Router, SSR, and zero-config bundling |
| `react` & `react-dom` | `^19.0.0` | Core UI component lifecycle and DOM rendering |
| `lucide-react` | `^0.469.0` | Security, defense layer, and audit telemetry iconography |
| `recharts` | `^2.15.0` | Real-time defense metrics, latency graphs, and radar charts |
| `tailwindcss` | `^3.4.17` | Utility-first cyber-defense themed styling engine |
| `clsx` & `tailwind-merge` | `^2.1.1` / `^2.6.0` | Dynamic CSS utility class synthesis |
| `typescript` | `^5.7.2` | Strict static typing across all dashboard tabs |

---

## 6. Network Port Architecture & Firewall Rules

The system orchestrates three services communicating over Docker's internal virtual bridge network (`securerag-net`) while binding the following host ports:

```
[Browser / Evaluator]
        │
        ├─── Port 3000 ────► Next.js Dashboard UI (SSR & Client State)
        │
        ├─── Port 8000 ────► FastAPI Backend & Swagger OpenAPI (/docs)
        │                          │
        │                          ▼ (Internal securerag-net:6333)
        └─── Port 6333 ────► Qdrant Vector Engine & Web Dashboard (/dashboard)
```

| Port | Protocol | Service | Host Binding | Purpose |
| :---: | :---: | :--- | :---: | :--- |
| **3000** | HTTP | Next.js Frontend | `0.0.0.0:3000` | Security operations dashboard, red-team studio, live side-by-side comparison |
| **8000** | HTTP | FastAPI Backend | `0.0.0.0:8000` | REST API endpoints, LangGraph pipeline, Layer 1-5 telemetry, `/api/health`, `/docs` |
| **6333** | HTTP | Qdrant Vector DB | `0.0.0.0:6333` | Vector collection management, hybrid search endpoint, web management console |
| **6334** | gRPC | Qdrant Engine | Internal only | High-speed internal vector indexing channel |

---

## 7. Verification & Health Check Procedure

To verify all system requirements are satisfied on an active deployment:

```bash
# 1. Probe Backend Health & Indexed Corpus Count
curl -s http://localhost:8000/api/health

# Expected response:
# {"status":"healthy","qdrant_connected":true,"indexed_chunks":16,"default_provider":"gemini",...}

# 2. Probe Qdrant Vector Engine
curl -s http://localhost:6333/collections/securerag_hybrid_kb

# 3. Access Web Interfaces in Browser:
# Dashboard : http://localhost:3000
# API Docs  : http://localhost:8000/docs
# Qdrant UI : http://localhost:6333/dashboard
```

