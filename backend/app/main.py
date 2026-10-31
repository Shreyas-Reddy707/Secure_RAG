import logging
import time
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import Dict, List

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.core.security import verify_admin_access
from app.evaluation.benchmark_runner import get_cached_benchmark, run_full_benchmark
from app.models.schemas import (
    CompareQueryRequest,
    CompareQueryResponse,
    CorpusStatsResponse,
    InjectPoisonRequest,
    SecureRAGResult,
)
from app.pipeline.baseline_rag import run_baseline_rag
from app.pipeline.graph import execute_securerag_pipeline
from app.services.seed_corpus import ensure_corpus_seeded, reset_corpus_to_default
from app.services.vector_store import vector_store

logger = logging.getLogger("securerag")

# Rate limiting sliding-window parameters: 120 requests/minute per client IP
RATE_LIMIT_MAX_REQUESTS = 120
RATE_LIMIT_WINDOW_SECONDS = 60
_client_request_log: Dict[str, List[float]] = defaultdict(list)

@asynccontextmanager
async def lifespan(app: FastAPI):
    ensure_corpus_seeded()
    yield

app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    lifespan=lifespan,
    debug=settings.DEBUG,
)

# 1. Strict Security Headers Middleware
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response

# 2. In-Memory Per-IP Rate Limiting Middleware (120 req/min)
@app.middleware("http")
async def rate_limiting_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "127.0.0.1"
    now = time.time()
    
    # Prune timestamps older than window
    timestamps = _client_request_log[client_ip]
    while timestamps and timestamps[0] < now - RATE_LIMIT_WINDOW_SECONDS:
        timestamps.pop(0)
        
    if len(timestamps) >= RATE_LIMIT_MAX_REQUESTS:
        logger.warning(f"Rate limit exceeded for client IP: {client_ip}")
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many requests. Rate limit of 120 req/min exceeded."},
            headers={"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)},
        )
        
    timestamps.append(now)
    return await call_next(request)

# 3. Explicit CORS Settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# 4. Global Exception Handler (Prevents Stack Trace Leakage)
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(
        f"Unhandled server error on {request.method} {request.url.path}: {str(exc)}",
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred. Please contact system security."},
    )

@app.get("/api/health")
def health_check():
    chunks = vector_store.list_all_chunks()
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "indexed_chunks": len(chunks),
        "llm_provider": settings.DEFAULT_LLM_PROVIDER,
    }

@app.post("/api/chat/compare", response_model=CompareQueryResponse)
@app.post("/api/v1/query/compare", response_model=CompareQueryResponse)
def compare_rag_pipelines(req: CompareQueryRequest):
    state = execute_securerag_pipeline(
        query=req.query,
        top_k=req.top_k,
        llm_provider=req.llm_provider,
    )
    # If Layer 1 or 2 blocked the query before retrieval, fetch top_k chunks for Baseline RAG to demonstrate vulnerability
    baseline_candidates = (
        state["candidate_chunks"]
        if state["candidate_chunks"]
        else vector_store.hybrid_search(req.query, top_k=req.top_k)
    )
    baseline_res = run_baseline_rag(
        query=req.query,
        candidate_chunks=baseline_candidates,
        quarantined_chunks=state["quarantined_chunks"],
        input_blocked_by_securerag=state["input_blocked"],
        llm_provider=req.llm_provider,
        is_casual_query=state.get("is_casual_query", False),
        stopped_at_layer=state.get("stopped_at_layer"),
    )

    securerag_res = SecureRAGResult(
        answer=state["final_answer"],
        faithfulness_score=state["faithfulness_score"],
        output_passed_audit=state["output_passed_audit"],
        audit_notes=state["audit_notes"],
        spotlight_nonce=state["spotlight_nonce"],
        cited_chunk_ids=state["cited_chunk_ids"],
        total_latency_ms=state["total_latency_ms"],
        input_blocked=state["input_blocked"],
        stopped_at_layer=state.get("stopped_at_layer"),
        harm_prevention_explanation=state.get("harm_prevention_explanation"),
        telemetry=state["telemetry"],
        candidate_chunks=state["candidate_chunks"],
        verified_chunks=state["verified_chunks"],
        quarantined_chunks=state["quarantined_chunks"],
    )

    return CompareQueryResponse(
        query=req.query,
        sanitized_query=state["sanitized_query"],
        baseline=baseline_res,
        securerag=securerag_res,
    )

@app.get("/api/corpus/stats", response_model=CorpusStatsResponse)
def get_corpus_stats():
    chunks = vector_store.list_all_chunks()
    poisoned = [c for c in chunks if c.get("ground_truth_is_poisoned")]
    clean = [c for c in chunks if not c.get("ground_truth_is_poisoned")]
    return CorpusStatsResponse(
        total_chunks=len(chunks),
        clean_chunks=len(clean),
        poisoned_chunks=len(poisoned),
        collection_name=settings.QDRANT_COLLECTION,
        chunks=chunks,
    )

@app.post("/api/corpus/inject", dependencies=[Depends(verify_admin_access)])
def inject_custom_poison(req: InjectPoisonRequest):
    chunk_id = f"CHUNK_LIVE_{uuid.uuid4().hex[:6].upper()}"
    record = {
        "chunk_id": chunk_id,
        "doc_id": f"DOC_ADV_{uuid.uuid4().hex[:4].upper()}",
        "doc_title": req.doc_title,
        "text": req.text,
        "attack_category": req.attack_category,
        "ground_truth_is_poisoned": True,
    }
    vector_store.upsert_chunks([record])
    return {"status": "injected", "chunk": record}

@app.post("/api/corpus/reset", dependencies=[Depends(verify_admin_access)])
def reset_corpus():
    count = reset_corpus_to_default()
    return {"status": "reset", "indexed_chunks": count}

@app.get("/api/eval/latest")
def get_latest_evaluation():
    return get_cached_benchmark()

@app.post("/api/eval/run", dependencies=[Depends(verify_admin_access)])
def trigger_evaluation_run():
    return run_full_benchmark()
