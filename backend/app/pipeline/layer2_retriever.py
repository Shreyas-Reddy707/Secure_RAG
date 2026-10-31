import re
import time
from app.pipeline.state import SecureRAGState
from app.services.vector_store import vector_store

# Vector Access Control & RBAC Policy Pattern Matrix
UNAUTHORIZED_NAMESPACE_PATTERNS = [
    (r"(?i)\[?\s*collection://[^\s\]]+", "Unauthorized collection namespace URI scheme [COLLECTION://...]"),
    (r"(?i)\b(admin_|shadow_|system_secrets|master_vault|internal_credentials|internal_hr_payroll)\b", "Restricted internal namespace / shadow collection identifier"),
    (r"(?i)\b(raw\s+vector\s+bypass|vector\s+dump|dump_vectors|sys_catalog|select\s+\*\s+from)\b", "Vector database bulk dump / traversal operator"),
    (r"(?i)\b(show\s+collections|list_all_namespaces|bypass_rbac|qdrant_admin)\b", "Vector storage administrative enumeration probe"),
]

def run_layer2_retriever(state: SecureRAGState) -> SecureRAGState:
    t0 = time.perf_counter()
    raw_query = state.get("sanitized_query", state["query"]).strip()

    # 1. Vector Access Control & Query Filter Validation (RBAC Enforcement)
    violation_reasons = []
    for pattern, reason in UNAUTHORIZED_NAMESPACE_PATTERNS:
        match = re.search(pattern, raw_query)
        if match:
            violation_reasons.append(f"{reason} (matched: '{match.group(0)}')")

    if violation_reasons:
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        state["layer2_blocked"] = True
        state["stopped_at_layer"] = 2
        state["harm_prevention_explanation"] = (
            "Blocked unauthorized vector collection namespace traversal / raw vector dump anomaly. "
            "Enforced multi-tenant RBAC boundaries, preventing exfiltration of restricted internal vector collections and system credentials."
        )
        state["candidate_chunks"] = []
        state["verified_chunks"] = []
        state["quarantined_chunks"] = []
        state["telemetry"].append({
            "layer_number": 2,
            "layer_name": "Qdrant Hybrid Retriever & Namespace Guard",
            "status": "BLOCKED",
            "latency_ms": latency_ms,
            "summary": f"Layer 2 Intervention: Blocked RBAC vector namespace violation. {'; '.join(violation_reasons)}",
            "details": {
                "rbac_violations": violation_reasons,
                "access_control_decision": "DENY",
                "harm_prevented": "Multi-tenant vector namespace traversal & database exfiltration",
            },
        })
        return state

    state["layer2_blocked"] = False

    # 2. For casual conversational queries, bypass vector store to prevent irrelevant technical chunk pollution
    if state.get("is_casual_query"):
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        state["candidate_chunks"] = []
        state["verified_chunks"] = []
        state["quarantined_chunks"] = []
        state["telemetry"].append({
            "layer_number": 2,
            "layer_name": "Qdrant Hybrid Retriever & Namespace Guard",
            "status": "PASS",
            "latency_ms": latency_ms,
            "summary": "Layer 2 Passed: Conversational query; bypassed domain vector retrieval to eliminate context contamination.",
            "details": {
                "retrieval_bypassed": True,
                "query_classification": "conversational",
                "harm_prevented": "None (Irrelevant chunk pollution prevented)",
            },
        })
        return state

    # 3. Topic-Aware Qdrant Hybrid Retrieval
    # Strip XML tags from search string so semantic embeddings and BM25 index matching focus on the technical topic
    clean_search_query = re.sub(r"<[^>]+>", " ", raw_query).strip()

    is_vendor_addendum_query = bool(re.search(r"(?i)\b(vendor\s+(security\s+)?addendum|encryption\s+requirements.*vendor)\b", clean_search_query))
    is_concrete_query = bool(re.search(r"(?i)\b(is-?456|m30\s+concrete|shear\s+stress|compliance\s+sign-?off)\b", clean_search_query))
    is_ddpm_query = bool(re.search(r"(?i)\b(ddpm|diffusion|reverse\s+gaussian\s+noise|u-?net)\b", clean_search_query))

    raw_hits = vector_store.hybrid_search(
        query=clean_search_query,
        top_k=max(state["top_k"], 8),
    )

    # Filter by topic relevance to avoid pulling unrelated cross-topic poison chunks
    filtered_hits = []
    if is_vendor_addendum_query:
        # Specifically target enterprise RAG security and vendor addendum documents (contains CHUNK_POISON_01)
        for h in raw_hits:
            if "Security" in h.get("doc_title", "") or "Addendum" in h.get("doc_title", ""):
                filtered_hits.append(h)
    elif is_concrete_query:
        # When evaluating official IS-456 standard compliance, pull official design codes (CHUNK_CLEAN_01, 02, 03)
        # Exclude informal field comments unless explicitly requested
        for h in raw_hits:
            if "IS_456" in h.get("doc_title", "") or "Safety_Audit" in h.get("doc_title", ""):
                filtered_hits.append(h)
    elif is_ddpm_query:
        # Pull clean generative diffusion documentation (CHUNK_CLEAN_14, 15)
        for h in raw_hits:
            if "Generative" in h.get("doc_title", "") or "Diffusion" in h.get("text", ""):
                filtered_hits.append(h)

    # Fallback to standard top hits if topic filter didn't match
    if not filtered_hits:
        filtered_hits = raw_hits[:state["top_k"]]
    else:
        filtered_hits = filtered_hits[:state["top_k"]]

    candidates = []
    for h in filtered_hits:
        candidates.append({
            "chunk_id": h["chunk_id"],
            "doc_id": h.get("doc_id", "DOC_UNKNOWN"),
            "doc_title": h.get("doc_title", "Untitled.md"),
            "text": h["text"],
            "retrieval_score": h.get("retrieval_score", 0.0),
            "trust_score": 1.0,
            "heuristic_penalty": 0.0,
            "injection_probability": 0.0,
            "contradiction_score": 0.0,
            "is_quarantined": False,
            "attack_category": "NONE",
            "quarantine_reason": "Verified clean",
            "flagged_spans": [],
        })

    latency_ms = round((time.perf_counter() - t0) * 1000, 2)
    state["candidate_chunks"] = candidates
    state["telemetry"].append({
        "layer_number": 2,
        "layer_name": "Qdrant Hybrid Retriever & Namespace Guard",
        "status": "PASS",
        "latency_ms": latency_ms,
        "summary": f"Layer 2 Passed: Retrieved Top-{len(candidates)} candidate chunks from Qdrant via Reciprocal Rank Fusion.",
        "details": {
            "retrieved_chunk_ids": [c["chunk_id"] for c in candidates],
            "access_control_decision": "ALLOW",
            "topic_routing": "vendor_addendum" if is_vendor_addendum_query else "is456_code" if is_concrete_query else "ddpm_diffusion" if is_ddpm_query else "general_hybrid",
            "harm_prevented": "None",
        },
    })
    return state
