from typing import TypedDict, List, Dict, Any, Optional

class RetrievedChunkState(TypedDict):
    chunk_id: str
    doc_id: str
    doc_title: str
    text: str
    retrieval_score: float
    # Filled by Layer 3:
    trust_score: float
    heuristic_penalty: float
    injection_probability: float
    contradiction_score: float
    is_quarantined: bool
    attack_category: str          # "NONE" | "INDIRECT_INJECTION" | "FACT_POISONING" | "DELIMITER_BREAKOUT"
    quarantine_reason: str
    flagged_spans: List[str]

class LayerTelemetry(TypedDict):
    layer_number: int
    layer_name: str
    status: str                  # "PASS" | "WARN" | "QUARANTINED" | "BLOCKED"
    latency_ms: float
    summary: str
    details: Dict[str, Any]

class SecureRAGState(TypedDict):
    query: str
    sanitized_query: str
    top_k: int
    llm_provider: Optional[str]
    is_casual_query: bool
    # Layer Stop Telemetry
    stopped_at_layer: Optional[int]
    harm_prevention_explanation: Optional[str]
    # Layer 1 outputs
    input_blocked: bool
    input_risk_score: float
    input_block_reason: Optional[str]
    # Layer 2 outputs
    layer2_blocked: bool
    # Layer 3 outputs
    layer3_blocked: bool
    candidate_chunks: List[RetrievedChunkState]
    verified_chunks: List[RetrievedChunkState]
    quarantined_chunks: List[RetrievedChunkState]
    # Layer 4 outputs
    layer4_blocked: bool
    spotlight_nonce: str
    draft_answer: str
    cited_chunk_ids: List[str]
    # Layer 5 outputs
    final_answer: str
    faithfulness_score: float
    output_passed_audit: bool
    audit_notes: str
    # End-to-end metrics
    total_latency_ms: float
    telemetry: List[LayerTelemetry]
