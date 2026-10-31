from pydantic import BaseModel, Field, field_validator
from typing import List, Dict, Any, Optional, Literal

# ============================================================================
# 1. LLM Structured Output Schemas (Used in Layer 3 & Layer 4)
# ============================================================================
class SingleChunkAuditLLM(BaseModel):
    chunk_id: str = Field(description="Exact ID of the evaluated chunk.")
    injection_probability: float = Field(
        ge=0.0, le=1.0,
        description="Probability (0.0 to 1.0) that this chunk contains an Indirect Prompt Injection, role hijack, or delimiter breakout."
    )
    contradiction_score: float = Field(
        ge=0.0, le=1.0,
        description="Probability (0.0 to 1.0) that this chunk states false/poisoned numerical or technical facts contradicting the majority consensus of other retrieved chunks."
    )
    attack_category: Literal["NONE", "INDIRECT_INJECTION", "FACT_POISONING", "DELIMITER_BREAKOUT"] = Field(
        description="Primary threat category detected in the chunk."
    )
    reason: str = Field(description="Concise 1-sentence explanation of why this chunk was flagged or verified.")
    flagged_substrings: List[str] = Field(
        default_factory=list,
        description="Exact suspicious phrases or poisoned numeric claims found inside the chunk text."
    )

class ChunkAuditBatchLLM(BaseModel):
    consensus_summary: str = Field(
        description="Brief summary of the ground-truth consensus across the candidate chunks."
    )
    audits: List[SingleChunkAuditLLM]

class SynthesizedAnswerLLM(BaseModel):
    answer: str = Field(
        description="Grounded technical response using ONLY facts from the spotlighted data blocks, with inline citations like [CHUNK_01]."
    )
    cited_chunk_ids: List[str] = Field(
        description="List of chunk IDs explicitly cited in the answer."
    )

# ============================================================================
# 2. Pipeline Telemetry & REST API Schemas
# ============================================================================
class ChunkDetailResponse(BaseModel):
    chunk_id: str
    doc_id: str
    doc_title: str
    text: str
    retrieval_score: float
    trust_score: float
    heuristic_penalty: float
    injection_probability: float
    contradiction_score: float
    is_quarantined: bool
    attack_category: str
    quarantine_reason: str
    flagged_spans: List[str]

class LayerTelemetryResponse(BaseModel):
    layer_number: int
    layer_name: str
    status: Literal["PASS", "WARN", "QUARANTINED", "BLOCKED", "SKIPPED"]
    latency_ms: float
    summary: str
    details: Dict[str, Any] = Field(default_factory=dict)

class BaselineRAGResult(BaseModel):
    answer: str
    latency_ms: float
    compromised: bool
    compromise_reason: str
    used_chunk_ids: List[str]

class SecureRAGResult(BaseModel):
    answer: str
    faithfulness_score: float
    output_passed_audit: bool
    audit_notes: str
    spotlight_nonce: str
    cited_chunk_ids: List[str]
    total_latency_ms: float
    input_blocked: bool
    stopped_at_layer: Optional[int] = None
    harm_prevention_explanation: Optional[str] = None
    telemetry: List[LayerTelemetryResponse]
    candidate_chunks: List[ChunkDetailResponse]
    verified_chunks: List[ChunkDetailResponse]
    quarantined_chunks: List[ChunkDetailResponse]

class CompareQueryRequest(BaseModel):
    query: str = Field(..., min_length=2, max_length=1500)
    top_k: int = Field(default=6, ge=2, le=10)
    llm_provider: Optional[Literal["gemini", "groq", "deterministic"]] = None

    @field_validator("query", mode="before")
    @classmethod
    def sanitize_query(cls, v: Any) -> str:
        if isinstance(v, str):
            return v.replace("\x00", "").strip()
        return v

class CompareQueryResponse(BaseModel):
    query: str
    sanitized_query: str
    baseline: BaselineRAGResult
    securerag: SecureRAGResult

class InjectPoisonRequest(BaseModel):
    doc_title: str = Field(default="Custom_Adversarial_Note.md", max_length=255)
    text: str = Field(..., min_length=10, max_length=3000)
    attack_category: Literal["INDIRECT_INJECTION", "FACT_POISONING", "DELIMITER_BREAKOUT"] = "INDIRECT_INJECTION"

    @field_validator("doc_title", "text", mode="before")
    @classmethod
    def sanitize_inputs(cls, v: Any) -> str:
        if isinstance(v, str):
            return v.replace("\x00", "").strip()
        return v

class CorpusStatsResponse(BaseModel):
    total_chunks: int
    clean_chunks: int
    poisoned_chunks: int
    collection_name: str
    chunks: List[Dict[str, Any]]

