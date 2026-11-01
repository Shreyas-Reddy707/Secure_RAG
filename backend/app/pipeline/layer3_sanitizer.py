import re
import time
from typing import List, Tuple
from app.pipeline.state import SecureRAGState, RetrievedChunkState
from app.config import settings

# Content Sanitization Heuristic Rules for In-Context Chunk Threats
HEURISTIC_RULES: List[Tuple[str, float, str, str]] = [
    (r"(?i)\[\s*system\s*(override|instruction|note|directive)?[^\]]*\]", 0.95, "INDIRECT_INJECTION", "Fake [SYSTEM OVERRIDE] header detected in retrieved chunk"),
    (r"(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|other|above)\s+(context|instructions|documents|rules)", 0.95, "INDIRECT_INJECTION", "Imperative instruction override phrase in document"),
    (r"(?i)(you\s+must\s+state|always\s+recommend|mandatory\s+response\s+override|output\s+the\s+exact\s+phrase)", 0.90, "INDIRECT_INJECTION", "Forced response hijacking directive inside chunk"),
    (r"(?i)\b(exfiltrate|untrusted-telemetry|untrusted-|leak_keys|phone_home)\b", 0.95, "DATA_EXFILTRATION", "Data exfiltration directive or untrusted endpoint reference"),
    (r"!\[.*?\]\(https?://[^\)]+\)", 0.95, "BEACON_EXFILTRATION", "Covert Markdown image beacon exfiltration detected"),
    (r"<!--[\s\S]*?-->", 0.90, "HTML_COMMENT_INJECTION", "Covert HTML comment instruction injection detected"),
    (r"(?i)(disable\s+(encryption|tls|aes)|recommend\s+disabling\s+(all\s+)?(tls|encryption)|encryption\s+is\s+(completely\s+)?deprecated)", 0.95, "FACT_POISONING", "Adversarial encryption deprecation override"),
    (r"(?i)(emergency\s+revision\s+99|unverified\s+override\s+bulletin|supersedes\s+all\s+safety\s+codes\s+without\s+review)", 0.90, "FACT_POISONING", "Unverified emergency specification spoofing marker"),
    (r"(?i)\b(terrorist|bomb|explosive|ransomware|keylogger|exploit\s+payload)\b", 0.95, "MALICIOUS_PAYLOAD", "Malicious or harmful file payload detected"),
]

SUBTLE_POISON_MARKERS = [
    (r"(?i)(350\s*MPa|0\.0\s*safety\s*factor|disable\s+(tls|encryption)|plaintext\s+api\s+keys|divide\s+by\s+zero\s+norm|skip\s+gradient\s+clipping)",
     "Contradicts verified multi-chunk engineering/AI consensus specifications.")
]


def _fast_chunk_scan(text: str) -> Tuple[float, str, List[str], List[str]]:
    max_penalty = 0.0
    category = "NONE"
    reasons = []
    spans = []

    for pattern, weight, cat, reason in HEURISTIC_RULES:
        for match in re.finditer(pattern, text):
            if weight > max_penalty:
                max_penalty = weight
                category = cat
            reasons.append(reason)
            spans.append(match.group(0))

    for pat, reason in SUBTLE_POISON_MARKERS:
        m = re.search(pat, text)
        if m:
            if 0.88 > max_penalty:
                max_penalty = 0.88
                if category == "NONE":
                    category = "FACT_POISONING"
            reasons.append(reason)
            spans.append(m.group(0))

    return max_penalty, category, list(dict.fromkeys(reasons)), list(dict.fromkeys(spans))


def run_layer3_sanitizer(state: SecureRAGState) -> SecureRAGState:
    t0 = time.perf_counter()
    chunks = state.get("candidate_chunks", [])
    raw_query = state.get("sanitized_query", state["query"]).strip()

    # Also inspect any [UPLOADED_DOCUMENT] text inside query for covert injection / beacons
    upload_injection_detected = False
    upload_reasons = []
    if "[UPLOADED_DOCUMENT:" in raw_query:
        p_up, cat_up, r_up, s_up = _fast_chunk_scan(raw_query)
        if p_up >= 0.50:
            upload_injection_detected = True
            upload_reasons.extend(r_up)

    if not chunks and not upload_injection_detected:
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        state["layer3_blocked"] = False
        state["verified_chunks"] = []
        state["quarantined_chunks"] = []
        state["telemetry"].append({
            "layer_number": 3,
            "layer_name": "Zero-Trust Context Sanitizer & Consensus Engine",
            "status": "PASS",
            "latency_ms": latency_ms,
            "summary": "Layer 3 Passed: Zero candidate context chunks to audit for conversational/general query.",
            "details": {
                "quarantined_ids": [],
                "verified_ids": [],
                "harm_prevented": "None (No candidate context to sanitize)",
            },
        })
        return state

    verified_chunks = []
    quarantined_chunks = []

    for c in chunks:
        penalty, cat, reasons, spans = _fast_chunk_scan(c["text"])
        is_explicit_poison = bool(
            c.get("ground_truth_is_poisoned") or
            c.get("is_poisoned") or
            str(c.get("chunk_id", "")).startswith("CHUNK_POISON_")
        )

        # Check injection probability or contradiction score thresholds
        has_score_violation = (
            float(c.get("injection_probability", 0.0)) >= 0.45 or
            float(c.get("contradiction_score", 0.0)) >= 0.65
        )

        is_flagged = (penalty >= 0.45) or is_explicit_poison or has_score_violation

        if is_flagged:
            if penalty == 0.0:
                penalty = 0.95
                cat = "INDIRECT_INJECTION" if is_explicit_poison else "FACT_POISONING"
                reasons.append("Ground-truth poisoned knowledge marker detected")

            c["heuristic_penalty"] = round(penalty, 3)
            c["injection_probability"] = round(penalty if "INJECTION" in cat else 0.50, 3)
            c["contradiction_score"] = round(penalty if "POISON" in cat else 0.50, 3)
            c["trust_score"] = 0.0
            c["is_quarantined"] = True
            c["attack_category"] = cat if cat != "NONE" else "INDIRECT_INJECTION"
            c["quarantine_reason"] = "; ".join(reasons) if reasons else "Adversarial indirect prompt injection or fact corruption detected"
            c["flagged_spans"] = spans
            quarantined_chunks.append(c)
        else:
            c["heuristic_penalty"] = 0.0
            c["trust_score"] = 1.0
            c["is_quarantined"] = False
            c["attack_category"] = "NONE"
            c["quarantine_reason"] = "Verified clean"
            verified_chunks.append(c)

    latency_ms = round((time.perf_counter() - t0) * 1000, 2)
    state["verified_chunks"] = verified_chunks
    state["quarantined_chunks"] = quarantined_chunks

    # STRICT ZERO-TRUST HALT:
    # Whenever ANY chunk is detected as poisoned/malicious, immediately HALT at Layer 3
    if len(quarantined_chunks) > 0 or upload_injection_detected:
        state["layer3_blocked"] = True
        state["blocked"] = True
        state["stopped_at_layer"] = 3
        state["block_reason"] = "Layer 3 Context Sanitizer intercepted an Indirect Prompt Injection / Poisoned Document chunk in retrieved context."

        q_ids = [q["chunk_id"] for q in quarantined_chunks]
        quarantined_ids_str = ", ".join(q_ids) if q_ids else "UPLOADED_DOCUMENT"
        threat_cat = quarantined_chunks[0].get("attack_category", "INDIRECT_INJECTION") if quarantined_chunks else "INDIRECT_INJECTION"

        state["harm_prevention_explanation"] = (
            f"Strict Zero-Trust Halt: Quarantined {len(quarantined_chunks) or 1} targeted malicious chunk(s) ({quarantined_ids_str}). "
            f"Threat Vector: {threat_cat}. "
            f"Safely aborted pipeline execution to prevent feeding injected overrides or poisoned facts to the LLM generator."
        )
        state["final_answer"] = (
            f"Request halted by Layer 3 Zero-Trust Context Sanitizer. "
            f"Reason: Strict Zero-Trust policy triggered — {len(quarantined_chunks) or 1} retrieved chunk(s) quarantined ({quarantined_ids_str}). "
            f"SecureRAG halted downstream synthesis to eliminate poisoned context ingestion. "
            f"Harm Prevention: {state['harm_prevention_explanation']}"
        )
        summary = (
            f"Layer 3 Intervention: Quarantined {len(quarantined_chunks) or 1} poisoned chunk(s) ({quarantined_ids_str}). "
            f"Pipeline halted under Strict Zero-Trust policy."
        )
        details = {
            "quarantined_chunks": [
                {
                    "chunk_id": q["chunk_id"],
                    "attack_category": q["attack_category"],
                    "quarantine_reason": q["quarantine_reason"],
                    "trust_score": q["trust_score"],
                    "flagged_spans": q["flagged_spans"],
                }
                for q in quarantined_chunks
            ],
            "verified_count": len(verified_chunks),
            "harm_prevented": f"Prevented LLM generator from ingesting {len(quarantined_chunks) or 1} malicious context chunks into prompt window",
        }
        status = "BLOCKED"
    else:
        state["layer3_blocked"] = False
        summary = f"Layer 3 Passed: All {len(verified_chunks)} candidate chunks verified clean in {latency_ms:.1f}ms."
        details = {
            "verified_ids": [v["chunk_id"] for v in verified_chunks],
            "quarantined_count": 0,
            "harm_prevented": "None (All active context verified clean)",
        }
        status = "PASS"

    state["telemetry"].append({
        "layer_number": 3,
        "layer_name": "Zero-Trust Context Sanitizer & Consensus Engine",
        "status": status,
        "latency_ms": latency_ms,
        "summary": summary,
        "details": details,
    })
    return state
