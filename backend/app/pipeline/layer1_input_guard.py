import re
import time
from app.pipeline.state import SecureRAGState

# Dynamic Pattern Matrix for Direct Injections, Jailbreaks & System Prompt Extraction ONLY
# Note: XML delimiter tags (</DATA_BLOCK) belong to Layer 4, and compliance sign-offs belong to Layer 5.
DIRECT_INJECTION_PATTERN_MATRIX = [
    # 1. Imperative instruction override patterns
    (r"(?i)\bignore\s+(all\s+)?(previous|prior|above|other|system)\s+(instructions|rules|prompts|commands|directives|guidelines)\b", 0.95, "Direct instruction override attempt"),
    (r"(?i)\b(disregard|forget|bypass|override)\s+(all\s+)?(prior|previous|existing|system|safety)\s+(rules|prompts|instructions|filters)\b", 0.95, "Safety constraint circumvention directive"),
    
    # 2. System prompt and secret extraction patterns
    (r"(?i)\b(reveal|print|show|output|repeat|leak|exfiltrate|display)\s+(your\s+)?(system\s+prompt|hidden\s+instructions|developer\s+prompt|secret\s+token|spotlight\s+nonce)\b", 0.95, "System prompt / secret extraction attempt"),
    (r"(?i)\bwhat\s+(is|are)\s+your\s+(exact\s+)?(system\s+prompt|initial\s+instructions|internal\s+rules)\b", 0.90, "System prompt discovery probe"),

    # 3. Persona switches and jailbreak framing
    (r"(?i)\b(you\s+are\s+now\s+in\s+developer\s+mode|jailbreak|do\s+anything\s+now|dan\s+mode|unrestricted\s+mode|chaos\s+mode)\b", 0.95, "Jailbreak persona switch attempt"),
    (r"(?i)\b(pretend\s+you\s+have\s+no\s+(ethics|rules|constraints)|act\s+as\s+an\s+unfiltered\s+assistant)\b", 0.90, "Unfiltered persona switch framing"),
    
    # 4. Prompt extraction / canary probes
    (r"(?i)\boutput\s+the\s+words?\s+above\s+starting\s+with\b", 0.85, "Context boundary extraction probe"),
]

# Patterns representing non-adversarial conversational queries
CASUAL_CONVERSATIONAL_PATTERNS = [
    r"(?i)^(hi|hello|hey|howdy|greetings|good\s+(morning|afternoon|evening))\b",
    r"(?i)\b(how\s+are\s+you|who\s+are\s+you|what\s+is\s+your\s+name|what\s+can\s+you\s+do)\b",
    r"(?i)\b(weather|temperature|forecast|rain|sunny|umbrella|climate)\b",
    r"(?i)\b(what\s+time\s+is\s+it|what\s+is\s+today's?\s+date|what\s+day\s+is\s+it)\b",
    r"(?i)\b(tell\s+me\s+a\s+joke|write\s+a\s+poem|who\s+won|sports|recipe|movie)\b",
    r"(?i)\b(explain\s+generative\s+ai|what\s+is\s+generative\s+ai|tell\s+me\s+about\s+ai|what\s+is\s+machine\s+learning)\b",
]

SPECIFIC_STANDARDS_KEYWORDS = (
    r"(?i)\b(is-?456|is-?13920|is-?13311|tau_c_max|boundary\s+elements|135\s+degree|"
    r"reparameterization|scaled\s+dot-?product|d_k|tls\s+1\.3|aes-?256-?gcm|ddpm|diffusion)\b"
)

L1_BLOCK_THRESHOLD = 0.60

def run_layer1_input_guard(state: SecureRAGState) -> SecureRAGState:
    t0 = time.perf_counter()
    raw_query = state["query"].strip()

    max_risk = 0.0
    matched_reasons = []

    # Dynamic evaluation against the direct injection pattern matrix ONLY
    for pattern, weight, reason in DIRECT_INJECTION_PATTERN_MATRIX:
        if re.search(pattern, raw_query):
            if weight > max_risk:
                max_risk = weight
            matched_reasons.append(reason)

    is_blocked = max_risk >= L1_BLOCK_THRESHOLD

    # Determine if query is benign conversational
    is_casual = False
    if not is_blocked and max_risk == 0.0:
        has_casual = any(re.search(pat, raw_query) for pat in CASUAL_CONVERSATIONAL_PATTERNS)
        has_standards = bool(re.search(SPECIFIC_STANDARDS_KEYWORDS, raw_query))
        if has_casual and not has_standards:
            is_casual = True

    latency_ms = round((time.perf_counter() - t0) * 1000, 2)

    # Preserve raw query content untouched so downstream layers (L4 delimiter checks, etc.) inspect original payloads
    state["sanitized_query"] = raw_query
    state["input_risk_score"] = round(max_risk, 3)
    state["input_blocked"] = is_blocked
    state["input_block_reason"] = "; ".join(matched_reasons) if is_blocked else None
    state["is_casual_query"] = is_casual

    if is_blocked:
        state["stopped_at_layer"] = 1
        state["harm_prevention_explanation"] = (
            "Prevented direct instruction override / jailbreak attempt at pre-retrieval firewall. "
            "Eliminated the threat of system prompt exfiltration or safety parameter circumvention before vector search."
        )
        summary = f"Layer 1 Intervention: Blocked direct attack (risk={max_risk:.2f} >= {L1_BLOCK_THRESHOLD}). Reason: {state['input_block_reason']}"
        details = {
            "risk_score": max_risk,
            "threshold": L1_BLOCK_THRESHOLD,
            "matched_rules": matched_reasons,
            "harm_prevented": "Direct system prompt extraction / jailbreak bypass",
        }
    else:
        summary = (
            f"Layer 1 Passed: Conversational query verified safe (risk={max_risk:.2f}). Forwarded for natural synthesis."
            if is_casual
            else f"Layer 1 Passed: Query passed input firewall checks (risk={max_risk:.2f} < {L1_BLOCK_THRESHOLD})."
        )
        details = {
            "risk_score": max_risk,
            "threshold": L1_BLOCK_THRESHOLD,
            "is_casual_query": is_casual,
            "harm_prevented": "None (Benign query verified)",
        }

    state["telemetry"].append({
        "layer_number": 1,
        "layer_name": "Pre-Retrieval Input Firewall",
        "status": "BLOCKED" if is_blocked else "PASS",
        "latency_ms": latency_ms,
        "summary": summary,
        "details": details,
    })
    return state
