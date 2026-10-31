import re
import time
from app.pipeline.state import SecureRAGState

# Dynamic Threat Matrix: Direct Jailbreaks, System Prompt Extraction, and Dangerous Malicious Intent
DIRECT_INJECTION_PATTERN_MATRIX = [
    # 1. Terrorism, Violent Extremism & Mass Harm Intent
    (r"(?i)\b(terrorist|terrorism|extremist|radicalize|hijack(ing)?|hostage|mass\s+casualty|jihadist|suicide\s+bomber|taliban|isis|al-qaeda)\b", 0.98, "Severe Public Safety Violation: Terrorism / Violent Extremism detected"),
    (r"(?i)\bi\s+want\s+to\s+become\s+a\s+terrorist\b", 0.99, "Severe Public Safety Violation: Explicit terrorism declaration"),

    # 2. Weapons, Explosives, CBRN & Proliferation
    (r"(?i)\b(make|build|construct|assemble|synthesize|how\s+to\s+make)\s+(a\s+)?(bomb|explosive|ied|grenade|pipe\s*bomb|molotov|detonator|bioweapon|chemical\s+weapon|dirty\s+bomb)\b", 0.98, "Severe Public Safety Violation: Weapon / Explosive fabrication request"),
    (r"(?i)\b(anthrax|ricin|sarin|vx\s+nerve\s+agent|mustard\s+gas|botulinum|c4\s+explosive)\b", 0.95, "Dangerous CBRN Chemical/Biological weapon proliferation reference"),
    (r"(?i)\b(how\s+to\s+detonate|firearm\s+auto-?sear|convert.*to\s+full\s+auto|ghost\s+gun\s+cad)\b", 0.95, "Weapons & Firearms proliferation directive"),

    # 3. Severe Violence, Murder, Poisoning & Self-Harm
    (r"(?i)\b(how\s+to\s+)?(kill|murder|assassinate|poison|strangle|slaughter)\s+(someone|people|a\s+person|my\s+|the\s+president|innocent)\b", 0.98, "Severe Violent Crime Violation: Murder / Assassination / Poisoning directive"),
    (r"(?i)\b(how\s+to\s+commit\s+suicide|methods\s+of\s+self-?harm|best\s+way\s+to\s+kill\s+myself)\b", 0.98, "Severe Harm / Self-Harm policy violation"),

    # 4. Cyberattacks, Malware Generation & Exploitation
    (r"(?i)\b(write|create|generate|provide)\s+(a\s+)?(ransomware|keylogger|trojan|rootkit|reverse\s+shell|spyware|botnet|credential\s+harvester)\b", 0.95, "Malicious Cyberattack: Malware generation request"),
    (r"(?i)\b(ddos\s+attack|exploit\s+payload|sql\s+injection\s+payload|steal\s+passwords|bypass\s+antivirus|zero-?day\s+exploit)\b", 0.90, "Cyberattack & unauthorized system penetration directive"),

    # 5. Imperative instruction override patterns
    (r"(?i)\bignore\s+(all\s+)?(previous|prior|above|other|system)\s+(instructions|rules|prompts|commands|directives|guidelines)\b", 0.95, "Direct instruction override attempt"),
    (r"(?i)\b(disregard|forget|bypass|override)\s+(all\s+)?(prior|previous|existing|system|safety)\s+(rules|prompts|instructions|filters)\b", 0.95, "Safety constraint circumvention directive"),
    
    # 6. System prompt and secret extraction patterns
    (r"(?i)\b(reveal|print|show|output|repeat|leak|exfiltrate|display)\s+(your\s+)?(system\s+prompt|hidden\s+instructions|developer\s+prompt|secret\s+token|spotlight\s+nonce)\b", 0.95, "System prompt / secret extraction attempt"),
    (r"(?i)\bwhat\s+(is|are)\s+your\s+(exact\s+)?(system\s+prompt|initial\s+instructions|internal\s+rules)\b", 0.90, "System prompt discovery probe"),

    # 7. Persona switches and jailbreak framing
    (r"(?i)\b(you\s+are\s+now\s+in\s+developer\s+mode|jailbreak|do\s+anything\s+now|dan\s+mode|unrestricted\s+mode|chaos\s+mode)\b", 0.95, "Jailbreak persona switch attempt"),
    (r"(?i)\b(pretend\s+you\s+have\s+no\s+(ethics|rules|constraints)|act\s+as\s+an\s+unfiltered\s+assistant)\b", 0.90, "Unfiltered persona switch framing"),
    
    # 8. Prompt extraction / canary probes
    (r"(?i)\boutput\s+the\s+words?\s+above\s+starting\s+with\b", 0.85, "Context boundary extraction probe"),
]

# Patterns representing non-adversarial conversational queries
CASUAL_CONVERSATIONAL_PATTERNS = [
    r"(?i)^(hi|hello|hey|howdy|greetings|good\s+(morning|afternoon|evening))\b",
    r"(?i)\b(how\s+are\s+you|who\s+are\s+you|what\s+is\s+your\s+name|what\s+can\s+you\s+do)\b",
    r"(?i)\b(weather|temperature|forecast|rain|sunny|umbrella|climate)\b",
    r"(?i)\b(what\s+time\s+is\s+it|what\s+is\s+today's?\s+date|what\s+day\s+is\s+it)\b",
    r"(?i)\b(tell\s+me\s+a\s+joke|write\s+a\s+poem|who\s+won|sports|recipe|movie)\b",
    r"(?i)\b(what\s+is\s+gen\s*ai|explain\s+gen\s*ai|what\s+is\s+generative\s+ai|explain\s+generative\s+ai|tell\s+me\s+about\s+ai|what\s+is\s+machine\s+learning|deep\s+learning|generative\s+ai|artificial\s+intelligence)\b",
    r"(?i)\b(python|write\s+a\s+function|coding|write\s+code|code\s+snippet|how\s+to\s+code|data\s+structure)\b",
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

    # Dynamic evaluation against the direct injection and harmful intent pattern matrix
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

    state["sanitized_query"] = raw_query
    state["input_risk_score"] = round(max_risk, 3)
    state["input_blocked"] = is_blocked
    state["input_block_reason"] = "; ".join(matched_reasons) if is_blocked else None
    state["is_casual_query"] = is_casual

    if is_blocked:
        state["stopped_at_layer"] = 1
        is_severe_harm = any("Public Safety" in r or "Violent" in r or "Weapon" in r or "Cyberattack" in r or "Harm" in r for r in matched_reasons)
        if is_severe_harm:
            state["harm_prevention_explanation"] = (
                "Blocked at Layer 1 Input Firewall: Severe harmful/malicious intent detected "
                "(Terrorism / Weapons / Violent Harm / Cyberattack Violation). "
                "Enforced strict AI safety boundary before any processing."
            )
        else:
            state["harm_prevention_explanation"] = (
                "Prevented direct instruction override / jailbreak attempt at pre-retrieval firewall. "
                "Eliminated the threat of system prompt exfiltration or safety parameter circumvention before vector search."
            )
        summary = f"Layer 1 Intervention: Blocked threat (risk={max_risk:.2f} >= {L1_BLOCK_THRESHOLD}). Reason: {state['input_block_reason']}"
        details = {
            "risk_score": max_risk,
            "threshold": L1_BLOCK_THRESHOLD,
            "matched_rules": matched_reasons,
            "harm_prevented": state["harm_prevention_explanation"],
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
