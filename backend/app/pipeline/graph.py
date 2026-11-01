import time
from langgraph.graph import StateGraph, END
from app.pipeline.state import SecureRAGState
from app.pipeline.layer1_input_guard import run_layer1_input_guard
from app.pipeline.layer2_retriever import run_layer2_retriever
from app.pipeline.layer3_sanitizer import run_layer3_sanitizer
from app.pipeline.layer4_synthesizer import run_layer4_synthesizer
from app.pipeline.layer5_auditor import run_layer5_auditor

def finalize_layer1_blocked(state: SecureRAGState) -> SecureRAGState:
    state["stopped_at_layer"] = 1
    state["blocked"] = True
    state["input_blocked"] = True
    state["final_answer"] = (
        f"Request blocked by Layer 1 Pre-Retrieval Input Firewall. "
        f"Reason: {state.get('input_block_reason') or state.get('block_reason') or 'Direct prompt injection / jailbreak detected.'} "
        f"Harm Prevention: {state.get('harm_prevention_explanation')}"
    )
    state["faithfulness_score"] = 1.0
    state["output_passed_audit"] = True
    state["audit_notes"] = "Query safely rejected prior to vector retrieval."

    # Pad downstream telemetry so all 5 layers are present in UI trace as SKIPPED
    existing_layers = {t["layer_number"] for t in state.get("telemetry", [])}
    for layer_num, layer_name in [
        (2, "Qdrant Hybrid Retriever & Namespace Guard"),
        (3, "Zero-Trust Context Sanitizer & Consensus Engine"),
        (4, "Cryptographic Nonce-Spotlighted Synthesizer"),
        (5, "Output Faithfulness & Citation Policy Auditor"),
    ]:
        if layer_num not in existing_layers:
            state["telemetry"].append({
                "layer_number": layer_num,
                "layer_name": layer_name,
                "status": "SKIPPED",
                "latency_ms": 0.0,
                "summary": "Execution halted at Layer 1; downstream processing skipped to eliminate risk.",
                "details": {"bypassed": True, "harm_prevented": "Protected downstream agent pipeline"},
            })
    return state

def finalize_layer2_blocked(state: SecureRAGState) -> SecureRAGState:
    state["stopped_at_layer"] = 2
    state["blocked"] = True
    state["layer2_blocked"] = True
    state["final_answer"] = (
        f"Request blocked by Layer 2 Qdrant Hybrid Retriever & Namespace Guard. "
        f"Reason: {state.get('block_reason') or 'Unauthorized vector collection namespace traversal or vector dump pattern detected.'} "
        f"Harm Prevention: {state.get('harm_prevention_explanation')}"
    )
    state["faithfulness_score"] = 1.0
    state["output_passed_audit"] = True
    state["audit_notes"] = "Vector namespace traversal blocked."

    existing_layers = {t["layer_number"] for t in state.get("telemetry", [])}
    for layer_num, layer_name in [
        (3, "Zero-Trust Context Sanitizer & Consensus Engine"),
        (4, "Cryptographic Nonce-Spotlighted Synthesizer"),
        (5, "Output Faithfulness & Citation Policy Auditor"),
    ]:
        if layer_num not in existing_layers:
            state["telemetry"].append({
                "layer_number": layer_num,
                "layer_name": layer_name,
                "status": "SKIPPED",
                "latency_ms": 0.0,
                "summary": "Execution halted at Layer 2; downstream sanitization and synthesis skipped.",
                "details": {"bypassed": True, "harm_prevented": "Multi-tenant vector collection breach prevented"},
            })
    return state

def finalize_layer3_blocked(state: SecureRAGState) -> SecureRAGState:
    state["stopped_at_layer"] = 3
    state["blocked"] = True
    state["layer3_blocked"] = True
    q_count = len(state.get("quarantined_chunks", []))
    reasons = [c.get("quarantine_reason", "Poisoning detected") for c in state.get("quarantined_chunks", [])]
    reason_str = "; ".join(set(reasons)) if reasons else "Adversarial indirect prompt injection or fact corruption detected in retrieved context."
    state["final_answer"] = (
        f"Request halted by Layer 3 Zero-Trust Context Sanitizer. "
        f"Reason: Strict Zero-Trust policy triggered — {q_count or 1} retrieved chunk(s) quarantined ({reason_str}). "
        f"SecureRAG halted downstream synthesis to eliminate poisoned context ingestion. "
        f"Harm Prevention: {state.get('harm_prevention_explanation')}"
    )
    state["faithfulness_score"] = 1.0
    state["output_passed_audit"] = True
    state["audit_notes"] = f"Zero-Trust halt triggered: {q_count or 1} chunk(s) quarantined."

    existing_layers = {t["layer_number"] for t in state.get("telemetry", [])}
    for layer_num, layer_name in [
        (4, "Cryptographic Nonce-Spotlighted Synthesizer"),
        (5, "Output Faithfulness & Citation Policy Auditor"),
    ]:
        if layer_num not in existing_layers:
            state["telemetry"].append({
                "layer_number": layer_num,
                "layer_name": layer_name,
                "status": "SKIPPED",
                "latency_ms": 0.0,
                "summary": "Execution halted at Layer 3; downstream synthesis skipped under Zero-Trust policy.",
                "details": {"bypassed": True, "harm_prevented": "Prevented poisoned context LLM ingestion"},
            })
    return state

def finalize_layer4_blocked(state: SecureRAGState) -> SecureRAGState:
    state["stopped_at_layer"] = 4
    state["blocked"] = True
    state["layer4_blocked"] = True
    state["final_answer"] = (
        f"Request blocked by Layer 4 Cryptographic Nonce-Spotlighted Synthesizer. "
        f"Reason: {state.get('block_reason') or 'Nonce delimiter breakout or context containment escape sequence detected.'} "
        f"Harm Prevention: {state.get('harm_prevention_explanation')}"
    )
    state["faithfulness_score"] = 1.0
    state["output_passed_audit"] = True
    state["audit_notes"] = "Delimiter breakout halted at synthesis stage."

    existing_layers = {t["layer_number"] for t in state.get("telemetry", [])}
    if 5 not in existing_layers:
        state["telemetry"].append({
            "layer_number": 5,
            "layer_name": "Output Faithfulness & Citation Policy Auditor",
            "status": "SKIPPED",
            "latency_ms": 0.0,
            "summary": "Execution halted at Layer 4; output auditor skipped as synthesis was terminated.",
            "details": {"bypassed": True, "harm_prevented": "Prompt injection escape prevented"},
        })
    return state

def route_after_layer1(state: SecureRAGState) -> str:
    if state.get("input_blocked") or state.get("stopped_at_layer") == 1 or state.get("blocked"):
        return "finalize_l1"
    return "layer2_retriever"

def route_after_layer2(state: SecureRAGState) -> str:
    if state.get("layer2_blocked") or state.get("stopped_at_layer") == 2:
        return "finalize_l2"
    if state.get("blocked") or state.get("stopped_at_layer") is not None:
        return "finalize_l1"
    return "layer3_sanitizer"

def route_after_layer3(state: SecureRAGState) -> str:
    if (
        state.get("layer3_blocked")
        or state.get("stopped_at_layer") == 3
        or state.get("blocked")
        or (state.get("quarantined_chunks") and len(state["quarantined_chunks"]) > 0)
    ):
        return "finalize_l3"
    if state.get("stopped_at_layer") is not None:
        return END
    return "layer4_synthesizer"

def route_after_layer4(state: SecureRAGState) -> str:
    if state.get("layer4_blocked") or state.get("stopped_at_layer") == 4:
        return "finalize_l4"
    if state.get("blocked") or state.get("stopped_at_layer") is not None:
        return END
    return "layer5_auditor"

def build_securerag_graph():
    workflow = StateGraph(SecureRAGState)
    workflow.add_node("layer1_input_guard", run_layer1_input_guard)
    workflow.add_node("layer2_retriever", run_layer2_retriever)
    workflow.add_node("layer3_sanitizer", run_layer3_sanitizer)
    workflow.add_node("layer4_synthesizer", run_layer4_synthesizer)
    workflow.add_node("layer5_auditor", run_layer5_auditor)

    workflow.add_node("finalize_l1", finalize_layer1_blocked)
    workflow.add_node("finalize_l2", finalize_layer2_blocked)
    workflow.add_node("finalize_l3", finalize_layer3_blocked)
    workflow.add_node("finalize_l4", finalize_layer4_blocked)

    workflow.set_entry_point("layer1_input_guard")
    workflow.add_conditional_edges(
        "layer1_input_guard",
        route_after_layer1,
        {"finalize_l1": "finalize_l1", "layer2_retriever": "layer2_retriever"},
    )
    workflow.add_conditional_edges(
        "layer2_retriever",
        route_after_layer2,
        {"finalize_l2": "finalize_l2", "finalize_l1": "finalize_l1", "layer3_sanitizer": "layer3_sanitizer", END: END},
    )
    workflow.add_conditional_edges(
        "layer3_sanitizer",
        route_after_layer3,
        {"finalize_l3": "finalize_l3", "layer4_synthesizer": "layer4_synthesizer", END: END},
    )
    workflow.add_conditional_edges(
        "layer4_synthesizer",
        route_after_layer4,
        {"finalize_l4": "finalize_l4", "layer5_auditor": "layer5_auditor", END: END},
    )
    workflow.add_edge("layer5_auditor", END)
    workflow.add_edge("finalize_l1", END)
    workflow.add_edge("finalize_l2", END)
    workflow.add_edge("finalize_l3", END)
    workflow.add_edge("finalize_l4", END)

    return workflow.compile()

securerag_graph = build_securerag_graph()

def execute_securerag_pipeline(query: str, top_k: int = 6, llm_provider: str = None) -> SecureRAGState:
    t0 = time.perf_counter()
    initial_state: SecureRAGState = {
        "query": query,
        "sanitized_query": query,
        "top_k": top_k,
        "llm_provider": llm_provider,
        "is_casual_query": False,
        "stopped_at_layer": None,
        "blocked": False,
        "block_reason": None,
        "harm_prevention_explanation": None,
        "input_blocked": False,
        "input_risk_score": 0.0,
        "input_block_reason": None,
        "layer2_blocked": False,
        "candidate_chunks": [],
        "verified_chunks": [],
        "quarantined_chunks": [],
        "layer3_blocked": False,
        "layer4_blocked": False,
        "spotlight_nonce": "N/A",
        "draft_answer": "",
        "cited_chunk_ids": [],
        "final_answer": "",
        "faithfulness_score": 0.0,
        "output_passed_audit": True,
        "audit_notes": "",
        "total_latency_ms": 0.0,
        "telemetry": [],
    }
    final_state = securerag_graph.invoke(initial_state)

    # Post-execution safety enforcement: ensure clean halted state cannot be corrupted
    if final_state.get("stopped_at_layer") == 3 or final_state.get("layer3_blocked"):
        final_state["stopped_at_layer"] = 3
        final_state["blocked"] = True
        final_state["layer3_blocked"] = True
        # Ensure Layer 4 and Layer 5 are present as SKIPPED in telemetry
        existing_layers = {t["layer_number"]: t for t in final_state["telemetry"]}
        for l_num, l_name in [
            (4, "Cryptographic Nonce-Spotlighted Synthesizer"),
            (5, "Output Faithfulness & Citation Policy Auditor"),
        ]:
            if l_num not in existing_layers:
                final_state["telemetry"].append({
                    "layer_number": l_num,
                    "layer_name": l_name,
                    "status": "SKIPPED",
                    "latency_ms": 0.0,
                    "summary": "Execution halted at Layer 3; downstream processing skipped.",
                    "details": {"bypassed": True, "harm_prevented": "Prevented poisoned context LLM ingestion"},
                })
            elif existing_layers[l_num]["status"] != "SKIPPED":
                existing_layers[l_num]["status"] = "SKIPPED"
                existing_layers[l_num]["summary"] = "Execution halted at Layer 3; downstream processing skipped."

    final_state["total_latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    return final_state
