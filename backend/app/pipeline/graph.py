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
    state["final_answer"] = (
        f"Request blocked by Layer 1 Pre-Retrieval Input Firewall. "
        f"Reason: {state.get('input_block_reason') or 'Direct prompt injection / jailbreak detected.'} "
        f"Harm Prevention: {state.get('harm_prevention_explanation')}"
    )
    state["faithfulness_score"] = 1.0
    state["output_passed_audit"] = True
    state["audit_notes"] = "Query safely rejected prior to vector retrieval."

    # Pad downstream telemetry so all 5 layers are present in UI trace as SKIPPED
    for layer_num, layer_name in [
        (2, "Qdrant Hybrid Retriever & Namespace Guard"),
        (3, "Zero-Trust Context Sanitizer & Consensus Engine"),
        (4, "Cryptographic Nonce-Spotlighted Synthesizer"),
        (5, "Output Faithfulness & Citation Policy Auditor"),
    ]:
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
    state["final_answer"] = (
        f"Request blocked by Layer 2 Qdrant Hybrid Retriever & Namespace Guard. "
        f"Reason: Unauthorized vector collection namespace traversal or vector dump pattern detected. "
        f"Harm Prevention: {state.get('harm_prevention_explanation')}"
    )
    state["faithfulness_score"] = 1.0
    state["output_passed_audit"] = True
    state["audit_notes"] = "Vector namespace traversal blocked."

    for layer_num, layer_name in [
        (3, "Zero-Trust Context Sanitizer & Consensus Engine"),
        (4, "Cryptographic Nonce-Spotlighted Synthesizer"),
        (5, "Output Faithfulness & Citation Policy Auditor"),
    ]:
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
    q_count = len(state.get("quarantined_chunks", []))
    reasons = [c.get("quarantine_reason", "Poisoning detected") for c in state.get("quarantined_chunks", [])]
    reason_str = "; ".join(set(reasons)) if reasons else "Adversarial indirect prompt injection or fact corruption detected in retrieved context."
    state["final_answer"] = (
        f"Request halted by Layer 3 Zero-Trust Context Sanitizer. "
        f"Reason: Strict Zero-Trust policy triggered — {q_count} retrieved chunk(s) quarantined ({reason_str}). "
        f"SecureRAG halted downstream synthesis to eliminate poisoned context ingestion. "
        f"Harm Prevention: {state.get('harm_prevention_explanation')}"
    )
    state["faithfulness_score"] = 1.0
    state["output_passed_audit"] = True
    state["audit_notes"] = f"Zero-Trust halt triggered: {q_count} chunk(s) quarantined."

    for layer_num, layer_name in [
        (4, "Cryptographic Nonce-Spotlighted Synthesizer"),
        (5, "Output Faithfulness & Citation Policy Auditor"),
    ]:
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
    state["final_answer"] = (
        f"Request blocked by Layer 4 Cryptographic Nonce-Spotlighted Synthesizer. "
        f"Reason: Nonce delimiter breakout or context containment escape sequence detected. "
        f"Harm Prevention: {state.get('harm_prevention_explanation')}"
    )
    state["faithfulness_score"] = 1.0
    state["output_passed_audit"] = True
    state["audit_notes"] = "Delimiter breakout halted at synthesis stage."

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
    return "finalize_l1" if state.get("input_blocked") else "layer2_retriever"

def route_after_layer2(state: SecureRAGState) -> str:
    return "finalize_l2" if state.get("layer2_blocked") else "layer3_sanitizer"

def route_after_layer3(state: SecureRAGState) -> str:
    if state.get("layer3_blocked") or (state.get("quarantined_chunks") and len(state["quarantined_chunks"]) > 0):
        return "finalize_l3"
    return "layer4_synthesizer"

def route_after_layer4(state: SecureRAGState) -> str:
    return "finalize_l4" if state.get("layer4_blocked") else "layer5_auditor"

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
        {"finalize_l2": "finalize_l2", "layer3_sanitizer": "layer3_sanitizer"},
    )
    workflow.add_conditional_edges(
        "layer3_sanitizer",
        route_after_layer3,
        {"finalize_l3": "finalize_l3", "layer4_synthesizer": "layer4_synthesizer"},
    )
    workflow.add_conditional_edges(
        "layer4_synthesizer",
        route_after_layer4,
        {"finalize_l4": "finalize_l4", "layer5_auditor": "layer5_auditor"},
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
    final_state["total_latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    return final_state
