import { useState, useEffect } from "react";
import { ChatMessage, LayerTelemetry, ChunkDetail } from "@/lib/types";
import {
  ShieldCheck,
  ShieldAlert,
  ArrowUpRight,
  Database,
  Activity,
  ChevronDown,
  Layers,
  FileCheck,
  Cpu,
} from "lucide-react";

interface MetricsGraphTabProps {
  selectedMessage: ChatMessage | null;
  onSelectMessage: (msg: ChatMessage) => void;
  chatHistory: ChatMessage[];
  onNavigateHome: () => void;
}

const LAYER_DEFINITIONS = [
  {
    num: 1,
    name: "Input Firewall",
    fullName: "L1: Pre-Retrieval Input Firewall",
    role: "Direct injection & secret extraction",
  },
  {
    num: 2,
    name: "Retriever Gate",
    fullName: "L2: Qdrant Hybrid Retriever & Namespace Guard",
    role: "RBAC namespace protection & hybrid search",
  },
  {
    num: 3,
    name: "Context Sanitizer",
    fullName: "L3: Zero-Trust Context Sanitizer & Consensus",
    role: "Heuristic scan & cross-chunk consensus",
  },
  {
    num: 4,
    name: "Nonce Sandbox",
    fullName: "L4: Cryptographic Nonce-Spotlighted Synthesizer",
    role: "Dynamic delimiter boundary isolation",
  },
  {
    num: 5,
    name: "Policy Auditor",
    fullName: "L5: Output Faithfulness & Citation Policy Auditor",
    role: "Citation provenance & safety compliance",
  },
];

export default function MetricsGraphTab({
  selectedMessage,
  onSelectMessage,
  chatHistory,
  onNavigateHome,
}: MetricsGraphTabProps) {
  const assistantMessages = chatHistory.filter((m) => m.sender === "assistant" && m.compareResult);
  const currentMsg = selectedMessage?.compareResult ? selectedMessage : assistantMessages[assistantMessages.length - 1] || null;

  const [activeLayerNum, setActiveLayerNum] = useState<number>(1);

  useEffect(() => {
    if (currentMsg?.stoppedLayer) {
      setActiveLayerNum(currentMsg.stoppedLayer);
    } else {
      setActiveLayerNum(1);
    }
  }, [currentMsg]);

  if (!currentMsg || !currentMsg.compareResult) {
    return (
      <div className="w-full max-w-xl mx-auto py-28 text-center space-y-4">
        <div className="w-12 h-12 rounded-full bg-white/[0.04] border border-white/10 mx-auto flex items-center justify-center text-stone-400">
          <Activity className="w-5 h-5 text-[#67e8f9]" />
        </div>
        <h3 className="text-xl font-serif text-white">No Telemetry Recorded Yet</h3>
        <p className="text-xs text-stone-400 max-w-sm mx-auto font-light leading-relaxed">
          Execute any inquiry or simulate a threat in the Home tab to inspect the 3D stacked acrylic layer breakdown.
        </p>
        <button
          onClick={onNavigateHome}
          className="bg-[#ff6b35] text-black font-semibold rounded-full px-5 py-2 text-xs shadow-md hover:opacity-95 transition-all inline-flex items-center space-x-1.5"
        >
          <span>Return to Home Studio</span>
          <ArrowUpRight className="w-3.5 h-3.5 stroke-[2.5]" />
        </button>
      </div>
    );
  }

  const result = currentMsg.compareResult;
  const telemetryList: LayerTelemetry[] = result.securerag.telemetry || [];
  const stoppedLayer = currentMsg.stoppedLayer;

  const activeTelemetry = telemetryList.find((t) => t.layer_number === activeLayerNum) || {
    layer_number: activeLayerNum,
    layer_name: LAYER_DEFINITIONS[activeLayerNum - 1]?.fullName || `Layer ${activeLayerNum}`,
    status: (stoppedLayer && activeLayerNum > stoppedLayer ? "SKIPPED" : "PASS") as any,
    latency_ms: 0.0,
    summary: stoppedLayer && activeLayerNum > stoppedLayer ? "Layer bypassed due to upstream security halt." : "Layer passed verification.",
    details: {},
  };

  return (
    <div className="w-full space-y-10 pb-16">
      {/* Top Editorial Header & Query Switcher */}
      <div className="flex flex-col md:flex-row items-start md:items-end justify-between gap-6 hairline-border-b pb-6">
        <div>
          <div className="flex items-center space-x-2 text-[10px] uppercase font-mono tracking-widest text-stone-400 mb-2">
            <span className="w-1.5 h-1.5 rounded-full bg-[#67e8f9] shadow-[0_0_8px_#67e8f9]" />
            <span>ZERO-TRUST RUNTIME INSPECTION</span>
          </div>
          <h1 className="text-3xl sm:text-4xl font-normal tracking-tight text-white leading-tight">
            Security,{" "}
            <span className="font-serif italic text-[#67e8f9] font-normal">
              at the speed of thought.
            </span>
          </h1>
          <p className="text-xs text-stone-400 font-light mt-1">
            Inspecting query: <span className="font-mono text-stone-200">"{result.query}"</span>
          </p>
        </div>

        {/* Right Query Selector Pill & Status */}
        <div className="flex items-center space-x-3 shrink-0">
          {assistantMessages.length > 1 && (
            <div className="relative">
              <select
                value={currentMsg.id}
                onChange={(e) => {
                  const target = assistantMessages.find((m) => m.id === e.target.value);
                  if (target) onSelectMessage(target);
                }}
                className="bg-white/[0.04] border border-white/10 text-xs text-stone-200 rounded-full px-4 py-2 pr-8 appearance-none focus:outline-none focus:border-white/20 cursor-pointer font-mono"
              >
                {assistantMessages.map((m, idx) => (
                  <option key={m.id} value={m.id} className="bg-[#070709] text-stone-200">
                    Turn #{idx + 1}: {m.isThreat ? "🛑 [Blocked] " : "✅ [Passed] "} {m.compareResult?.query.slice(0, 28)}...
                  </option>
                ))}
              </select>
              <ChevronDown className="w-3.5 h-3.5 text-stone-400 absolute right-3 top-2.5 pointer-events-none" />
            </div>
          )}

          <div
            className={`px-3.5 py-1.5 rounded-full text-xs font-medium border flex items-center space-x-1.5 ${
              currentMsg.isThreat
                ? "bg-[#ff6b35]/10 border-[#ff6b35]/40 text-[#ff6b35]"
                : "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
            }`}
          >
            {currentMsg.isThreat ? (
              <>
                <ShieldAlert className="w-3.5 h-3.5 text-[#ff6b35]" />
                <span>Halted at Layer {stoppedLayer}</span>
              </>
            ) : (
              <>
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                <span>All 5 Layers Cleared</span>
              </>
            )}
          </div>
        </div>
      </div>

      {/* 3D Stacked Translucent Acrylic Glass Slabs (Isometric Architecture) */}
      <div className="py-6">
        <div className="flex items-center justify-between mb-4">
          <span className="text-[10px] font-mono uppercase tracking-widest text-stone-500">
            3D ISOMETRIC ACRYLIC LAYER SLABS (CLICK TO AUDIT)
          </span>
          <span className="text-[11px] font-mono text-stone-400">
            Active: Layer {activeLayerNum}
          </span>
        </div>

        {/* Isometric 3D Slab Wrapper */}
        <div className="perspective-1600 py-6">
          <div
            className="grid grid-cols-1 sm:grid-cols-5 gap-4 transition-all duration-500"
            style={{
              transform: "rotateX(22deg) rotateY(-18deg) rotateZ(4deg)",
              transformStyle: "preserve-3d",
            }}
          >
            {LAYER_DEFINITIONS.map((def) => {
              const tel = telemetryList.find((t) => t.layer_number === def.num);
              const isBlockedHere = stoppedLayer === def.num || tel?.status === "BLOCKED";
              const isSkipped = tel?.status === "SKIPPED" || (stoppedLayer && def.num > stoppedLayer);
              const isPass = tel?.status === "PASS" && !isSkipped;
              const isSelected = activeLayerNum === def.num;

              let slabStyle = "bg-white/[0.04] border-white/10 text-stone-400";
              let edgeHighlight = "border-t border-l border-white/20";
              let statusPill = "CLEARED";

              if (isBlockedHere) {
                slabStyle =
                  "bg-[#ff6b35]/25 border-[#ff6b35] text-stone-100 shadow-[0_20px_45px_rgba(255,107,53,0.35)] -translate-y-4 scale-[1.05]";
                edgeHighlight = "border-t-2 border-l-2 border-[#ff6b35]";
                statusPill = "HALTED";
              } else if (isPass) {
                slabStyle =
                  "bg-[#38bdf8]/15 border-cyan-400/50 text-stone-100 shadow-[0_15px_35px_rgba(56,189,248,0.2)]";
                edgeHighlight = "border-t-2 border-l-2 border-cyan-300/70";
                statusPill = "PASSED";
              } else if (isSkipped) {
                slabStyle = "bg-white/[0.02] border-white/[0.05] text-stone-600 opacity-40";
                edgeHighlight = "border-t border-white/[0.08]";
                statusPill = "LOCKED";
              }

              return (
                <div
                  key={def.num}
                  onClick={() => setActiveLayerNum(def.num)}
                  className={`relative p-5 rounded-2xl backdrop-blur-xl transition-all duration-300 cursor-pointer border ${slabStyle} ${edgeHighlight} ${
                    isSelected ? "ring-2 ring-white/60 -translate-y-2" : "hover:-translate-y-1"
                  }`}
                  style={{
                    transformStyle: "preserve-3d",
                  }}
                >
                  {/* Glowing Top Slab Indicator */}
                  <div className="flex items-center justify-between mb-3 text-[10px] font-mono">
                    <span className="font-bold uppercase tracking-wider text-stone-300">
                      L{def.num}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded-full text-[9px] font-semibold tracking-wider ${
                        isBlockedHere
                          ? "bg-[#ff6b35] text-black"
                          : isPass
                          ? "bg-cyan-400/20 text-cyan-200 border border-cyan-400/30"
                          : "bg-stone-800 text-stone-500"
                      }`}
                    >
                      {statusPill}
                    </span>
                  </div>

                  <div className="font-medium text-xs text-white mb-1 tracking-tight">
                    {def.name}
                  </div>
                  <div className="text-[10px] text-stone-400 line-clamp-2 font-light leading-snug">
                    {def.role}
                  </div>

                  <div className="mt-4 pt-2 border-t border-white/[0.08] flex items-center justify-between text-[9px] font-mono text-stone-400">
                    <span>Latency</span>
                    <span className="text-stone-200">
                      {tel?.latency_ms !== undefined ? `${tel.latency_ms} ms` : "0 ms"}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Clean Borderless 3-Column Hairline Forensic Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 hairline-border-t pt-8">
        {/* Column 1: 01 / TRIGGER REASON */}
        <div className="space-y-3">
          <div className="flex items-center space-x-2 text-[10px] uppercase font-mono tracking-widest text-[#ff6b35]">
            <span>01 / TRIGGER REASON</span>
          </div>
          <h3 className="text-base font-normal text-white tracking-tight">
            {activeTelemetry.layer_name}
          </h3>
          <p className="text-xs text-stone-300 leading-relaxed font-light">
            {activeTelemetry.summary}
          </p>

          {activeTelemetry.details && Object.keys(activeTelemetry.details).length > 0 && (
            <div className="p-3.5 rounded-xl bg-white/[0.02] border border-white/[0.06] space-y-1.5 text-[11px] font-mono text-stone-400 mt-3">
              <span className="text-[9px] uppercase font-bold text-stone-500 block mb-1">
                Telemetry Log
              </span>
              {Object.entries(activeTelemetry.details).map(([k, v]) => (
                <div key={k} className="truncate">
                  <span className="text-stone-300">{k}:</span> {JSON.stringify(v)}
                </div>
              ))}
            </div>
          )}

          <div className="pt-2 text-[10px] font-mono text-stone-500 flex justify-between">
            <span>Execution Latency:</span>
            <span className="text-stone-300">{activeTelemetry.latency_ms} ms</span>
          </div>
        </div>

        {/* Column 2: 02 / HARM PREVENTED VS. BASELINE */}
        <div className="space-y-3 lg:border-l lg:border-white/[0.08] lg:pl-8">
          <div className="flex items-center space-x-2 text-[10px] uppercase font-mono tracking-widest text-[#67e8f9]">
            <span>02 / HARM PREVENTED VS. BASELINE</span>
          </div>
          <h3 className="text-base font-normal text-white tracking-tight">
            Damage Mitigation Guarantee
          </h3>
          <p className="text-xs text-stone-300 leading-relaxed font-light">
            {currentMsg.harmExplanation ||
              activeTelemetry.details?.harm_prevented ||
              "Zero-Trust boundaries preserved integrity, preventing prompt overrides or factual corruption."}
          </p>

          <div className="p-3.5 rounded-xl bg-white/[0.02] border border-white/[0.06] space-y-2 mt-3 text-xs">
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-stone-400">Baseline Naive RAG Status:</span>
              <span
                className={`font-semibold font-mono ${
                  result.baseline.compromised ? "text-[#ff6b35]" : "text-emerald-400"
                }`}
              >
                {result.baseline.compromised ? "Compromised" : "Benign"}
              </span>
            </div>
            <p className="text-[11px] text-stone-400 font-mono line-clamp-3 leading-relaxed">
              "{result.baseline.answer}"
            </p>
            <span className="text-[10px] text-stone-500 block font-mono">
              Mechanism: {result.baseline.compromise_reason}
            </span>
          </div>

          <div className="pt-2 text-[10px] font-mono text-stone-500 flex justify-between">
            <span>Baseline Latency:</span>
            <span className="text-stone-300">{result.baseline.latency_ms} ms</span>
          </div>
        </div>

        {/* Column 3: 03 / CONTEXT & CHUNK X-RAY */}
        <div className="space-y-3 lg:border-l lg:border-white/[0.08] lg:pl-8">
          <div className="flex items-center space-x-2 text-[10px] uppercase font-mono tracking-widest text-stone-400">
            <span>03 / CONTEXT & CHUNK X-RAY</span>
          </div>
          <div className="flex items-center justify-between">
            <h3 className="text-base font-normal text-white tracking-tight">
              Retrieved Vectors
            </h3>
            <span className="text-xs font-mono text-stone-400">
              {result.securerag.candidate_chunks?.length || 0} chunks
            </span>
          </div>

          <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
            {result.securerag.candidate_chunks && result.securerag.candidate_chunks.length > 0 ? (
              result.securerag.candidate_chunks.map((c: ChunkDetail) => (
                <div
                  key={c.chunk_id}
                  className="p-3 rounded-xl bg-white/[0.02] border border-white/[0.06] text-[11px] space-y-1"
                >
                  <div className="flex items-center justify-between font-mono">
                    <span className="font-semibold text-white">{c.chunk_id}</span>
                    <span
                      className={`text-[9px] px-1.5 py-0.5 rounded font-mono ${
                        c.is_quarantined
                          ? "bg-[#ff6b35]/20 text-[#ff6b35]"
                          : "bg-emerald-500/20 text-emerald-300"
                      }`}
                    >
                      {c.is_quarantined ? "Quarantined" : "Verified"}
                    </span>
                  </div>
                  <div className="text-[10px] text-stone-500 truncate">{c.doc_title}</div>
                  <p className="text-[11px] text-stone-300 line-clamp-2 font-light">
                    {c.text}
                  </p>
                </div>
              ))
            ) : (
              <div className="p-4 text-center text-xs text-stone-500 bg-white/[0.02] rounded-xl border border-white/[0.06] font-light">
                Conversational query bypassed vector database retrieval.
              </div>
            )}
          </div>

          <div className="pt-2 text-[10px] font-mono text-stone-500 flex justify-between">
            <span>Verified: {result.securerag.verified_chunks?.length || 0}</span>
            <span className="text-[#ff6b35]">Quarantined: {result.securerag.quarantined_chunks?.length || 0}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
