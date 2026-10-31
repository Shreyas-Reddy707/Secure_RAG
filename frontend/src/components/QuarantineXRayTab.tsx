import { useEffect, useState } from "react";
import { fetchCorpusStats } from "@/lib/api";
import { CorpusStats, ChunkDetail } from "@/lib/types";
import { FileText, Database } from "lucide-react";

export default function QuarantineXRayTab() {
  const [stats, setStats] = useState<CorpusStats | null>(null);
  const [selectedChunk, setSelectedChunk] = useState<ChunkDetail | null>(null);

  useEffect(() => {
    fetchCorpusStats()
      .then((data) => {
        setStats(data);
        if (data.chunks.length > 0) setSelectedChunk(data.chunks[0]);
      })
      .catch(console.error);
  }, []);

  if (!stats) return <div className="text-center py-12 text-slate-400">Loading vector database corpus...</div>;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Corpus List */}
      <div className="bg-surface border border-border rounded-xl p-4 shadow-lg lg:col-span-1 space-y-3 max-h-[750px] overflow-y-auto">
        <div className="flex items-center justify-between pb-2 border-b border-border">
          <div className="flex items-center space-x-2">
            <Database className="w-4 h-4 text-blue-400" />
            <h3 className="font-bold text-white text-sm">Qdrant Indexed Corpus ({stats.total_chunks})</h3>
          </div>
          <span className="text-xs text-slate-400">{stats.poisoned_chunks} poisoned</span>
        </div>
        <div className="space-y-2">
          {stats.chunks.map((c) => {
            const isSelected = selectedChunk?.chunk_id === c.chunk_id;
            const isPoisoned = c.ground_truth_is_poisoned;
            return (
              <div
                key={c.chunk_id}
                onClick={() => setSelectedChunk(c)}
                className={`p-3 rounded-lg border text-xs cursor-pointer transition-all ${
                  isSelected ? "bg-blue-600/20 border-blue-500" : "bg-card/40 border-border hover:bg-card"
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-mono font-bold text-slate-200">{c.chunk_id}</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-medium ${isPoisoned ? "bg-red-500/20 text-red-400 border border-red-500/30" : "bg-green-500/20 text-green-400"}`}>
                    {isPoisoned ? "Adversarial Ground Truth" : "Clean Code/Note"}
                  </span>
                </div>
                <div className="text-slate-400 truncate mb-1">{c.doc_title}</div>
                <div className="text-slate-300 line-clamp-2">{c.text}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Detailed X-Ray Inspector */}
      <div className="bg-surface border border-border rounded-xl p-6 shadow-lg lg:col-span-2 flex flex-col justify-between">
        {selectedChunk ? (
          <div className="space-y-6">
            <div className="flex items-center justify-between pb-4 border-b border-border">
              <div>
                <h3 className="font-bold text-white text-base flex items-center space-x-2">
                  <FileText className="w-5 h-5 text-blue-400" />
                  <span>{selectedChunk.doc_title}</span>
                </h3>
                <span className="text-xs text-slate-400 font-mono">Chunk ID: {selectedChunk.chunk_id} | Doc ID: {selectedChunk.doc_id}</span>
              </div>
              <span className={`px-3 py-1 rounded-full text-xs font-semibold ${selectedChunk.ground_truth_is_poisoned ? "bg-red-500/20 text-red-400 border border-red-500/30" : "bg-green-500/20 text-green-400"}`}>
                {selectedChunk.ground_truth_is_poisoned ? "⚠️ Poisoned Payload" : "🛡️ Clean Document"}
              </span>
            </div>

            <div>
              <span className="text-xs font-semibold text-slate-400 block mb-2">Raw Chunk Content:</span>
              <div className="bg-background border border-border rounded-lg p-4 font-mono text-sm text-slate-200 leading-relaxed">
                {selectedChunk.text}
              </div>
            </div>

            <div className="grid grid-cols-3 gap-4">
              <div className="bg-card/50 border border-border rounded-lg p-3 text-center">
                <span className="text-xs text-slate-400 block mb-1">Attack Category</span>
                <span className="text-xs font-bold text-amber-400">{selectedChunk.attack_category || "NONE"}</span>
              </div>
              <div className="bg-card/50 border border-border rounded-lg p-3 text-center">
                <span className="text-xs text-slate-400 block mb-1">Ground Truth Status</span>
                <span className={`text-xs font-bold ${selectedChunk.ground_truth_is_poisoned ? "text-red-400" : "text-green-400"}`}>
                  {selectedChunk.ground_truth_is_poisoned ? "Malicious" : "Benign"}
                </span>
              </div>
              <div className="bg-card/50 border border-border rounded-lg p-3 text-center">
                <span className="text-xs text-slate-400 block mb-1">Target Defense</span>
                <span className="text-xs font-bold text-blue-400">Layer 3 Sanitizer</span>
              </div>
            </div>
          </div>
        ) : (
          <div className="text-center py-24 text-slate-400">Select a chunk from the corpus list to inspect its security metadata.</div>
        )}
      </div>
    </div>
  );
}

