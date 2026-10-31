"use client";

import { useState } from "react";
import Navbar from "@/components/Navbar";
import HomeLandingTab from "@/components/HomeLandingTab";
import HomeChatTab from "@/components/HomeChatTab";
import MetricsGraphTab from "@/components/MetricsGraphTab";
import BenchmarkDashboardTab from "@/components/BenchmarkDashboardTab";
import { ChatMessage, LiveSessionStats } from "@/lib/types";

export default function Home() {
  const [activeTab, setActiveTab] = useState<"home" | "chat" | "metrics" | "benchmark">("home");
  const [chatHistory, setChatHistory] = useState<ChatMessage[]>([]);
  const [selectedMessageForMetrics, setSelectedMessageForMetrics] = useState<ChatMessage | null>(null);
  const [pendingScenarioQuery, setPendingScenarioQuery] = useState<string | null>(null);
  const [liveSessionStats, setLiveSessionStats] = useState<LiveSessionStats>({
    totalQueries: 0,
    passedCount: 0,
    blockedL1: 0,
    blockedL2: 0,
    blockedL3: 0,
    blockedL4: 0,
    blockedL5: 0,
  });

  const handleRunScenarioFromHome = (query: string) => {
    setPendingScenarioQuery(query);
    setActiveTab("chat");
  };

  return (
    <div className="relative min-h-screen w-full bg-[#070709] text-stone-100 flex flex-col font-sans selection:bg-[#ff6b35]/25 selection:text-[#ff8f65] overflow-x-hidden">
      {/* Studio Ambient Radial Lighting (Soft Amber-Orange + Ice-Cyan) */}
      <div className="fixed -top-48 -left-48 w-[650px] h-[650px] bg-[radial-gradient(ellipse_at_center,_rgba(255,107,53,0.12),_transparent_70%)] pointer-events-none -z-10" />
      <div className="fixed top-1/4 -right-48 w-[700px] h-[700px] bg-[radial-gradient(ellipse_at_center,_rgba(56,189,248,0.10),_transparent_70%)] pointer-events-none -z-10" />
      <div className="fixed -bottom-48 left-1/3 w-[600px] h-[600px] bg-[radial-gradient(ellipse_at_center,_rgba(255,107,53,0.06),_transparent_70%)] pointer-events-none -z-10" />

      {/* Minimalist Studio Top Navbar (4 Tabs) */}
      <Navbar activeTab={activeTab} setActiveTab={(tab) => setActiveTab(tab as any)} />

      {/* Main Full-Bleed Content Area */}
      <main className="flex-1 w-full px-5 sm:px-8 lg:px-14 py-4 transition-all duration-300">
        {activeTab === "home" && (
          <HomeLandingTab
            onNavigateTab={(tab) => setActiveTab(tab)}
            onRunScenario={handleRunScenarioFromHome}
          />
        )}

        {activeTab === "chat" && (
          <HomeChatTab
            chatHistory={chatHistory}
            setChatHistory={setChatHistory}
            setSelectedMessageForMetrics={setSelectedMessageForMetrics}
            setActiveTab={setActiveTab}
            setLiveSessionStats={setLiveSessionStats}
            pendingQuery={pendingScenarioQuery}
            clearPendingQuery={() => setPendingScenarioQuery(null)}
          />
        )}

        {activeTab === "metrics" && (
          <MetricsGraphTab
            selectedMessage={selectedMessageForMetrics}
            onSelectMessage={setSelectedMessageForMetrics}
            chatHistory={chatHistory}
            onNavigateHome={() => setActiveTab("chat")}
          />
        )}

        {activeTab === "benchmark" && (
          <BenchmarkDashboardTab
            chatHistory={chatHistory}
            liveSessionStats={liveSessionStats}
            onSelectMessage={setSelectedMessageForMetrics}
            setActiveTab={setActiveTab}
          />
        )}
      </main>
    </div>
  );
}
