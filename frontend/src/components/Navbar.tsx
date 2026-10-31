import { ArrowUpRight } from "lucide-react";

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

export default function Navbar({ activeTab, setActiveTab }: NavbarProps) {
  const tabs = [
    { id: "home", label: "Home" },
    { id: "chat", label: "AI Chat" },
    { id: "metrics", label: "Metrics & Trace" },
    { id: "benchmark", label: "Benchmark & Ablation" },
  ];

  return (
    <header className="sticky top-0 z-50 w-full px-5 sm:px-8 lg:px-14 py-3.5 bg-[#070709]/80 backdrop-blur-md border-b border-white/[0.06]">
      <div className="w-full flex items-center justify-between">
        {/* Left: Minimalist Bold Wordmark with Glowing Dot */}
        <div
          className="flex items-center space-x-2 cursor-pointer group select-none"
          onClick={() => setActiveTab("home")}
        >
          <span className="text-sm font-extrabold tracking-wider text-white">
            SECURERAG
          </span>
          <span className="w-1.5 h-1.5 rounded-full bg-[#ff6b35] shadow-[0_0_8px_#ff6b35]" />
        </div>

        {/* Center: 4 Clean Borderless Navigation Tabs */}
        <nav className="flex items-center space-x-5 sm:space-x-8">
          {tabs.map((t) => {
            const isActive = activeTab === t.id;
            return (
              <button
                key={t.id}
                onClick={() => setActiveTab(t.id)}
                className={`group relative text-xs tracking-wide transition-all duration-200 py-1 flex items-center space-x-1.5 ${
                  isActive
                    ? "text-white font-medium"
                    : "text-stone-400 hover:text-stone-200 font-normal"
                }`}
              >
                <span>{t.label}</span>
                {isActive ? (
                  <span className="w-1 h-1 rounded-full bg-[#ff6b35] shadow-[0_0_6px_#ff6b35]" />
                ) : (
                  <span className="w-1 h-1 rounded-full bg-transparent group-hover:bg-stone-600 transition-colors" />
                )}
              </button>
            );
          })}
        </nav>

        {/* Right: Sleek Solid Pill Badge */}
        <div className="flex items-center space-x-3">
          <button
            onClick={() => setActiveTab("chat")}
            className="inline-flex items-center space-x-1.5 bg-[#ff6b35] hover:opacity-90 text-black font-semibold rounded-full px-4 py-1.5 text-[11px] shadow-[0_2px_12px_rgba(255,107,53,0.3)] transition-all"
          >
            <span>Zero-Trust Active</span>
            <ArrowUpRight className="w-3 h-3 text-black stroke-[2.5]" />
          </button>
        </div>
      </div>
    </header>
  );
}
