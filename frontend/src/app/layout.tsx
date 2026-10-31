import type { Metadata } from "next";
import { Plus_Jakarta_Sans, Instrument_Serif } from "next/font/google";
import "./globals.css";

const sans = Plus_Jakarta_Sans({
  subsets: ["latin"],
  variable: "--font-sans",
  weight: ["300", "400", "500", "600", "700", "800"],
  display: "swap",
});

const serif = Instrument_Serif({
  subsets: ["latin"],
  variable: "--font-serif",
  weight: "400",
  style: ["normal", "italic"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "SecureRAG | Autonomous Zero-Trust Multi-Agent Defense",
  description: "Luxury Editorial 3D Defense Architecture against Indirect Injection, Namespace Traversal & Factual Poisoning",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={`dark ${sans.variable} ${serif.variable}`}>
      <body className="min-h-screen bg-[#070709] text-stone-100 antialiased font-sans selection:bg-[#ff6b35]/25 selection:text-[#ff8f65]">
        {children}
      </body>
    </html>
  );
}
