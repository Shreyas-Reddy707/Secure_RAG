import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#090d16",
        surface: "#111827",
        card: "#1f2937",
        border: "#374151",
        primary: "#3b82f6",
        accent: "#8b5cf6",
        danger: "#ef4444",
        success: "#10b981",
        warning: "#f59e0b",
      },
    },
  },
  plugins: [],
};
export default config;

