import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./lib/**/*.{js,ts,jsx,tsx,mdx}",
    "./mdx-components.tsx",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ["var(--font-inter)", "system-ui", "sans-serif"],
        mono: ["var(--font-jetbrains-mono)", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      // Same cobalt / sky / slate system as the architecture diagram, so the
      // diagram sits natively on the page instead of fighting it.
      colors: {
        cobalt: {
          DEFAULT: "#2563eb",
          deep: "#172554",
          bright: "#60a5fa",
        },
        sky: {
          brand: "#0891b2",
        },
      },
    },
  },
  plugins: [],
};

export default config;
