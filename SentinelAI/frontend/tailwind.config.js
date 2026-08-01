/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/pages/**/*.{js,jsx,ts,tsx}",
    "./src/components/**/*.{js,jsx,ts,tsx}",
    "./src/hooks/**/*.{js,jsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        sentinel: {
          bg:       "#070B14",
          surface:  "#0D1424",
          card:     "#0A0E1A",
          border:   "#1E2C4A",
          muted:    "#1A2035",
          blue:     "#00D4FF",
          navy:     "#0050FF",
          red:      "#FF3B3B",
          orange:   "#FF8C00",
          yellow:   "#FFD700",
          green:    "#00C851",
          purple:   "#9B59B6",
          text:     "#E2E8FF",
          subtext:  "#6B7DB3",
          dim:      "#4A5578",
          faint:    "#2A3555",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
      },
      fontSize: {
        "2xs": "0.65rem",
      },
      animation: {
        pulse:    "pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        spin:     "spin 1s linear infinite",
        glow:     "glow 2s ease-in-out infinite",
        "slide-in":"slideIn 0.2s ease-out",
        "fade-in": "fadeIn 0.3s ease-out",
        "bounce-x":"bounceX 1s infinite",
      },
      keyframes: {
        glow: {
          "0%,100%": { boxShadow: "0 0 5px #00D4FF44" },
          "50%":     { boxShadow: "0 0 20px #00D4FF88, 0 0 40px #00D4FF44" },
        },
        slideIn: {
          from: { transform: "translateY(-8px)", opacity: "0" },
          to:   { transform: "translateY(0)",    opacity: "1" },
        },
        fadeIn: {
          from: { opacity: "0" },
          to:   { opacity: "1" },
        },
        bounceX: {
          "0%,100%": { transform: "translateX(0)" },
          "50%":     { transform: "translateX(4px)" },
        },
      },
      boxShadow: {
        "sentinel-glow": "0 0 20px rgba(0,212,255,0.2)",
        "sentinel-red":  "0 0 20px rgba(255,59,59,0.3)",
        "sentinel-card": "0 4px 24px rgba(0,0,0,0.4)",
      },
      borderRadius: {
        "2xl": "1rem",
        "3xl": "1.5rem",
      },
      backdropBlur: {
        xs: "2px",
      },
    },
  },
  plugins: [],
};
