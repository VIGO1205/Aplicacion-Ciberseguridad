/** @type {import('tailwindcss').Config} */
const themed = (name, darkRgb) => `rgb(var(--color-${name}, ${darkRgb}) / <alpha-value>)`;

export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        white: themed("white", "255 255 255"),
        slate: {
          50: themed("slate-50", "248 250 252"),
          100: themed("slate-100", "241 245 249"),
          200: themed("slate-200", "226 232 240"),
          300: themed("slate-300", "203 213 225"),
          400: themed("slate-400", "148 163 184"),
          500: themed("slate-500", "100 116 139"),
          600: themed("slate-600", "71 85 105"),
          700: themed("slate-700", "51 65 85"),
          800: themed("slate-800", "30 41 59"),
          900: themed("slate-900", "15 23 42"),
          950: themed("slate-950", "2 6 23"),
        },
        cyan: {
          100: themed("cyan-100", "207 250 254"),
          200: themed("cyan-200", "165 243 252"),
          300: themed("cyan-300", "103 232 249"),
          400: themed("cyan-400", "34 211 238"),
          500: themed("cyan-500", "6 182 212"),
        },
        emerald: {
          100: themed("emerald-100", "209 250 229"),
          200: themed("emerald-200", "167 243 208"),
          300: themed("emerald-300", "110 231 183"),
          400: themed("emerald-400", "52 211 153"),
          950: themed("emerald-950", "2 44 34"),
        },
        rose: {
          300: themed("rose-300", "253 164 175"),
          400: themed("rose-400", "251 113 133"),
          500: themed("rose-500", "244 63 94"),
          950: themed("rose-950", "76 5 25"),
        },
        amber: {
          200: themed("amber-200", "253 230 138"),
          300: themed("amber-300", "252 211 77"),
          400: themed("amber-400", "251 191 36"),
        },
        orange: {
          300: themed("orange-300", "253 186 116"),
          400: themed("orange-400", "251 146 60"),
        },
        violet: {
          300: themed("violet-300", "196 181 253"),
          400: themed("violet-400", "167 139 250"),
          500: themed("violet-500", "139 92 246"),
        },
        sky: {
          300: themed("sky-300", "125 211 252"),
          400: themed("sky-400", "56 189 248"),
        },
        ink: {
          950: themed("ink-950", "5 11 22"),
          900: themed("ink-900", "8 17 31"),
          850: themed("ink-850", "11 23 40"),
          800: themed("ink-800", "15 31 51"),
          700: themed("ink-700", "23 43 67"),
        },
        accent: {
          50: "#ecfeff",
          300: "#67e8f9",
          400: "#22d3ee",
          500: "#06b6d4",
          600: "#0891b2",
        },
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Consolas", "monospace"],
      },
      boxShadow: {
        glow: "0 0 40px -12px rgba(34, 211, 238, 0.35)",
        card: "0 20px 45px -30px rgba(0, 0, 0, 0.9)",
      },
      keyframes: {
        "fade-up": {
          "0%": { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        "pulse-soft": {
          "0%, 100%": { opacity: "0.6" },
          "50%": { opacity: "1" },
        },
      },
      animation: {
        "fade-up": "fade-up 0.35s ease-out both",
        "pulse-soft": "pulse-soft 2.4s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
