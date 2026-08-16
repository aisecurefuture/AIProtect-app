import type { Config } from "tailwindcss";
export default {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  darkMode: "media",
  theme: {
    extend: {
      colors: {
        // Sampled from the supplied artwork. See docs/brand/BRAND.md for
        // which of these may carry TEXT: cyan and sky are logo colours only
        // (1.74:1 and 2.67:1 on white -- they fail every text threshold).
        brand: {
          cyan: "#00D8F0",
          sky: "#00A8F0",
          blue: "#0078F0",
          indigo: "#2010F0",
          navy: "#0D1B3E",
        },
      },
    },
  },
} satisfies Config;
