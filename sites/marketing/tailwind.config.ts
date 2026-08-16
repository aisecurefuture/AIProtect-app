import type { Config } from "tailwindcss";
export default {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // From docs/brand/BRAND.md. cyan and sky are LOGO colours: 1.74:1 and
        // 2.67:1 on white, so they never carry text on a light background.
        brand: { cyan: "#00D8F0", sky: "#00A8F0", blue: "#0078F0",
                 indigo: "#2010F0", navy: "#0D1B3E" },
      },
    },
  },
} satisfies Config;
