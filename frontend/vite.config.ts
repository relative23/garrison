import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// A release archive carries the build as static/ next to the binary
// (xtask/src/release.rs), so production hosts never need Node.
export default defineConfig({
  base: "/admin/",
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
    // One CSS file and hashed asset names; the strict CSP allows no inline code.
    cssCodeSplit: false,
    assetsInlineLimit: 0,
    // prerender.mjs reads which files each view's chunk needs, then removes it.
    manifest: true,
  },
  server: {
    // `npm run dev` proxies the API to a locally running web service.
    proxy: { "/api": "http://127.0.0.1:8091" },
  },
  test: {
    environment: "jsdom",
    globals: true,
    include: ["tests/**/*.test.{ts,tsx}"],
    setupFiles: ["tests/setup.ts"],
    // Each test starts with the real fetch and timers again.
    unstubGlobals: true,
    restoreMocks: true,
    // `npm run coverage` fails when the tests cover less than this.
    coverage: {
      include: ["src/**/*.{ts,tsx}"],
      exclude: ["src/main.tsx", "src/api/schema.gen.ts", "src/**/*.d.ts"],
      thresholds: { statements: 95, branches: 90, functions: 95, lines: 95 },
    },
  },
});
