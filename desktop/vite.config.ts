import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import path from "node:path";

export default defineConfig({
  root: import.meta.dirname,
  plugins: [react()],
  clearScreen: false,
  build: {
    outDir: path.resolve(import.meta.dirname, "../desktop-dist"),
    // scripts/clean-dist.mjs empties desktop-dist first (npm run desktop:build) and
    // fails if anything survives. Vite's own emptying uses Node's recursive
    // removal, which on Windows silently removes nothing under a non-ASCII path.
    emptyOutDir: false,
    sourcemap: false,
    target: "es2022",
  },
  server: {
    host: "127.0.0.1",
    port: 1420,
    strictPort: true,
  },
  test: {
    environment: "jsdom",
    setupFiles: "./src/test-setup.ts",
    css: true,
    testTimeout: 30_000,
  },
});
