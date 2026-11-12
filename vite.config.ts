import { defineConfig } from "vite-plus";
import { voidPlugin } from "void";
import { voidReact } from "@void/react/plugin";

const e2eRole = process.env.MCP_E2E_ROLE;

export default defineConfig({
  // Parallel test servers must not rewrite one another's dependency cache or local KV.
  cacheDir: e2eRole ? `.void/e2e/${e2eRole}/vite` : undefined,
  plugins: [voidPlugin(e2eRole ? { persistTo: `.void/e2e/${e2eRole}/state` } : {}), voidReact()],
  lint: {
    ignorePatterns: [
      ".void/**",
      ".frontend-review/**",
      "dist/**",
      "playwright-report/**",
      "test-results/**",
    ],
  },
  fmt: {
    ignorePatterns: [
      ".void/**",
      ".frontend-review/**",
      "dist/**",
      "playwright-report/**",
      "test-results/**",
      "pnpm-lock.yaml",
    ],
  },
});
