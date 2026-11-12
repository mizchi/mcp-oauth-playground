import { defineConfig } from "@playwright/test";
import base from "./playwright.config";

// Run exactly the same browser contracts against Hono's two Wrangler entry points.
process.env.MCP_E2E_ORIGIN = "http://localhost:8791";
process.env.MCP_E2E_GITHUB_ORIGIN = "http://localhost:8792";

export default defineConfig({
  ...base,
  use: { ...base.use, baseURL: "http://localhost:8791" },
  webServer: [
    {
      command: "pnpm dev:hono:local",
      url: "http://localhost:8791/.well-known/oauth-protected-resource/mcp",
      reuseExistingServer: false,
    },
    {
      command:
        "pnpm exec wrangler dev --cwd hono --config wrangler.jsonc --port 8792 --ip localhost --persist-to .wrangler/hono-e2e-github --var PUBLIC_ORIGIN:http://localhost:8792 --var ENABLE_DCR:true --var GITHUB_CLIENT_ID:e2e-client --var GITHUB_CLIENT_SECRET:e2e-secret",
      url: "http://localhost:8792/.well-known/oauth-protected-resource/mcp",
      reuseExistingServer: false,
    },
  ],
});
