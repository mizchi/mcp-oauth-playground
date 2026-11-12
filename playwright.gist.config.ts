import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  testMatch: "gist.spec.ts",
  fullyParallel: true,
  use: { baseURL: "http://127.0.0.1:3457", trace: "retain-on-failure" },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "mobile", use: { ...devices["iPhone 13"], defaultBrowserType: "chromium" } },
  ],
  webServer: [
    {
      command:
        "pnpm exec wrangler dev --cwd tests/fixtures --config gist-worker.jsonc --port 8793 --ip localhost --persist-to ../../.wrangler/gist-e2e",
      url: "http://localhost:8793/.well-known/oauth-protected-resource/mcp",
      reuseExistingServer: false,
    },
    {
      command: "node snippets/mcp-oauth/client.ts",
      env: {
        MCP_RESOURCE: "http://localhost:8793/mcp",
        MCP_CLIENT_PORT: "3457",
        MCP_REGISTER: "true",
      },
      url: "http://127.0.0.1:3457/",
      reuseExistingServer: false,
    },
  ],
});
