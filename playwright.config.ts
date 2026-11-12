import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  testMatch: ["local-flow.spec.ts", "oauth.spec.ts"],
  fullyParallel: true,
  use: { baseURL: "http://localhost:5173", trace: "retain-on-failure" },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "mobile", use: { ...devices["iPhone 13"], defaultBrowserType: "chromium" } },
  ],
  webServer: [
    {
      command: "pnpm dev:local",
      url: "http://localhost:5173/.well-known/oauth-protected-resource/mcp",
      reuseExistingServer: false,
      env: {
        PUBLIC_ORIGIN: "http://localhost:5173",
        MCP_E2E_ROLE: "local",
        GITHUB_CLIENT_ID: "",
        GITHUB_CLIENT_SECRET: "",
        ALLOWED_GITHUB_USER_IDS: "",
      },
    },
    {
      command: "pnpm exec vp dev --host localhost --port 5174 --strictPort",
      url: "http://localhost:5174/.well-known/oauth-protected-resource/mcp",
      reuseExistingServer: false,
      env: {
        PUBLIC_ORIGIN: "http://localhost:5174",
        MCP_E2E_ROLE: "github",
        LOGIN_PROVIDER: "github",
        ENABLE_DCR: "true",
        GITHUB_CLIENT_ID: "e2e-client",
        GITHUB_CLIENT_SECRET: "e2e-secret",
        ALLOWED_GITHUB_USER_IDS: "123",
      },
    },
  ],
});
