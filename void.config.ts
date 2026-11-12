import { defineConfig } from "void/config";

export default defineConfig({
  target: "cloudflare",
  routing: { typedRoutes: true },
  inference: { bindings: { kv: "OAUTH_KV", db: false } },
  worker: {
    compatibility_date: "2026-11-05",
    compatibility_flags: ["nodejs_compat", "global_fetch_strictly_public"],
  },
  cloudflare: {
    name: "mcp-oauth-playground",
    ratelimits: [
      {
        name: "AUTH_RATE_LIMITER",
        namespace_id: "1001",
        simple: { limit: 60, period: 60 },
      },
    ],
  },
  head: {
    htmlAttrs: { lang: "ja" },
    meta: [{ name: "viewport", content: "width=device-width, initial-scale=1" }],
  },
});
