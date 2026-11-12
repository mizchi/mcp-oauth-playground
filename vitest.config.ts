import { defineConfig } from "vite-plus";
import { cloudflareTest } from "@cloudflare/vitest-plugin";

export default defineConfig({
  plugins: [
    cloudflareTest({
      miniflare: {
        compatibilityDate: "2026-11-05",
        compatibilityFlags: ["nodejs_compat", "global_fetch_strictly_public"],
        kvNamespaces: ["OAUTH_KV"],
      },
    }),
  ],
  test: { include: ["tests/**/*.test.ts"] },
});
