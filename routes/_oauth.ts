import { defineHandler } from "void";
import { env } from "void/env";
import { createPlayground } from "../src/playground";

export const handleOAuth = defineHandler(async (c) => {
  if (!import.meta.env.DEV && env.LOGIN_PROVIDER === "local") {
    return new Response("Local login is available only during development", { status: 503 });
  }
  const provider =
    import.meta.env.DEV && env.LOGIN_PROVIDER === "local"
      ? (await import("../dev/local-identity-provider")).createLocalIdentityProvider(
          env.PUBLIC_ORIGIN,
        )
      : undefined;
  // Read schema defaults explicitly: enumerating the env proxy only returns raw binding keys.
  const app = createPlayground(
    {
      OAUTH_KV: c.env.OAUTH_KV as KVNamespace,
      AUTH_RATE_LIMITER: c.env.AUTH_RATE_LIMITER as RateLimit,
      PUBLIC_ORIGIN: env.PUBLIC_ORIGIN,
      GITHUB_CLIENT_ID: env.GITHUB_CLIENT_ID,
      GITHUB_CLIENT_SECRET: env.GITHUB_CLIENT_SECRET,
      ALLOWED_GITHUB_USER_IDS: env.ALLOWED_GITHUB_USER_IDS,
      ENABLE_DCR: env.ENABLE_DCR,
    },
    provider,
  );
  return app.fetch(c.req.raw, c.executionCtx as ExecutionContext);
});
