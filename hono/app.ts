import { Hono, type Handler } from "hono";
import { html } from "hono/html";
import { z } from "zod";
import type { PlaygroundEnv } from "../src/contracts";
import type { IdentityProvider } from "../src/identity-provider";
import { createPlayground } from "../src/playground";

// Wrangler bindings are explicit here; no generated types or framework env proxy.
export interface HonoBindings {
  OAUTH_KV: KVNamespace;
  AUTH_RATE_LIMITER: PlaygroundEnv["AUTH_RATE_LIMITER"];
  PUBLIC_ORIGIN: string;
  LOGIN_PROVIDER?: string;
  ENABLE_DCR?: string | boolean;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  ALLOWED_GITHUB_USER_IDS?: string;
}

const settingsSchema = z.object({
  PUBLIC_ORIGIN: z.url(),
  LOGIN_PROVIDER: z.enum(["github", "local"]).default("github"),
  ENABLE_DCR: z
    .union([z.boolean(), z.enum(["true", "false"]).transform((v) => v === "true")])
    .default(false),
  GITHUB_CLIENT_ID: z.string().optional(),
  GITHUB_CLIENT_SECRET: z.string().optional(),
  ALLOWED_GITHUB_USER_IDS: z.string().optional(),
});

export interface HonoEnv {
  Bindings: HonoBindings;
  Variables: { settings: PlaygroundEnv & { LOGIN_PROVIDER: "github" | "local" } };
}

export function createHonoApp(
  options: {
    localIdentityProvider?: (env: PlaygroundEnv) => IdentityProvider;
  } = {},
) {
  const app = new Hono<HonoEnv>();

  app.use("*", async (c, next) => {
    const parsed = settingsSchema.safeParse(c.env);
    if (!parsed.success || new URL(parsed.data.PUBLIC_ORIGIN).origin !== parsed.data.PUBLIC_ORIGIN)
      return c.text("Invalid worker configuration", 503);
    c.set("settings", {
      ...parsed.data,
      OAUTH_KV: c.env.OAUTH_KV,
      AUTH_RATE_LIMITER: c.env.AUTH_RATE_LIMITER,
    });
    await next();
  });

  app.get("/", (c) => {
    const { PUBLIC_ORIGIN: origin, LOGIN_PROVIDER: provider } = c.get("settings");
    c.header("Cache-Control", "no-store");
    c.header(
      "Content-Security-Policy",
      "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    );
    c.header("X-Content-Type-Options", "nosniff");
    return c.html(
      html`<!doctype html>
        <html lang="ja">
          <head>
            <meta charset="utf-8" />
            <meta name="viewport" content="width=device-width, initial-scale=1" />
            <title>MCP OAuth / Hono</title>
          </head>
          <body>
            <main>
              <h1>MCP OAuth / Hono</h1>
              <p>MCP クライアントの接続 URL: <code>${origin}/mcp</code></p>
              <p>ログイン先: ${provider === "local" ? "ローカル認可サーバー" : "GitHub"}</p>
              <p>クライアントから接続して権限に同意し、ログイン後に whoami を実行してください。</p>
              <p>
                <a href="/.well-known/oauth-protected-resource/mcp">Protected Resource Metadata</a>
              </p>
              <p>
                <a href="/.well-known/oauth-authorization-server">Authorization Server Metadata</a>
              </p>
            </main>
          </body>
        </html>`,
    );
  });

  const oauth: Handler<HonoEnv> = (c) => {
    const settings = c.get("settings");
    if (settings.LOGIN_PROVIDER === "local" && !options.localIdentityProvider)
      return c.text("Local login is available only in the local entry point", 503);
    const provider =
      settings.LOGIN_PROVIDER === "local" ? options.localIdentityProvider!(settings) : undefined;
    // Native Request, bindings and ExecutionContext go directly to the shared OAuth/MCP core.
    return createPlayground(settings, provider).fetch(
      c.req.raw,
      c.executionCtx as ExecutionContext,
    );
  };

  app.all("/authorize", oauth); // GET: consent; POST: approve/deny and begin login.
  app.all("/oauth/*", oauth); // Callback, code/refresh exchange, revocation, optional DCR.
  app.all("/mcp", oauth); // Bearer validation and whoami.
  app.all("/.well-known/oauth-authorization-server", oauth);
  app.all("/.well-known/oauth-protected-resource", oauth);
  app.all("/.well-known/oauth-protected-resource/*", oauth);
  return app;
}
