/**
 * Hono / Cloudflare Workers: GitHub login -> OAuth 2.1 + PKCE -> MCP whoami.
 * Repository-local imports are unnecessary. Pair with client.ts; Node.js 24+.
 *
 * In a fresh directory: pnpm init && pnpm pkg set type=module
 * pnpm add hono@4.13.16 @cloudflare/workers-oauth-provider@1.2.4 @modelcontextprotocol/server@2.4.0 zod@4.6.7
 * pnpm add -D wrangler@4.158.0 typescript@7.0.2 @cloudflare/workers-types@5.20261104.1
 * Save this configuration as wrangler.jsonc beside server.ts:
 * {
 *   "name": "hono-mcp-oauth", "main": "server.ts",
 *   "compatibility_date": "2026-11-05",
 *   "compatibility_flags": ["nodejs_compat", "global_fetch_strictly_public"],
 *   "vars": { "PUBLIC_ORIGIN": "http://localhost:8791", "ENABLE_DCR": "true", "ALLOWED_GITHUB_USER_IDS": "73962" },
 *   "kv_namespaces": [{ "binding": "OAUTH_KV", "id": "00000000000000000000000000000000" }],
 *   "ratelimits": [{ "name": "AUTH_RATE_LIMITER", "namespace_id": "1004", "simple": { "limit": 60, "period": 60 } }]
 * }
 * Put GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET in .dev.vars (never in this file).
 * GitHub OAuth App callback: http://localhost:8791/oauth/callback
 * pnpm exec wrangler dev --port 8791
 *
 * Before deployment: configure your HTTPS PUBLIC_ORIGIN, real KV namespace ID,
 * GitHub callback/secrets and an account-unique rate-limit namespace ID.
 * DCR is opt-in; use false unless required. Rate limits are approximate per location.
 * Access tokens: 10 min; refresh grants: 7 days, only with offline_access consent.
 * KV consent/state transactions aren't globally atomic. Strict concurrency needs
 * stronger storage. Revoking GitHub access does not automatically revoke MCP grants.
 * MCP revision: 2026-07-28. Sources:
 * https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
 * https://github.com/cloudflare/workers-oauth-provider
 */
import { Hono, type Handler } from "hono";
import { isIP } from "node:net";
import { z } from "zod";
import {
  AuthorizationError,
  CimdFetchError,
  OAuthAuthorizationServer,
  OAuthError,
  OAuthResourceServer,
  insufficientScope,
  type AuthRequest,
  type ConsentDescription,
} from "@cloudflare/workers-oauth-provider";
import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";

export interface Bindings {
  OAUTH_KV: KVNamespace;
  AUTH_RATE_LIMITER: Pick<RateLimit, "limit">;
  PUBLIC_ORIGIN: string;
  ENABLE_DCR?: boolean | string;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  ALLOWED_GITHUB_USER_IDS?: string;
}
const settingsSchema = z.object({
  PUBLIC_ORIGIN: z.url(),
  ENABLE_DCR: z
    .union([z.boolean(), z.enum(["true", "false"]).transform((v) => v === "true")])
    .default(false),
  GITHUB_CLIENT_ID: z.string().optional(),
  GITHUB_CLIENT_SECRET: z.string().optional(),
  ALLOWED_GITHUB_USER_IDS: z.string().optional(),
});
type Settings = Omit<Bindings, "ENABLE_DCR"> & { ENABLE_DCR: boolean };
type Identity = { id: string; login: string; name: string };
type AppEnv = {
  Bindings: Bindings;
  Variables: {
    settings: Settings;
    request: Request;
    as: OAuthAuthorizationServer<Settings>;
  };
};
const scopes = ["mcp:read", "offline_access"];
const supported = (values: string[]) => values.every((value) => scopes.includes(value));
const allowed = (env: Settings, identity: Identity) =>
  /^[1-9]\d*$/.test(identity.id) &&
  (env.ALLOWED_GITHUB_USER_IDS ?? "")
    .split(",")
    .map((id) => id.trim())
    .includes(identity.id);
const errorResponse = (error: string, status = 400, description = error) =>
  Response.json(
    { error, error_description: description },
    { status, headers: { "Cache-Control": "no-store" } },
  );
const oauthError = (request: AuthRequest, error: string) => {
  const url = new URL(request.redirectUri);
  for (const [key, value] of Object.entries({ error, state: request.state, iss: request.issuer! }))
    url.searchParams.set(key, value);
  return url.href;
};
const s256 = async (value: string) => {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
};
const escape = (value: string) =>
  value.replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!,
  );

function consentPage(details: ConsentDescription, handle: string) {
  return `<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>MCP の認可</title></head><body>
    <h1>${escape(details.clientName)} にアクセスを許可しますか？</h1>
    <p>${details.clientDomain ? escape(details.clientDomain) : "クライアント名は自己申告です。"}</p>
    <p>リダイレクト先: ${escape(details.redirectHost)}</p>
    ${details.redirectIsLoopback ? "<p>お使いのコンピューターのアプリへの認可です。そのアプリから開始したことを確認してください。</p>" : ""}
    <p>mcp:read: プロフィールの参照。offline_access: 再ログインせずに接続を更新。</p>
    <ul>${details.scope.map((value) => `<li>${escape(value)}</li>`).join("")}</ul>
    <form method="post" action="/authorize"><input type="hidden" name="handle" value="${escape(handle)}">
    <button name="decision" value="approve">許可して GitHub へ</button><button name="decision" value="deny">拒否</button></form>
    </body></html>`;
}

// Count actual streamed bytes before formData()/JSON parsing, including without Content-Length.
async function boundedBody(request: Request, contentType: string) {
  if (request.headers.get("Content-Type")?.split(";")[0].trim().toLowerCase() !== contentType)
    return errorResponse("invalid_request", 400, "Unsupported Content-Type");
  if (Number(request.headers.get("Content-Length")) > 16_384)
    return errorResponse("invalid_request", 413, "Request body is too large");
  if (!request.body) return request;
  const reader = request.body.getReader();
  const bytes = new Uint8Array(16_384);
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (size + value.byteLength > bytes.length) {
        void reader.cancel().catch(() => {});
        return errorResponse("invalid_request", 413, "Request body is too large");
      }
      bytes.set(value, size);
      size += value.byteLength;
    }
  } catch {
    return errorResponse("invalid_request");
  } finally {
    reader.releaseLock();
  }
  return new Request(request, { method: request.method, body: bytes.slice(0, size) });
}

/** Optional transport injection is for tests; the published default uses real GitHub APIs. */
export function createServer(options: { fetchGitHub?: typeof fetch } = {}) {
  const app = new Hono<AppEnv>();
  async function githubIdentity(env: Settings, code: string, verifier: string): Promise<Identity> {
    const json = async (url: string, init: RequestInit): Promise<unknown> => {
      const response = await (options.fetchGitHub ?? fetch)(url, {
        ...init,
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok) throw new Error("GitHub unavailable");
      return response.json();
    };
    const token = z.object({ access_token: z.string().min(1), token_type: z.string() }).parse(
      await json("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          client_id: env.GITHUB_CLIENT_ID!,
          client_secret: env.GITHUB_CLIENT_SECRET!,
          redirect_uri: `${env.PUBLIC_ORIGIN}/oauth/callback`,
          code,
          code_verifier: verifier,
        }),
      }),
    );
    const user = z
      .object({
        id: z.number().int().positive(),
        login: z.string().min(1),
        name: z.string().nullable(),
      })
      .parse(
        await json("https://api.github.com/user", {
          headers: {
            Authorization: `Bearer ${token.access_token}`,
            Accept: "application/vnd.github+json",
            "User-Agent": "hono-mcp-oauth-snippet",
          },
        }),
      );
    // Only the identity survives. Never store or forward GitHub's access token to MCP.
    return { id: String(user.id), login: user.login, name: user.name ?? user.login };
  }

  app.onError((error, c) => {
    if (error instanceof AuthorizationError && error.redirectTo)
      return c.redirect(error.redirectTo, 302);
    if (error instanceof AuthorizationError || error instanceof CimdFetchError)
      return errorResponse("invalid_request");
    // Never echo upstream bodies, authorization codes or tokens in error responses/logs.
    return errorResponse("server_error", 500);
  });
  app.use("*", async (c, next) => {
    const parsed = settingsSchema.safeParse(c.env);
    if (!parsed.success || new URL(parsed.data.PUBLIC_ORIGIN).origin !== parsed.data.PUBLIC_ORIGIN)
      return errorResponse("temporarily_unavailable", 503);
    const env: Settings = { ...c.env, ...parsed.data };
    const url = new URL(c.req.url);
    if (url.origin !== env.PUBLIC_ORIGIN) return errorResponse("invalid_request", 403);
    if (url.pathname === "/mcp") {
      if (c.req.header("Origin") && c.req.header("Origin") !== env.PUBLIC_ORIGIN)
        return errorResponse("invalid_request", 403);
      if (url.searchParams.has("access_token")) return errorResponse("invalid_request");
    }
    let request = c.req.raw;
    if (
      [
        "/authorize",
        "/oauth/token",
        "/oauth/callback",
        ...(env.ENABLE_DCR ? ["/oauth/register"] : []),
      ].includes(url.pathname)
    ) {
      try {
        // Cloudflare overwrites CF-Connecting-IP at ingress; don't use X-Forwarded-For.
        const { success } = await env.AUTH_RATE_LIMITER.limit({
          key: `${env.PUBLIC_ORIGIN}:${url.pathname}:${c.req.header("CF-Connecting-IP") ?? "anonymous"}`,
        });
        if (!success) {
          const r = errorResponse("temporarily_unavailable", 429);
          r.headers.set("Retry-After", "60");
          return r;
        }
      } catch {
        return errorResponse("temporarily_unavailable", 503);
      }
      if (request.method === "POST" && url.pathname !== "/oauth/callback") {
        const bounded = await boundedBody(
          request,
          url.pathname === "/oauth/register"
            ? "application/json"
            : "application/x-www-form-urlencoded",
        );
        if (bounded instanceof Response) return bounded;
        request = bounded;
      }
    }
    c.set("settings", env);
    c.set("request", request);
    c.set(
      "as",
      new OAuthAuthorizationServer<Settings>({
        issuer: env.PUBLIC_ORIGIN,
        resources: [`${env.PUBLIC_ORIGIN}/mcp`],
        scopesSupported: scopes,
        clientIdMetadataDocumentEnabled: true,
        ...(env.ENABLE_DCR ? { clientRegistrationEndpoint: "/oauth/register" } : {}),
        accessTokenTTL: 600,
        refreshTokenTTL: 604800,
        tokenExchangeCallback: ({ grantType, props, scope }) => {
          if (!allowed(env, props) || !supported(scope))
            throw new OAuthError("invalid_grant", {
              description: "Authorization is no longer allowed",
            }); // Also revokes this grant.
          if (grantType === "authorization_code" && !scope.includes("offline_access"))
            return { refreshTokenTTL: 0 };
        },
      }),
    );
    await next();
  });

  app.get("/", (c) => c.text(`MCP endpoint: ${c.get("settings").PUBLIC_ORIGIN}/mcp`));
  app.get("/authorize", async (c) => {
    const request = c.get("request"),
      oauth = c.get("as").getOAuthApi(c.get("settings"));
    const clientId = new URL(request.url).searchParams.get("client_id");
    if (clientId && URL.canParse(clientId)) {
      const url = new URL(clientId),
        host = url.hostname.replace(/^\[|\]$/g, "");
      if (
        ["http:", "https:"].includes(url.protocol) &&
        (url.protocol !== "https:" ||
          isIP(host) ||
          host === "localhost" ||
          host.endsWith(".localhost"))
      )
        return errorResponse("invalid_request");
    }
    const auth = await oauth.parseAuthRequest(request); // Validates client and exact redirect URI before any redirect.
    if (!supported(auth.scope)) return c.redirect(oauthError(auth, "invalid_scope"), 302);
    if (
      !new URL(request.url).searchParams.has("resource") ||
      !auth.codeChallenge ||
      auth.codeChallengeMethod !== "S256"
    )
      return c.redirect(oauthError(auth, "invalid_request"), 302);
    const description = await oauth.describeConsent(auth),
      consent = await oauth.beginConsent(auth);
    consent.headers.set("Content-Type", "text/html; charset=utf-8");
    return new Response(consentPage(description, consent.handle), { headers: consent.headers });
  });
  app.post("/authorize", async (c) => {
    const env = c.get("settings"),
      request = c.get("request"),
      oauth = c.get("as").getOAuthApi(env);
    if (request.headers.get("Origin") !== env.PUBLIC_ORIGIN)
      return errorResponse("invalid_request");
    const form = await request.formData(),
      handle = String(form.get("handle") ?? "");
    if (form.get("decision") === "deny")
      return new Response(null, {
        status: 302,
        headers: (await oauth.denyConsent(request, handle)).headers,
      });
    if (form.get("decision") !== "approve") return errorResponse("invalid_request");
    if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET || !env.ALLOWED_GITHUB_USER_IDS?.trim())
      return errorResponse("temporarily_unavailable", 503);
    const approved = await oauth.approveConsent(request, handle);
    if (!supported(approved.request.scope))
      return c.redirect(oauthError(approved.request, "invalid_scope"), 302);
    const verifier = crypto.randomUUID() + crypto.randomUUID();
    const upstream = await oauth.beginUpstream(approved.request, {
      data: { verifier },
      headers: approved.headers,
    });
    const url = new URL("https://github.com/login/oauth/authorize");
    url.search = new URLSearchParams({
      client_id: env.GITHUB_CLIENT_ID,
      redirect_uri: `${env.PUBLIC_ORIGIN}/oauth/callback`,
      state: upstream.state,
      code_challenge: await s256(verifier),
      code_challenge_method: "S256",
      scope: "",
    }).toString();
    upstream.headers.set("Location", url.href);
    return new Response(null, { status: 302, headers: upstream.headers });
  });
  app.get("/oauth/callback", async (c) => {
    const env = c.get("settings"),
      oauth = c.get("as").getOAuthApi(env);
    const { request, data, headers } = await oauth.finishUpstream<{ verifier: string }>(
      c.get("request"),
    );
    const url = new URL(c.req.url);
    const deny = (error: string) => {
      headers.set("Location", oauthError(request, error));
      return new Response(null, { status: 302, headers });
    };
    if (url.searchParams.has("error") || !url.searchParams.get("code"))
      return deny("access_denied");
    if (!supported(request.scope)) return deny("invalid_scope");
    let identity: Identity;
    try {
      identity = await githubIdentity(env, url.searchParams.get("code")!, data.verifier);
    } catch {
      return deny("temporarily_unavailable");
    }
    if (!allowed(env, identity)) return deny("access_denied");
    const completed = await oauth.completeAuthorization({
      request,
      userId: identity.id,
      metadata: { login: identity.login },
      props: identity,
      scope: request.scope,
    });
    headers.set("Location", completed.redirectTo);
    return new Response(null, { status: 302, headers });
  });
  app.post("/oauth/token", async (c) => {
    const request = c.get("request"),
      form = await request.clone().formData();
    if (form.has("grant_type") && !form.get("resource")) return errorResponse("invalid_target");
    return c.get("as").fetch(request, c.get("settings"), c.executionCtx as ExecutionContext);
  });
  const authorization: Handler<AppEnv> = (c) =>
    c.get("as").fetch(c.get("request"), c.get("settings"), c.executionCtx as ExecutionContext);
  app.all("/oauth/*", authorization);
  app.all("/.well-known/oauth-authorization-server", authorization);

  const resource: Handler<AppEnv> = (c) => {
    const env = c.get("settings"),
      as = c.get("as");
    const server = new OAuthResourceServer<Settings, Identity>({
      resourceMetadata: {
        resource: `${env.PUBLIC_ORIGIN}/mcp`,
        authorization_servers: [env.PUBLIC_ORIGIN],
      },
      requiredScopes: ["mcp:read"],
      validateToken: (bindings) => async (audience, token) => {
        const valid = await as.validateToken<Identity>(audience, token, bindings);
        return valid && allowed(env, valid.props) && supported(valid.scope ?? []) ? valid : null;
      },
      handler: {
        fetch(request, _env, ctx) {
          if (!ctx.auth.scope.includes("mcp:read"))
            return insufficientScope(ctx.auth, ["mcp:read"]);
          return createMcpHandler(() => {
            const mcp = new McpServer({ name: "hono-mcp-oauth-snippet", version: "1.0.0" });
            mcp.registerTool(
              "whoami",
              {
                inputSchema: z.object({}),
                annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
              },
              () => ({ content: [{ type: "text", text: JSON.stringify(ctx.props) }] }),
            );
            return mcp;
          }).fetch(request); // New MCP server per request: identities never share a session.
        },
      },
    });
    return server.fetch(c.get("request"), env, c.executionCtx as ExecutionContext);
  };
  app.all("/mcp", resource);
  app.all("/.well-known/oauth-protected-resource", resource);
  app.all("/.well-known/oauth-protected-resource/*", resource);
  return app;
}
export default createServer();
