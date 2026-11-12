/**
 * Hono / Node.js 24+: public MCP OAuth client with a loopback callback and PKCE S256.
 * Pair with server.ts; no repository-local imports and no client secret.
 *
 * In a fresh directory: pnpm init && pnpm pkg set type=module
 * pnpm add hono@4.13.16 @hono/node-server@2.1.6 zod@4.6.7
 * MCP_RESOURCE=http://localhost:8791/mcp MCP_REGISTER=true node client.ts
 * Open http://127.0.0.1:3456/ in your browser, then approve GitHub login.
 * A successful callback calls whoami, refreshes, calls whoami again and revokes
 * its grant. Tokens remain in memory and are never put in the page or stdout.
 *
 * Optional: MCP_CLIENT_PORT=3457; MCP_CLIENT_ID=pre-registered-public-client-id.
 * Pre-registration takes precedence over explicit DCR (MCP_REGISTER=true).
 * An HTTPS CIMD URL can also be used as MCP_CLIENT_ID when its metadata includes
 * this client's exact loopback redirect URI. This example does not host a CIMD.
 * For an AS on another origin, explicitly set MCP_AUTH_ORIGINS=https://auth.example.com.
 * The default only trusts the MCP resource origin. Redirects aren't followed.
 * This educational client targets canonical resource URLs and MCP 2026-07-28.
 * https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
 */
import { Hono } from "hono";
import { html } from "hono/html";
import { getCookie, setCookie } from "hono/cookie";
import { serve } from "@hono/node-server";
import { createHash, randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";
import { z } from "zod";

interface ClientOptions {
  resource: string;
  origin: string;
  clientId?: string;
  register?: boolean;
  authOrigins?: string[];
  fetch?: typeof fetch;
  now?: () => number;
}
const metadataSchema = z.object({
  issuer: z.string(),
  authorization_endpoint: z.string(),
  token_endpoint: z.string(),
  registration_endpoint: z.string().optional(),
  revocation_endpoint: z.string().optional(),
  code_challenge_methods_supported: z.array(z.string()),
  authorization_response_iss_parameter_supported: z.boolean().optional(),
});
const tokenSchema = z.object({
  access_token: z.string().min(1),
  token_type: z.string().refine((v) => v.toLowerCase() === "bearer"),
  refresh_token: z.string().min(1).optional(),
  scope: z.string().optional(),
  resource: z.string().optional(),
});
type Metadata = z.infer<typeof metadataSchema>;
type Tokens = z.infer<typeof tokenSchema>;
const secret = () => randomBytes(32).toString("base64url");
const challenge = (value: string) => createHash("sha256").update(value).digest("base64url");

function safeUrl(value: string) {
  const url = new URL(value);
  if (
    url.username ||
    url.password ||
    url.hash ||
    (url.protocol !== "https:" &&
      !(url.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)))
  )
    throw new Error("HTTPS or loopback HTTP URL required");
  return url;
}

export function createClientApp(options: ClientOptions) {
  const origin = safeUrl(options.origin);
  if (
    origin.origin !== options.origin ||
    !["127.0.0.1", "localhost", "[::1]"].includes(origin.hostname)
  )
    throw new Error("The callback must use an explicit loopback origin");
  const resource = safeUrl(options.resource).href;
  const redirectUri = `${origin.origin}/callback`;
  const trusted = new Set([
    new URL(resource).origin,
    ...(options.authOrigins ?? []).map((value) => safeUrl(value).origin),
  ]);
  const checked = (value: string) => {
    const url = safeUrl(value);
    if (!trusted.has(url.origin)) throw new Error("Untrusted OAuth endpoint origin");
    return url;
  };
  const now = options.now ?? Date.now;
  type Pending = {
    binding: string;
    verifier: string;
    metadata: Metadata;
    clientId: string;
    expires: number;
  };
  const pending = new Map<string, Pending>();
  let connecting = 0;

  async function request(url: string, init: RequestInit = {}) {
    checked(url); // Validate before sending credentials; never trust endpoint strings blindly.
    const response = await (options.fetch ?? fetch)(url, {
      ...init,
      redirect: "manual",
      signal: AbortSignal.timeout(10_000),
    });
    const reader = response.body?.getReader();
    const parts: Uint8Array[] = [];
    let size = 0;
    if (reader) {
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > 65_536) {
            void reader.cancel().catch(() => {});
            throw new Error("Response too large");
          }
          parts.push(value);
        }
      } finally {
        reader.releaseLock();
      }
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const part of parts) {
      bytes.set(part, offset);
      offset += part.byteLength;
    }
    const text = new TextDecoder().decode(bytes);
    return { response, data: text ? (JSON.parse(text) as unknown) : undefined };
  }

  async function discover() {
    const unauthenticated = await request(resource, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    if (unauthenticated.response.status !== 401) throw new Error("Expected Bearer challenge");
    const metadataUrl =
      unauthenticated.response.headers
        .get("WWW-Authenticate")
        ?.match(/\bresource_metadata="([^"]+)"/i)?.[1] ??
      new URL(`/.well-known/oauth-protected-resource${new URL(resource).pathname}`, resource).href;
    const pr = await request(metadataUrl);
    const protectedResource = z
      .object({ resource: z.string(), authorization_servers: z.array(z.string()).min(1).max(8) })
      .parse(pr.data);
    if (pr.response.status !== 200 || protectedResource.resource !== resource)
      throw new Error("Resource metadata mismatch");
    const issuer = protectedResource.authorization_servers[0];
    const issuerUrl = checked(issuer),
      path = issuerUrl.pathname === "/" ? "" : issuerUrl.pathname.replace(/\/$/, "");
    const auth = await request(
      new URL(`/.well-known/oauth-authorization-server${path}`, issuerUrl).href,
    );
    const metadata = metadataSchema.parse(auth.data);
    if (
      auth.response.status !== 200 ||
      metadata.issuer !== issuer ||
      !metadata.code_challenge_methods_supported.includes("S256")
    )
      throw new Error("Issuer or PKCE metadata mismatch");
    for (const endpoint of [
      metadata.authorization_endpoint,
      metadata.token_endpoint,
      metadata.registration_endpoint,
      metadata.revocation_endpoint,
    ])
      if (endpoint) checked(endpoint);
    if (!metadata.revocation_endpoint)
      throw new Error("This demonstration requires revocation support");
    return metadata;
  }

  async function token(metadata: Metadata, parameters: Record<string, string>): Promise<Tokens> {
    const result = await request(metadata.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(parameters),
    });
    if (result.response.status !== 200) throw new Error("Token exchange failed");
    const tokens = tokenSchema.parse(result.data);
    if (
      (tokens.resource && tokens.resource !== resource) ||
      (tokens.scope && !tokens.scope.split(" ").includes("mcp:read"))
    )
      throw new Error("Token resource or scope mismatch");
    return tokens;
  }
  async function whoami(accessToken: string) {
    const result = await request(resource, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/call",
        "Mcp-Name": "whoami",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: "whoami",
          arguments: {},
          _meta: {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
          },
        },
      }),
    });
    const rpc = z
      .object({
        jsonrpc: z.literal("2.0"),
        id: z.literal(1),
        result: z.object({
          isError: z.boolean().optional(),
          content: z.array(z.object({ type: z.string(), text: z.string().optional() })),
        }),
      })
      .parse(result.data);
    if (result.response.status !== 200 || rpc.result.isError) throw new Error("MCP call failed");
    return rpc.result.content;
  }

  const app = new Hono();
  app.onError((_error, c) =>
    c.text("OAuth/MCP flow failed. No credential details are displayed.", 502),
  );
  app.use("*", async (c, next) => {
    if (new URL(c.req.url).origin !== origin.origin) return c.text("Invalid host", 403);
    c.header("Cache-Control", "no-store");
    c.header("Referrer-Policy", "same-origin");
    c.header("X-Content-Type-Options", "nosniff");
    c.header(
      "Content-Security-Policy",
      "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    );
    for (const [state, flow] of pending) if (flow.expires <= now()) pending.delete(state);
    await next();
  });
  app.get("/", (c) =>
    c.html(
      html`<!doctype html>
        <html lang="ja">
          <head>
            <meta charset="utf-8" />
            <meta name="viewport" content="width=device-width,initial-scale=1" />
            <title>MCP OAuth Client</title>
          </head>
          <body>
            <h1>MCP OAuth Client</h1>
            <p>接続先: ${resource}</p>
            <p>ログイン後に whoami、トークン更新、失効を順番に実行します。</p>
            <form method="post" action="/connect"><button>接続して whoami を試す</button></form>
          </body>
        </html>`,
    ),
  );
  app.post("/connect", async (c) => {
    if (c.req.header("Origin") !== origin.origin) return c.text("Invalid origin", 403);
    if (pending.size + connecting >= 16) return c.text("Too many pending authorizations", 429);
    connecting++;
    try {
      const metadata = await discover();
      let clientId = options.clientId;
      if (!clientId) {
        if (!options.register || !metadata.registration_endpoint)
          throw new Error("Use a public client ID or explicitly opt in to DCR");
        const registered = await request(metadata.registration_endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            client_name: "Hono MCP OAuth Client",
            redirect_uris: [redirectUri],
            token_endpoint_auth_method: "none",
            application_type: "native",
            grant_types: ["authorization_code", "refresh_token"],
            response_types: ["code"],
          }),
        });
        if (registered.response.status !== 201) throw new Error("Client registration failed");
        clientId = z.object({ client_id: z.string().min(1) }).parse(registered.data).client_id;
      }
      const state = secret(),
        verifier = secret(),
        binding = secret();
      pending.set(state, { metadata, clientId, verifier, binding, expires: now() + 600_000 });
      setCookie(c, `mcp-client-${state}`, binding, {
        httpOnly: true,
        sameSite: "Lax",
        secure: origin.protocol === "https:",
        path: "/",
        maxAge: 600,
      });
      const url = new URL(metadata.authorization_endpoint);
      url.search = new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: "code",
        resource,
        scope: "mcp:read offline_access",
        state,
        code_challenge: challenge(verifier),
        code_challenge_method: "S256",
      }).toString();
      return c.redirect(url.href, 302);
    } finally {
      connecting--;
    }
  });
  app.get("/callback", async (c) => {
    c.header("Referrer-Policy", "no-referrer");
    const params = new URL(c.req.url).searchParams;
    const state = params.get("state") ?? "",
      flow = pending.get(state);
    if (
      params.getAll("state").length !== 1 ||
      !flow ||
      getCookie(c, `mcp-client-${state}`) !== flow.binding ||
      params.getAll("iss").length > 1 ||
      (flow.metadata.authorization_response_iss_parameter_supported && !params.has("iss")) ||
      (params.has("iss") && params.get("iss") !== flow.metadata.issuer)
    )
      return c.text("Invalid OAuth callback", 400);
    pending.delete(state); // Consume before any await, so duplicate callbacks cannot exchange twice.
    setCookie(c, `mcp-client-${state}`, "", {
      path: "/",
      maxAge: 0,
      httpOnly: true,
      sameSite: "Lax",
    });
    if (params.has("error")) return c.text("Authorization denied", 400);
    if (params.getAll("code").length !== 1 || !params.get("code"))
      return c.text("Missing authorization code", 400);
    let tokens: Tokens | undefined;
    let result: Awaited<ReturnType<typeof whoami>>;
    let refreshed = false;
    let revoked = false;
    try {
      tokens = await token(flow.metadata, {
        grant_type: "authorization_code",
        client_id: flow.clientId,
        redirect_uri: redirectUri,
        code: params.get("code")!,
        code_verifier: flow.verifier,
        resource,
      });
      result = await whoami(tokens.access_token);
      if (tokens.refresh_token) {
        tokens = await token(flow.metadata, {
          grant_type: "refresh_token",
          client_id: flow.clientId,
          refresh_token: tokens.refresh_token,
          resource,
        });
        refreshed = true;
        result = await whoami(tokens.access_token);
      }
    } finally {
      if (tokens) {
        // Cleanup must not replace an earlier protocol error.
        revoked = await request(flow.metadata.revocation_endpoint!, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            client_id: flow.clientId,
            token: tokens.refresh_token ?? tokens.access_token,
          }),
        }).then(
          ({ response }) => response.status === 200,
          () => false,
        );
      }
    }
    if (!revoked)
      throw new Error("Grant cleanup failed; revoke the dedicated test client manually");
    return c.json({ result, refreshed, revoked });
  });
  return app;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.MCP_CLIENT_PORT ?? "3456");
  if (!Number.isInteger(port) || port < 1 || port > 65_535)
    throw new Error("Invalid MCP_CLIENT_PORT");
  const origin = `http://127.0.0.1:${port}`;
  const app = createClientApp({
    origin,
    resource: process.env.MCP_RESOURCE ?? "http://localhost:8791/mcp",
    clientId: process.env.MCP_CLIENT_ID,
    register: process.env.MCP_REGISTER === "true",
    authOrigins: process.env.MCP_AUTH_ORIGINS?.split(",")
      .map((v) => v.trim())
      .filter(Boolean),
  });
  const server = serve({ fetch: app.fetch, hostname: "127.0.0.1", port }, () =>
    console.log(`Open ${origin}/`),
  );
  for (const signal of ["SIGINT", "SIGTERM"] as const) process.once(signal, () => server.close());
}
