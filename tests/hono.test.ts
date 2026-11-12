import { env } from "cloudflare:workers";
import { createExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vite-plus/test";
import { createHonoApp, type HonoBindings } from "../hono/app";
import localApp from "../hono/local";

const origin = "http://localhost:8791";

function setup(overrides: Partial<HonoBindings> = {}, local = false) {
  const bindings: HonoBindings = {
    OAUTH_KV: env.OAUTH_KV,
    AUTH_RATE_LIMITER: { limit: async () => ({ success: true }) },
    PUBLIC_ORIGIN: origin,
    LOGIN_PROVIDER: "github",
    ENABLE_DCR: "false",
    ALLOWED_GITHUB_USER_IDS: "73962",
    ...overrides,
  };
  const app = local ? localApp : createHonoApp();
  const request = (path: string, init?: RequestInit) =>
    app.fetch(new Request(new URL(path, origin), init), bindings, createExecutionContext());
  return { request };
}

describe("Hono worker adapter", () => {
  it("serves connection instructions as plain HTML", async () => {
    const { request } = setup();
    const response = await request("/");
    expect(response.status).toBe(200);
    const html = await response.text();
    expect(html).toContain("MCP OAuth / Hono");
    expect(html).toContain(`${origin}/mcp`);
    expect(html).not.toContain("<script");
    expect(response.headers.get("Content-Security-Policy")).toContain("frame-ancestors 'none'");
  });

  it("preserves discovery and the path-specific Bearer challenge", async () => {
    const { request } = setup();
    const denied = await request("/mcp", { method: "POST", body: "{}" });
    expect(denied.status).toBe(401);
    expect(denied.headers.get("WWW-Authenticate")).toContain(
      `${origin}/.well-known/oauth-protected-resource/mcp`,
    );
    expect(await (await request("/.well-known/oauth-authorization-server")).json()).toMatchObject({
      issuer: origin,
      code_challenge_methods_supported: ["S256"],
    });
    expect(await (await request("/.well-known/oauth-protected-resource/mcp")).json()).toMatchObject(
      {
        resource: `${origin}/mcp`,
        authorization_servers: [origin],
      },
    );
  });

  it("parses string false without exposing DCR", async () => {
    const { request } = setup();
    const response = await request("/.well-known/oauth-authorization-server");
    expect(await response.json()).not.toHaveProperty("registration_endpoint");
    expect((await request("/oauth/register", { method: "POST" })).status).toBe(404);
  });

  it("enables DCR only for true", async () => {
    const { request } = setup({ ENABLE_DCR: "true" });
    const response = await request("/oauth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        redirect_uris: [`${origin}/callback`],
        token_endpoint_auth_method: "none",
      }),
    });
    expect(response.status).toBe(201);
  });

  it.each(["yes", "1"])("rejects invalid boolean config %s", async (value) => {
    const { request } = setup({ ENABLE_DCR: value });
    expect((await request("/mcp")).status).toBe(503);
  });

  it("does not expose local login in the production entry point", async () => {
    const { request } = setup({ LOGIN_PROVIDER: "local" });
    expect((await request("/authorize")).status).toBe(503);
    expect((await request("/local-idp/authorize")).status).toBe(404);
    expect((await request("/.well-known/oauth-authorization-server/local-idp")).status).toBe(404);
  });

  it("shares the real local issuer only in the local entry point", async () => {
    const { request } = setup({ LOGIN_PROVIDER: "local" }, true);
    const response = await request("/.well-known/oauth-authorization-server/local-idp");
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ issuer: `${origin}/local-idp` });
  });

  it("keeps local routes unavailable when the local entry uses github mode", async () => {
    const { request } = setup({}, true);
    expect((await request("/local-idp/authorize")).status).toBe(404);
  });

  it("preserves Origin and query-token rejection", async () => {
    const { request } = setup();
    expect(
      (await request("/mcp", { headers: { Origin: "https://attacker.example" } })).status,
    ).toBe(403);
    expect((await request("/mcp?access_token=stolen")).status).toBe(400);
  });

  it("preserves body format and streamed size limits", async () => {
    const { request } = setup();
    const response = await request("/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_request" });
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(16_385));
        controller.close();
      },
    });
    expect(
      (
        await request("/oauth/token", {
          method: "POST",
          body,
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
        })
      ).status,
    ).toBe(413);
  });

  it("enforces the limiter on OAuth and local identity routes", async () => {
    const { request } = setup(
      { LOGIN_PROVIDER: "local", AUTH_RATE_LIMITER: { limit: async () => ({ success: false }) } },
      true,
    );
    for (const path of ["/authorize", "/oauth/token", "/local-idp/authorize"])
      expect((await request(path)).status).toBe(429);
  });
});
