import { env } from "cloudflare:workers";
import { createExecutionContext } from "cloudflare:test";
import { describe, expect, it, vi } from "vite-plus/test";
import { createPlayground as createSharedPlayground } from "../src/playground";
import { createServer } from "../snippets/mcp-oauth/server";
import type { PlaygroundEnv } from "../src/contracts";

describe.each([
  { name: "shared core", createPlayground: createSharedPlayground },
  {
    name: "standalone gist server",
    createPlayground: (bindings: PlaygroundEnv) => {
      const app = createServer();
      return {
        fetch: (request: Request, ctx: ExecutionContext) => app.fetch(request, bindings, ctx),
      };
    },
  },
])("$name", ({ createPlayground, name: suiteName }) => {
  const origin = "https://mcp.example.com";
  const resource = `${origin}/mcp`;
  const verifier = "v".repeat(64);
  const cookie = (r: Response) =>
    r.headers
      .getSetCookie()
      .map((v) => v.split(";")[0])
      .join("; ");

  async function setup(overrides: Partial<PlaygroundEnv> = {}) {
    const bindings: PlaygroundEnv = {
      OAUTH_KV: env.OAUTH_KV as KVNamespace,
      AUTH_RATE_LIMITER: { limit: async () => ({ success: true }) },
      PUBLIC_ORIGIN: origin,
      GITHUB_CLIENT_ID: "github-client",
      GITHUB_CLIENT_SECRET: "github-secret",
      ALLOWED_GITHUB_USER_IDS: "123",
      ENABLE_DCR: true,
      ...overrides,
    };
    const app = createPlayground(bindings);
    const request = (path: string, init?: RequestInit) =>
      app.fetch(new Request(new URL(path, origin), init), createExecutionContext());
    const registration = await request("/oauth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_name: "<script>alert(1)</script>",
        redirect_uris: ["http://localhost:3456/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        application_type: "native",
      }),
    });
    expect(registration.status).toBe(201);
    const { client_id: clientId } = (await registration.json()) as { client_id: string };
    const hash = new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
    );
    const challenge = btoa(String.fromCharCode(...hash))
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replaceAll("=", "");
    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: "http://localhost:3456/callback",
      response_type: "code",
      scope: "mcp:read offline_access",
      state: "client-state",
      resource,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    return { app, request, params, clientId, bindings };
  }

  async function consent(f: Awaited<ReturnType<typeof setup>>) {
    const page = await f.request(`/authorize?${f.params}`);
    expect(page.status).toBe(200);
    const html = await page.text();
    const handle = html.match(/name="handle" value="([^"]+)"/)?.[1];
    expect(handle).toBeTruthy();
    const approved = await f.request("/authorize", {
      method: "POST",
      headers: { Cookie: cookie(page), Origin: origin },
      body: new URLSearchParams({ handle: handle!, decision: "approve" }),
    });
    expect(approved.status).toBe(302);
    const upstream = new URL(approved.headers.get("Location")!);
    expect(upstream.origin).toBe("https://github.com");
    expect(upstream.searchParams.get("code_challenge_method")).toBe("S256");
    return { page, html, handle: handle!, approved, upstream };
  }

  async function login(
    f: Awaited<ReturnType<typeof setup>>,
    loginName = "mizchi",
    id = loginName === "mizchi" ? 123 : 456,
  ) {
    const flow = await consent(f);
    const mock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      if (String(input) === "https://github.com/login/oauth/access_token")
        return Response.json({ access_token: "github-upstream-token", token_type: "bearer" });
      if (String(input) === "https://api.github.com/user")
        return Response.json({ id, login: loginName, name: "Test User" });
      throw new Error(`Unexpected fetch: ${input}`);
    });
    try {
      return await f.request(
        `/oauth/callback?code=github-code&state=${flow.upstream.searchParams.get("state")}`,
        { headers: { Cookie: cookie(flow.approved) } },
      );
    } finally {
      mock.mockRestore();
    }
  }

  async function issueToken(f: Awaited<ReturnType<typeof setup>>) {
    const callback = await login(f);
    expect(callback.status).toBe(302);
    const redirect = new URL(callback.headers.get("Location")!);
    expect(redirect.searchParams.get("iss")).toBe(origin);
    expect(redirect.searchParams.get("state")).toBe("client-state");
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: redirect.searchParams.get("code")!,
      client_id: f.clientId,
      redirect_uri: f.params.get("redirect_uri")!,
      code_verifier: verifier,
      resource,
    });
    const exchanged = await f.request("/oauth/token", { method: "POST", body });
    expect(exchanged.status).toBe(200);
    const value = (await exchanged.json()) as {
      access_token: string;
      refresh_token: string;
      expires_in: number;
    };
    return { value, body };
  }

  describe("MCP OAuth security regressions", () => {
    it("rejects access and refresh after policy removal, and revokes the grant", async () => {
      const f = await setup();
      const { value } = await issueToken(f);
      const restricted = createPlayground({ ...f.bindings, ALLOWED_GITHUB_USER_IDS: "456" });
      const request = (path: string, init?: RequestInit) =>
        restricted.fetch(new Request(new URL(path, origin), init), createExecutionContext());
      expect(
        (
          await request("/mcp", {
            headers: { Authorization: `Bearer ${value.access_token}` },
          })
        ).status,
      ).toBe(401);
      const refreshed = await request("/oauth/token", {
        method: "POST",
        body: new URLSearchParams({
          grant_type: "refresh_token",
          client_id: f.clientId,
          refresh_token: value.refresh_token,
          resource,
        }),
      });
      expect(refreshed.status).toBe(400);
      expect(await refreshed.json()).toMatchObject({ error: "invalid_grant" });
      // Re-allowing the account must not resurrect the revoked grant.
      expect(
        (
          await f.request("/mcp", {
            headers: { Authorization: `Bearer ${value.access_token}` },
          })
        ).status,
      ).toBe(401);
    });

    it("re-checks policy between login and authorization-code exchange", async () => {
      const f = await setup();
      const callback = await login(f);
      const code = new URL(callback.headers.get("Location")!).searchParams.get("code")!;
      const restricted = createPlayground({ ...f.bindings, ALLOWED_GITHUB_USER_IDS: "456" });
      const response = await restricted.fetch(
        new Request(`${origin}/oauth/token`, {
          method: "POST",
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code,
            client_id: f.clientId,
            redirect_uri: f.params.get("redirect_uri")!,
            code_verifier: verifier,
            resource,
          }),
        }),
        createExecutionContext(),
      );
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({ error: "invalid_grant" });
    });

    it("allows a renamed account by numeric ID", async () => {
      const f = await setup();
      const callback = await login(f, "renamed-user", 123);
      expect(new URL(callback.headers.get("Location")!).searchParams.has("code")).toBe(true);
    });

    it("denies a reused login name with a different numeric ID", async () => {
      const f = await setup();
      const callback = await login(f, "mizchi", 456);
      expect(new URL(callback.headers.get("Location")!).searchParams.get("error")).toBe(
        "access_denied",
      );
    });

    it("rejects unknown scopes before displaying consent", async () => {
      const f = await setup();
      f.params.set("scope", "mcp:read mcp:admin offline_access");
      const response = await f.request(`/authorize?${f.params}`);
      expect(response.status).toBe(302);
      const redirect = new URL(response.headers.get("Location")!);
      expect(redirect.searchParams.get("error")).toBe("invalid_scope");
      expect(redirect.searchParams.get("state")).toBe("client-state");
      expect(redirect.searchParams.get("iss")).toBe(origin);
      expect(await response.text()).not.toContain('name="handle"');
    });

    it("returns a safe 400 for an unsupported token body type", async () => {
      const f = await setup();
      const response = await f.request("/oauth/token", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({ error: "invalid_request" });
      expect(response.headers.get("Cache-Control")).toBe("no-store");
    });

    it.each(["/oauth/token", "/oauth/register", "/authorize"])(
      "bounds actual body bytes at %s",
      async (path) => {
        const f = await setup();
        // No Content-Length: declared length checks alone do not bound a streamed request.
        const bytes = new TextEncoder().encode("x".repeat(16_385));
        const body = new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(bytes.subarray(0, 8192));
            controller.enqueue(bytes.subarray(8192));
            controller.close();
          },
        });
        const response = await f.request(path, {
          method: "POST",
          body,
          headers: {
            Origin: origin,
            "Content-Type":
              path === "/oauth/register" ? "application/json" : "application/x-www-form-urlencoded",
          },
        });
        expect(response.status).toBe(413);
      },
    );

    it("rate-limits before CIMD fetch and ignores caller-selected keys", async () => {
      const f = await setup();
      const limit = vi.fn().mockResolvedValue({ success: false });
      Object.assign(f.bindings, { AUTH_RATE_LIMITER: { limit } });
      f.params.set("client_id", "https://client.example.com/client.json");
      const mock = vi
        .spyOn(globalThis, "fetch")
        .mockResolvedValue(new Response("unavailable", { status: 503 }));
      try {
        const response = await f.request(`/authorize?${f.params}`, {
          headers: {
            "CF-Connecting-IP": "192.0.2.1",
            "X-Forwarded-For": "attacker-chosen",
          },
        });
        expect(response.status).toBe(429);
        expect(response.headers.get("Retry-After")).toBe("60");
        expect(limit).toHaveBeenCalledWith({ key: `${origin}:/authorize:192.0.2.1` });
        expect(mock).not.toHaveBeenCalled();
      } finally {
        mock.mockRestore();
      }
    });

    it.each(["/oauth/token", "/oauth/register", "/oauth/callback"])(
      "rate-limits %s before processing",
      async (path) => {
        const f = await setup();
        Object.assign(f.bindings, {
          AUTH_RATE_LIMITER: { limit: async () => ({ success: false }) },
        });
        const response = await f.request(
          path,
          path.endsWith("callback")
            ? undefined
            : {
                method: "POST",
                body: "invalid",
              },
        );
        expect(response.status).toBe(429);
      },
    );

    it("fails closed when the rate limiter is unavailable", async () => {
      const f = await setup();
      Object.assign(f.bindings, {
        AUTH_RATE_LIMITER: {
          limit: async () => {
            throw new Error("offline");
          },
        },
      });
      expect((await f.request(`/authorize?${f.params}`)).status).toBe(503);
    });
  });

  describe("MCP OAuth contract", () => {
    it("discovers the AS via a path-specific challenge with S256, CIMD and iss", async () => {
      const { request } = await setup();
      const r = await request("/mcp", { method: "POST", body: "{}" });
      expect(r.status).toBe(401);
      expect(r.headers.get("WWW-Authenticate")).toContain(
        `${origin}/.well-known/oauth-protected-resource/mcp`,
      );
      expect(r.headers.get("WWW-Authenticate")).toContain("mcp:read");
      expect(
        await (await request("/.well-known/oauth-protected-resource/mcp")).json(),
      ).toMatchObject({ resource, authorization_servers: [origin] });
      expect(await (await request("/.well-known/oauth-authorization-server")).json()).toMatchObject(
        {
          issuer: origin,
          code_challenge_methods_supported: ["S256"],
          authorization_response_iss_parameter_supported: true,
          client_id_metadata_document_supported: true,
        },
      );
    });

    it("escapes metadata, shows the redirect host and requires a browser-bound consent", async () => {
      const f = await setup();
      const { html, handle, page } = await consent(f);
      expect(html).not.toContain("<script>alert(1)</script>");
      expect(html).toContain("&lt;script&gt;");
      expect(html).toContain("localhost");
      expect(page.headers.get("Content-Security-Policy")).toContain("frame-ancestors 'none'");
      expect(
        (
          await f.request("/authorize", {
            method: "POST",
            body: new URLSearchParams({ handle, decision: "approve" }),
          })
        ).status,
      ).toBe(400);
    });

    it.each(["code_challenge", "resource"])("rejects missing %s", async (key) => {
      const { request, params } = await setup();
      params.delete(key);
      const r = await request(`/authorize?${params}`);
      expect([400, 302]).toContain(r.status);
      expect(await r.text()).not.toContain('name="handle"');
      if (r.status === 302)
        expect(new URL(r.headers.get("Location")!).searchParams.has("error")).toBe(true);
    });

    it("does not redirect to unregistered URIs", async () => {
      const { request, params } = await setup();
      params.set("redirect_uri", "https://attacker.example/callback");
      const r = await request(`/authorize?${params}`);
      expect(r.status).toBe(400);
      expect(r.headers.get("Location")).toBeNull();
    });

    it("exchanges a code once, calls whoami, rotates refresh tokens and revokes", async () => {
      const f = await setup();
      const { value, body } = await issueToken(f);
      expect(value.expires_in).toBe(600);
      expect(value.access_token).not.toBe("github-upstream-token");
      const mcp = await f.request("/mcp", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${value.access_token}`,
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream",
          "MCP-Protocol-Version": "2026-07-28",
          "MCP-Method": "tools/call",
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
      expect(mcp.status, await mcp.clone().text()).toBe(200);
      const result = await mcp.text();
      expect(result).toContain("mizchi");
      expect(result).not.toContain("github-upstream-token");
      const refreshed = await f.request("/oauth/token", {
        method: "POST",
        body: new URLSearchParams({
          grant_type: "refresh_token",
          client_id: f.clientId,
          refresh_token: value.refresh_token,
          resource,
        }),
      });
      expect(refreshed.status).toBe(200);
      const rotated = (await refreshed.json()) as { access_token: string; refresh_token: string };
      expect(rotated.refresh_token).not.toBe(value.refresh_token);
      const metadata = (await (
        await f.request("/.well-known/oauth-authorization-server")
      ).json()) as { revocation_endpoint: string };
      const revoked = await f.request(metadata.revocation_endpoint, {
        method: "POST",
        body: new URLSearchParams({ token: rotated.refresh_token, client_id: f.clientId }),
      });
      expect(revoked.status, await revoked.clone().text()).toBe(200);
      expect(
        (await f.request("/mcp", { headers: { Authorization: `Bearer ${rotated.access_token}` } }))
          .status,
      ).toBe(401);
      expect((await f.request("/oauth/token", { method: "POST", body })).status).toBe(400);
    });

    it("refuses identities outside the allowlist", async () => {
      const callback = await login(await setup(), "stranger");
      expect(callback.status).toBe(302);
      expect(new URL(callback.headers.get("Location")!).searchParams.get("error")).toBe(
        "access_denied",
      );
    });

    it("rejects a callback without the state binding cookie", async () => {
      const f = await setup();
      const flow = await consent(f);
      expect(
        (
          await f.request(
            `/oauth/callback?code=stolen&state=${flow.upstream.searchParams.get("state")}`,
          )
        ).status,
      ).toBe(400);
    });

    it("rejects wrong audiences, upstream tokens, query tokens and untrusted origins", async () => {
      const f = await setup();
      const { value } = await issueToken(f);
      const other = createPlayground({ ...f.bindings, PUBLIC_ORIGIN: "https://other.example.com" });
      const wrongAudience = await other.fetch(
        new Request("https://other.example.com/mcp", {
          headers: { Authorization: `Bearer ${value.access_token}` },
        }),
        createExecutionContext(),
      );
      expect(wrongAudience.status).toBe(401);
      expect(
        (await f.request("/mcp", { headers: { Authorization: "Bearer github-upstream-token" } }))
          .status,
      ).toBe(401);
      expect((await f.request(`/mcp?access_token=${value.access_token}`)).status).toBe(400);
      expect(
        (
          await f.request("/mcp", {
            headers: {
              Authorization: `Bearer ${value.access_token}`,
              Origin: "https://attacker.example",
            },
          })
        ).status,
      ).toBe(403);
    });

    it("rejects expired tokens", async () => {
      const f = await setup();
      const { value } = await issueToken(f);
      const now = Date.now();
      const date = vi.spyOn(Date, "now").mockReturnValue(now + 601_000);
      try {
        expect(
          (await f.request("/mcp", { headers: { Authorization: `Bearer ${value.access_token}` } }))
            .status,
        ).toBe(401);
      } finally {
        date.mockRestore();
      }
    });

    it("does not issue a refresh token without offline_access consent", async () => {
      const f = await setup();
      f.params.set("scope", "mcp:read");
      const { value } = await issueToken(f);
      expect(value).not.toHaveProperty("refresh_token");
    });

    it("challenges a valid token without mcp:read with 403 insufficient_scope", async () => {
      const f = await setup();
      f.params.set("scope", "offline_access");
      const { value } = await issueToken(f);
      const r = await f.request("/mcp", {
        headers: { Authorization: `Bearer ${value.access_token}` },
      });
      expect(r.status).toBe(403);
      expect(r.headers.get("WWW-Authenticate")).toContain("insufficient_scope");
      expect(r.headers.get("WWW-Authenticate")).toContain("mcp:read");
    });

    it.each(["resource", "code_verifier"])(
      "refuses a token exchange with wrong %s",
      async (key) => {
        const f = await setup();
        const callback = await login(f);
        const redirect = new URL(callback.headers.get("Location")!);
        const body = new URLSearchParams({
          grant_type: "authorization_code",
          code: redirect.searchParams.get("code")!,
          client_id: f.clientId,
          redirect_uri: f.params.get("redirect_uri")!,
          code_verifier: verifier,
          resource,
        });
        body.set(key, key === "resource" ? "https://attacker.example/mcp" : "x".repeat(64));
        const response = await f.request("/oauth/token", { method: "POST", body });
        expect(response.status).toBe(400);
        expect(await response.json()).not.toHaveProperty("access_token");
      },
    );

    it("code replay revokes tokens from the original exchange", async () => {
      const f = await setup();
      const { value, body } = await issueToken(f);
      expect((await f.request("/oauth/token", { method: "POST", body })).status).toBe(400);
      expect(
        (await f.request("/mcp", { headers: { Authorization: `Bearer ${value.access_token}` } }))
          .status,
      ).toBe(401);
    });

    it("denial returns state and issuer without starting upstream sign-in", async () => {
      const f = await setup();
      const page = await f.request(`/authorize?${f.params}`);
      const handle = (await page.text()).match(/name="handle" value="([^"]+)"/)![1];
      const denied = await f.request("/authorize", {
        method: "POST",
        headers: { Cookie: cookie(page), Origin: origin },
        body: new URLSearchParams({ handle, decision: "deny" }),
      });
      expect(denied.status).toBe(302);
      const target = new URL(denied.headers.get("Location")!);
      expect(target.searchParams.get("error")).toBe("access_denied");
      expect(target.searchParams.get("state")).toBe("client-state");
      expect(target.searchParams.get("iss")).toBe(origin);
    });

    it("supports CIMD and renders the verified client domain", async () => {
      const f = await setup();
      const clientId = `https://client.example.com/${suiteName.replaceAll(" ", "-")}/client.json`;
      f.params.set("client_id", clientId);
      const mock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
        Response.json(
          {
            client_id: clientId,
            client_name: "CIMD Test Client",
            redirect_uris: ["http://localhost:3456/callback"],
            token_endpoint_auth_method: "none",
          },
          { headers: { "Cache-Control": "max-age=300" } },
        ),
      );
      try {
        const r = await f.request(`/authorize?${f.params}`);
        expect(r.status, await r.clone().text()).toBe(200);
        expect(await r.text()).toContain("client.example.com");
        expect(mock).toHaveBeenCalledTimes(1);
      } finally {
        mock.mockRestore();
      }
    });

    it.each([
      "https://127.0.0.1/client.json",
      "https://[::1]/client.json",
      "https://169.254.169.254/client.json",
      "http://client.example.com/client.json",
    ])("refuses consent for unsafe CIMD URLs: %s", async (clientId) => {
      const f = await setup();
      f.params.set("client_id", clientId);
      const mock = vi.spyOn(globalThis, "fetch");
      try {
        expect((await f.request(`/authorize?${f.params}`)).status).toBe(400);
        expect(mock).not.toHaveBeenCalled();
      } finally {
        mock.mockRestore();
      }
    });

    it("does not advertise DCR when disabled", async () => {
      const f = await setup();
      const app = createPlayground({ ...f.bindings, ENABLE_DCR: false });
      const metadata = await app.fetch(
        new Request(`${origin}/.well-known/oauth-authorization-server`),
        createExecutionContext(),
      );
      expect(await metadata.json()).not.toHaveProperty("registration_endpoint");
      expect(
        (
          await app.fetch(
            new Request(`${origin}/oauth/register`, { method: "POST" }),
            createExecutionContext(),
          )
        ).status,
      ).toBe(404);
    });

    it("returns a safe OAuth error when GitHub returns a non-JSON outage page", async () => {
      const f = await setup();
      const flow = await consent(f);
      const mock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("upstream outage"));
      try {
        const response = await f.request(
          `/oauth/callback?code=code&state=${flow.upstream.searchParams.get("state")}`,
          { headers: { Cookie: cookie(flow.approved) } },
        );
        expect(response.status).toBe(302);
        const target = new URL(response.headers.get("Location")!);
        expect(target.searchParams.get("error")).toBe("temporarily_unavailable");
        expect(target.searchParams.get("state")).toBe("client-state");
        expect(target.searchParams.get("iss")).toBe(origin);
      } finally {
        mock.mockRestore();
      }
    });
  });
});
