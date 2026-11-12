import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { createClientApp } from "../../snippets/mcp-oauth/client.ts";

const origin = "http://127.0.0.1:3457";
const issuer = "https://mcp.example.com";
const resource = `${issuer}/mcp`;

function fixture(options = {}) {
  const calls = [];
  let challenge;
  let now = Date.now();
  const app = createClientApp({
    origin,
    resource,
    register: true,
    now: () => now,
    ...options,
    fetch: async (input, init) => {
      const url = String(input);
      const form = new URLSearchParams(init?.body);
      calls.push({ url, init, form });
      if (url === resource && !init?.headers?.Authorization)
        return new Response(null, {
          status: 401,
          headers: {
            "WWW-Authenticate": `Bearer resource_metadata="${issuer}/.well-known/oauth-protected-resource/mcp"`,
          },
        });
      if (url.endsWith("/.well-known/oauth-protected-resource/mcp"))
        return Response.json({
          resource,
          authorization_servers: [issuer],
          ...options.resourceMetadata,
        });
      if (url.endsWith("/.well-known/oauth-authorization-server"))
        return Response.json({
          issuer,
          authorization_endpoint: `${issuer}/authorize`,
          token_endpoint: `${issuer}/oauth/token`,
          registration_endpoint: `${issuer}/oauth/register`,
          revocation_endpoint: `${issuer}/oauth/token`,
          code_challenge_methods_supported: ["S256"],
          authorization_response_iss_parameter_supported: true,
          ...options.metadata,
        });
      if (url.endsWith("/oauth/register"))
        return Response.json({ client_id: "test-client" }, { status: 201 });
      if (url.endsWith("/oauth/token") && form.get("grant_type") === "authorization_code") {
        assert.equal(
          createHash("sha256").update(form.get("code_verifier")).digest("base64url"),
          challenge,
        );
        assert.equal(form.get("resource"), resource);
        if (options.redirectToken)
          return new Response(null, {
            status: 302,
            headers: { Location: "https://attacker.example/token" },
          });
        return Response.json({
          access_token: "secret-access-token",
          refresh_token: "secret-refresh-token",
          token_type: "Bearer",
          scope: "mcp:read offline_access",
        });
      }
      if (url.endsWith("/oauth/token") && form.get("grant_type") === "refresh_token") {
        assert.equal(form.get("resource"), resource);
        assert.equal(form.get("refresh_token"), "secret-refresh-token");
        return Response.json({
          access_token: "rotated-access-token",
          refresh_token: "rotated-refresh-token",
          token_type: "Bearer",
          scope: "mcp:read offline_access",
        });
      }
      if (url.endsWith("/oauth/token") && form.has("token"))
        return new Response(null, { status: options.rejectCleanup ? 500 : 200 });
      if (url === resource) {
        assert.match(init.headers.Authorization, /^Bearer (?:secret|rotated)-access-token$/);
        assert.equal(JSON.parse(init.body).params.name, "whoami");
        assert.equal(init.headers["MCP-Protocol-Version"], "2026-07-28");
        return Response.json({
          jsonrpc: "2.0",
          id: 1,
          result: { content: [{ type: "text", text: '{"id":"73962","login":"mizchi"}' }] },
        });
      }
      throw new Error("Unexpected request");
    },
  });
  const request = (path, init) => app.request(new URL(path, origin), init);
  async function begin() {
    const response = await request("/connect", { method: "POST", headers: { Origin: origin } });
    assert.equal(response.status, 302);
    const url = new URL(response.headers.get("Location"));
    assert.equal(url.searchParams.get("resource"), resource);
    assert.equal(url.searchParams.get("code_challenge_method"), "S256");
    assert.equal(url.searchParams.has("code_verifier"), false);
    challenge = url.searchParams.get("code_challenge");
    const cookie = response.headers.get("Set-Cookie").split(";")[0];
    const callback = new URL("/callback", origin);
    callback.search = new URLSearchParams({
      code: "test-code",
      state: url.searchParams.get("state"),
      iss: issuer,
    });
    return { cookie, callback };
  }
  return {
    request,
    calls,
    begin,
    advance: (ms) => {
      now += ms;
    },
  };
}

test("client performs discovery, bound PKCE, whoami, refresh and revocation without exposing tokens", async () => {
  const f = fixture();
  const { cookie, callback } = await f.begin();
  const response = await f.request(callback, { headers: { Cookie: cookie } });
  assert.equal(response.status, 200);
  const text = await response.text();
  assert.match(text, /73962/);
  assert.doesNotMatch(text, /secret-access-token|rotated-access-token|refresh-token/);
  assert.equal(JSON.parse(text).refreshed, true);
  assert.equal(JSON.parse(text).revoked, true);
  assert.equal(f.calls.filter((c) => c.form.has("token")).length, 1);
  assert.ok(f.calls.every((c) => c.init?.redirect === "manual"));
  assert.equal((await f.request(callback, { headers: { Cookie: cookie } })).status, 400);
});

for (const mode of [
  "wrong-state",
  "duplicate-state",
  "wrong-issuer",
  "missing-issuer",
  "missing-cookie",
  "expired",
]) {
  test(`client rejects ${mode} before token exchange`, async () => {
    const f = fixture();
    const { cookie, callback } = await f.begin();
    if (mode === "wrong-state") callback.searchParams.set("state", "attacker");
    if (mode === "duplicate-state") callback.searchParams.append("state", "attacker");
    if (mode === "wrong-issuer") callback.searchParams.set("iss", "https://attacker.example");
    if (mode === "missing-issuer") callback.searchParams.delete("iss");
    if (mode === "expired") f.advance(601_000);
    const response = await f.request(callback, {
      headers: mode === "missing-cookie" ? {} : { Cookie: cookie },
    });
    assert.equal(response.status, 400);
    assert.equal(f.calls.filter((c) => c.url.endsWith("/oauth/token")).length, 0);
  });
}

test("client rejects untrusted metadata endpoints before DCR or credential requests", async () => {
  const f = fixture({ metadata: { token_endpoint: "https://attacker.example/token" } });
  assert.equal(
    (await f.request("/connect", { method: "POST", headers: { Origin: origin } })).status,
    502,
  );
  assert.equal(f.calls.length, 3);
});

test("client requires explicit DCR opt-in", async () => {
  const f = fixture({ register: false });
  assert.equal(
    (await f.request("/connect", { method: "POST", headers: { Origin: origin } })).status,
    502,
  );
  assert.equal(
    f.calls.some((c) => c.url.endsWith("/oauth/register")),
    false,
  );
});

test("client rejects forged Origin and Host without making network calls", async () => {
  const f = fixture();
  assert.equal(
    (
      await f.request("/connect", {
        method: "POST",
        headers: { Origin: "https://attacker.example" },
      })
    ).status,
    403,
  );
  assert.equal(
    (
      await f.request("http://attacker.example/connect", {
        method: "POST",
        headers: { Origin: origin },
      })
    ).status,
    403,
  );
  assert.equal(f.calls.length, 0);
});

test("client does not follow token redirects", async () => {
  const f = fixture({ redirectToken: true });
  const { cookie, callback } = await f.begin();
  assert.equal((await f.request(callback, { headers: { Cookie: cookie } })).status, 502);
  assert.ok(f.calls.every((c) => c.url.startsWith(issuer)));
});

test("client reserves the pending-flow budget before asynchronous discovery", async () => {
  const f = fixture();
  const responses = await Promise.all(
    Array.from({ length: 17 }, () =>
      f.request("/connect", { method: "POST", headers: { Origin: origin } }),
    ),
  );
  assert.equal(responses.filter((r) => r.status === 302).length, 16);
  assert.equal(responses.filter((r) => r.status === 429).length, 1);
});

test("client never reports success when grant revocation fails", async () => {
  const f = fixture({ rejectCleanup: true });
  const { cookie, callback } = await f.begin();
  const response = await f.request(callback, { headers: { Cookie: cookie } });
  assert.equal(response.status, 502);
  assert.doesNotMatch(await response.text(), /revoked|secret-access-token|refresh-token/);
});
