import { describe, expect, it } from "vite-plus/test";
import { createLocalAuthorizationServer } from "../dev/local-authorization-server";
import { s256 } from "../src/pkce";

const issuer = "http://localhost:5173/local-idp";
const redirectUri = "http://localhost:5173/oauth/callback";
const clientId = "playground-local";
const verifier = "v".repeat(64);
const cookies = (r: Response) =>
  r.headers
    .getSetCookie()
    .map((v) => v.split(";")[0])
    .join("; ");

async function setup() {
  let now = Date.now();
  const server = createLocalAuthorizationServer({ issuer, clientId, redirectUri, now: () => now });
  const request = (path: string, init?: RequestInit) =>
    server.fetch(new Request(`${issuer}${path}`, init));
  const params = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    state: "client-state",
    scope: "profile",
    resource: `${issuer}/userinfo`,
    code_challenge: await s256(verifier),
    code_challenge_method: "S256",
  });
  const tokenBody = (code: string) =>
    new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: clientId,
      redirect_uri: redirectUri,
      code_verifier: verifier,
      resource: `${issuer}/userinfo`,
    });
  const authorize = async () => {
    const page = await request(`/authorize?${params}`);
    expect(page.status).toBe(200);
    const handle = (await page.text()).match(/name="handle" value="([^"]+)"/)![1];
    const response = await request("/authorize", {
      method: "POST",
      headers: { Cookie: cookies(page), Origin: new URL(issuer).origin },
      body: new URLSearchParams({ handle, decision: "approve" }),
    });
    expect(response.status).toBe(302);
    const target = new URL(response.headers.get("Location")!);
    expect(target.searchParams.get("state")).toBe("client-state");
    expect(target.searchParams.get("iss")).toBe(issuer);
    return target.searchParams.get("code")!;
  };
  return {
    request,
    params,
    tokenBody,
    authorize,
    advance: (ms: number) => {
      now += ms;
    },
  };
}

describe("self-implemented local authorization server", () => {
  it.each(["/authorize", "/token"])("bounds POST bodies at %s", async (path) => {
    const f = await setup();
    const response = await f.request(path, {
      method: "POST",
      headers: { Origin: new URL(issuer).origin },
      body: new URLSearchParams({ padding: "x".repeat(16_385) }),
    });
    expect(response.status).toBe(413);
  });

  it("matches the RFC 7636 S256 test vector", async () => {
    expect(await s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe(
      "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    );
  });

  it("advertises the canonical issuer and PKCE metadata", async () => {
    const server = createLocalAuthorizationServer({ issuer, clientId, redirectUri });
    const response = await server.fetch(
      new Request("http://localhost:5173/.well-known/oauth-authorization-server/local-idp"),
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      issuer,
      token_endpoint: `${issuer}/token`,
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      authorization_response_iss_parameter_supported: true,
    });
  });
  it("verifies S256 and issues its own short-lived userinfo token", async () => {
    const f = await setup();
    const code = await f.authorize();
    const response = await f.request("/token", { method: "POST", body: f.tokenBody(code) });
    expect(response.status).toBe(200);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    const token = (await response.json()) as { access_token: string; expires_in: number };
    expect(token.expires_in).toBe(300);
    const user = await f.request("/userinfo", {
      headers: { Authorization: `Bearer ${token.access_token}` },
    });
    expect(user.status).toBe(200);
    expect(await user.json()).toEqual({ id: "local-alice", login: "alice", name: "Local Alice" });
  });

  it.each(["missing", "wrong", "short", "invalid-characters"])(
    "rejects a %s verifier and consumes the attempted code",
    async (kind) => {
      const f = await setup();
      const code = await f.authorize();
      const body = f.tokenBody(code);
      if (kind === "missing") body.delete("code_verifier");
      else
        body.set(
          "code_verifier",
          kind === "short" ? "short" : kind === "wrong" ? "x".repeat(64) : "!".repeat(64),
        );
      const failed = await f.request("/token", { method: "POST", body });
      expect(failed.status).toBe(400);
      expect(await failed.json()).not.toHaveProperty("access_token");
      expect((await f.request("/token", { method: "POST", body: f.tokenBody(code) })).status).toBe(
        400,
      );
    },
  );

  it("only redeems a code once, including concurrent exchanges", async () => {
    const f = await setup();
    const code = await f.authorize();
    const results = await Promise.all(
      [1, 2].map(() => f.request("/token", { method: "POST", body: f.tokenBody(code) })),
    );
    expect(results.map((r) => r.status).sort()).toEqual([200, 400]);
  });

  it.each(["client_id", "redirect_uri", "resource"])("binds a code to %s", async (key) => {
    const f = await setup();
    const body = f.tokenBody(await f.authorize());
    body.set(key, "https://attacker.example/wrong");
    expect((await f.request("/token", { method: "POST", body })).status).toBe(400);
  });

  it("rejects expired codes and access tokens", async () => {
    const f = await setup();
    const code = await f.authorize();
    f.advance(60_001);
    expect((await f.request("/token", { method: "POST", body: f.tokenBody(code) })).status).toBe(
      400,
    );
    const valid = await f.request("/token", {
      method: "POST",
      body: f.tokenBody(await f.authorize()),
    });
    const token = (await valid.json()) as { access_token: string };
    f.advance(300_001);
    expect(
      (await f.request("/userinfo", { headers: { Authorization: `Bearer ${token.access_token}` } }))
        .status,
    ).toBe(401);
  });

  it.each(["plain", "missing-challenge", "wrong-resource", "unregistered-redirect"])(
    "rejects %s before consent",
    async (kind) => {
      const f = await setup();
      if (kind === "plain") f.params.set("code_challenge_method", "plain");
      if (kind === "missing-challenge") f.params.delete("code_challenge");
      if (kind === "wrong-resource") f.params.set("resource", "https://attacker.example/api");
      if (kind === "unregistered-redirect")
        f.params.set("redirect_uri", "https://attacker.example/callback");
      const response = await f.request(`/authorize?${f.params}`);
      expect(response.status).toBe(400);
      expect(response.headers.get("Location")).toBeNull();
    },
  );

  it("rejects forged consent and bearer tokens for other services", async () => {
    const f = await setup();
    const page = await f.request(`/authorize?${f.params}`);
    const handle = (await page.text()).match(/name="handle" value="([^"]+)"/)![1];
    expect(
      (
        await f.request("/authorize", {
          method: "POST",
          headers: { Origin: new URL(issuer).origin },
          body: new URLSearchParams({ handle, decision: "approve" }),
        })
      ).status,
    ).toBe(400);
    expect(
      (await f.request("/userinfo", { headers: { Authorization: "Bearer github-token" } })).status,
    ).toBe(401);
    expect((await f.request("/userinfo?access_token=anything")).status).toBe(400);
  });

  it("denies consent with state and issuer and no code", async () => {
    const f = await setup();
    const page = await f.request(`/authorize?${f.params}`);
    const handle = (await page.text()).match(/name="handle" value="([^"]+)"/)![1];
    const denied = await f.request("/authorize", {
      method: "POST",
      headers: { Cookie: cookies(page), Origin: new URL(issuer).origin },
      body: new URLSearchParams({ handle, decision: "deny" }),
    });
    const target = new URL(denied.headers.get("Location")!);
    expect(target.searchParams.get("error")).toBe("access_denied");
    expect(target.searchParams.get("state")).toBe("client-state");
    expect(target.searchParams.get("iss")).toBe(issuer);
    expect(target.searchParams.has("code")).toBe(false);
  });
});
