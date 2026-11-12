import { expect, test, type APIRequestContext } from "@playwright/test";
import { createHash, randomBytes } from "node:crypto";

const origin = process.env.MCP_E2E_ORIGIN ?? "http://localhost:5173";
const githubOrigin = process.env.MCP_E2E_GITHUB_ORIGIN ?? "http://localhost:5174";
const callback = `${origin}/oauth/test-client-callback`;
const meta = {
  "io.modelcontextprotocol/protocolVersion": "2026-07-28",
  "io.modelcontextprotocol/clientCapabilities": {},
};

async function clientAuthorization(request: APIRequestContext) {
  const verifier = randomBytes(32).toString("base64url");
  const response = await request.post("/oauth/register", {
    data: {
      client_name: "Local PKCE E2E Client",
      redirect_uris: [callback],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      application_type: "web",
    },
  });
  expect(response.status()).toBe(201);
  const { client_id: clientId } = await response.json();
  const state = randomBytes(32).toString("base64url");
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: callback,
    response_type: "code",
    resource: `${origin}/mcp`,
    scope: "mcp:read offline_access",
    state,
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
  });
  return { url: `/authorize?${params}`, verifier, state, clientId };
}

test("own authorization server completes PKCE, MCP access, refresh and revocation without mocks", async ({
  page,
  request,
}) => {
  const external: string[] = [];
  page.on("request", (r) => {
    if (new URL(r.url()).origin !== origin) external.push(r.url());
  });
  const client = await clientAuthorization(request);
  await page.goto(client.url);
  await page.getByRole("button", { name: "許可して ローカル認可サーバー へ" }).click();
  await expect(
    page.getByRole("heading", { name: "ローカル認可サーバー", exact: true }),
  ).toBeVisible();
  expect(new URL(page.url()).pathname).toBe("/local-idp/authorize");
  await page.getByRole("button", { name: "Alice としてログイン" }).click();
  await expect(page).toHaveURL(/\/oauth\/test-client-callback\?code=/);
  const authorized = new URL(page.url());
  expect(authorized.searchParams.get("state")).toBe(client.state);
  expect(authorized.searchParams.get("iss")).toBe(origin);
  const tokenResponse = await request.post("/oauth/token", {
    form: {
      grant_type: "authorization_code",
      client_id: client.clientId,
      redirect_uri: callback,
      code: authorized.searchParams.get("code")!,
      code_verifier: client.verifier,
      resource: `${origin}/mcp`,
    },
  });
  expect(tokenResponse.status(), await tokenResponse.text()).toBe(200);
  const token = await tokenResponse.json();
  const mcp = await request.post("/mcp", {
    headers: {
      Authorization: `Bearer ${token.access_token}`,
      Accept: "application/json, text/event-stream",
      "MCP-Protocol-Version": "2026-07-28",
      "Mcp-Method": "tools/call",
      "Mcp-Name": "whoami",
    },
    data: {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "whoami", arguments: {}, _meta: meta },
    },
  });
  expect(mcp.status(), await mcp.text()).toBe(200);
  const result = await mcp.json();
  expect(JSON.parse(result.result.content[0].text)).toEqual({
    id: "local-alice",
    login: "alice",
    name: "Local Alice",
  });
  const refreshed = await request.post("/oauth/token", {
    form: {
      grant_type: "refresh_token",
      client_id: client.clientId,
      refresh_token: token.refresh_token,
      resource: `${origin}/mcp`,
    },
  });
  expect(refreshed.status()).toBe(200);
  const rotated = await refreshed.json();
  expect(rotated.refresh_token).not.toBe(token.refresh_token);
  const metadata = await (await request.get("/.well-known/oauth-authorization-server")).json();
  const revoked = await request.post(metadata.revocation_endpoint, {
    form: { client_id: client.clientId, token: rotated.refresh_token },
  });
  expect(revoked.status()).toBe(200);
  expect(
    (
      await request.post("/mcp", {
        headers: { Authorization: `Bearer ${rotated.access_token}` },
        data: {},
      })
    ).status(),
  ).toBe(401);
  expect(external).toEqual([]);
});

test("own authorization server rejects a wrong verifier over HTTP", async ({ page, request }) => {
  const verifier = randomBytes(32).toString("base64url");
  const resource = `${origin}/local-idp/userinfo`;
  await page.goto(
    `/local-idp/authorize?${new URLSearchParams({ client_id: "playground-local", redirect_uri: `${origin}/oauth/callback`, response_type: "code", scope: "profile", resource, state: "negative-test", code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256" })}`,
  );
  const redirect = page.waitForResponse(
    (r) => new URL(r.url()).pathname === "/local-idp/authorize" && r.request().method() === "POST",
  );
  await page.getByRole("button", { name: "Alice としてログイン" }).click();
  const response = await redirect;
  expect(response.status()).toBe(302);
  const code = new URL(response.headers()["location"]).searchParams.get("code")!;
  const form = {
    grant_type: "authorization_code",
    client_id: "playground-local",
    redirect_uri: `${origin}/oauth/callback`,
    resource,
    code,
    code_verifier: "x".repeat(64),
  };
  const failed = await request.post("/local-idp/token", { form });
  expect(failed.status()).toBe(400);
  expect(await failed.json()).toEqual({ error: "invalid_grant" });
  expect(
    (
      await request.post("/local-idp/token", { form: { ...form, code_verifier: verifier } })
    ).status(),
  ).toBe(400);
});

test("GitHub mode does not expose the local issuer", async ({ request }) => {
  expect((await request.get(`${githubOrigin}/local-idp/authorize`)).status()).toBe(404);
  expect(
    (
      await request.get(`${githubOrigin}/.well-known/oauth-authorization-server/local-idp`)
    ).status(),
  ).toBe(404);
});
