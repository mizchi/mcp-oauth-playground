import { expect, test, type APIRequestContext } from "@playwright/test";
import { createHash } from "node:crypto";

const origin = process.env.MCP_E2E_ORIGIN ?? "http://localhost:5173";
const githubOrigin = process.env.MCP_E2E_GITHUB_ORIGIN ?? "http://localhost:5174";

async function authorizationUrl(request: APIRequestContext, targetOrigin = origin) {
  const registration = await request.post(`${targetOrigin}/oauth/register`, {
    data: {
      client_name: "Playwright MCP Client",
      redirect_uris: ["http://localhost:3456/callback"],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      application_type: "native",
    },
  });
  expect(registration.status(), await registration.text()).toBe(201);
  const client = await registration.json();
  return `/authorize?${new URLSearchParams({
    client_id: client.client_id,
    redirect_uri: "http://localhost:3456/callback",
    response_type: "code",
    resource: `${targetOrigin}/mcp`,
    scope: "mcp:read offline_access",
    state: "browser-state",
    code_challenge: createHash("sha256").update("v".repeat(64)).digest("base64url"),
    code_challenge_method: "S256",
  })}`;
}

test("connection instructions and discovery work on desktop and mobile", async ({
  page,
  request,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("MCP OAuth");
  await expect(page.getByText(`${origin}/mcp`, { exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.getByRole("link", { name: "Protected Resource Metadata" }).click();
  await expect(page.locator("body")).toContainText(`${origin}/mcp`);
  const challenge = await request.post("/mcp", { data: {} });
  expect(challenge.status()).toBe(401);
  expect(challenge.headers()["www-authenticate"]).toContain(
    "/.well-known/oauth-protected-resource/mcp",
  );
  expect(errors).toEqual([]);
});

test("denial returns the original state and issuer without contacting GitHub", async ({
  page,
  request,
}) => {
  let redirect = "";
  await page.route("**/authorize", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    const response = await route.fetch({ maxRedirects: 0 });
    expect(response.status()).toBe(302);
    redirect = response.headers()["location"];
    await route.fulfill({ status: 200, body: "Client callback ready" });
  });
  await page.goto(await authorizationUrl(request));
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Playwright MCP Client");
  await expect(page.getByText("localhost", { exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.getByRole("button", { name: "拒否", exact: true }).click();
  await expect(page.getByText("Client callback ready")).toBeVisible();
  const url = new URL(redirect);
  expect(url.origin).toBe("http://localhost:3456");
  expect(url.searchParams.get("error")).toBe("access_denied");
  expect(url.searchParams.get("state")).toBe("browser-state");
  expect(url.searchParams.get("iss")).toBe(origin);
});

test("only explicit approval starts the GitHub PKCE sign-in", async ({ page, request }) => {
  let redirect = "";
  // Stop at the external identity provider boundary; no real credentials are used.
  await page.route("**/authorize", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    const response = await route.fetch({ maxRedirects: 0 });
    expect(response.status()).toBe(302);
    redirect = response.headers()["location"];
    await route.fulfill({ status: 200, body: "GitHub sign-in ready" });
  });
  await page.goto(new URL(await authorizationUrl(request, githubOrigin), githubOrigin).href);
  await page.getByRole("button", { name: "許可して GitHub へ" }).click();
  await expect(page.getByText("GitHub sign-in ready")).toBeVisible();
  const url = new URL(redirect);
  expect(url.origin).toBe("https://github.com");
  expect(url.searchParams.get("redirect_uri")).toBe(`${githubOrigin}/oauth/callback`);
  expect(url.searchParams.get("state")).toBeTruthy();
  expect(url.searchParams.get("code_challenge")).toMatch(/^[\w-]{43}$/);
  expect(url.searchParams.get("code_challenge_method")).toBe("S256");
  expect(url.searchParams.get("scope")).toBe("");
});
