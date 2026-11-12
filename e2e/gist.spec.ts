import { expect, test } from "@playwright/test";

test("two standalone snippets complete login, PKCE, MCP, refresh and revocation", async ({
  page,
}) => {
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (
      url.origin === "http://localhost:8793" &&
      url.pathname === "/authorize" &&
      route.request().method() === "POST"
    ) {
      // Intercept the first response in the redirect chain; Playwright does not
      // route later hops. Preserve the real response's state-binding cookies.
      const response = await route.fetch({ maxRedirects: 0 });
      expect(response.status()).toBe(302);
      const upstream = new URL(response.headers()["location"]);
      expect(upstream.origin).toBe("https://github.com");
      expect(upstream.searchParams.get("code_challenge_method")).toBe("S256");
      const callback = new URL(upstream.searchParams.get("redirect_uri")!);
      callback.search = new URLSearchParams({
        code: "fixture-github-code",
        state: upstream.searchParams.get("state")!,
      }).toString();
      return route.fulfill({
        response,
        headers: { ...response.headers(), location: callback.href },
      });
    }
    if (!["http://localhost:8793", "http://127.0.0.1:3457"].includes(url.origin))
      return route.abort();
    return route.continue();
  });
  await page.goto("/");
  await page.getByRole("button", { name: "接続して whoami を試す" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Hono MCP OAuth Client");
  const callback = page.waitForResponse(
    (response) =>
      new URL(response.url()).origin === "http://127.0.0.1:3457" &&
      new URL(response.url()).pathname === "/callback",
  );
  await page.getByRole("button", { name: "許可して GitHub へ" }).click();
  const response = await callback;
  expect(response.status(), await response.text()).toBe(200);
  const result = await response.json();
  expect(result).toMatchObject({ refreshed: true, revoked: true });
  expect(JSON.stringify(result)).toContain("73962");
  expect(JSON.stringify(result)).not.toContain("fixture-github-token");
  expect(result).not.toHaveProperty("access_token");
  expect(result).not.toHaveProperty("refresh_token");
});
