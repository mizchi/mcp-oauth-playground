import { env } from "cloudflare:workers";
import { createExecutionContext } from "cloudflare:test";
import { describe, expect, it, vi } from "vite-plus/test";
import { createPlayground } from "../src/playground";
import { createLocalIdentityProvider } from "../dev/local-identity-provider";
import { s256 } from "../src/pkce";

const origin = "http://localhost:5173";
const cookie = (r: Response) =>
  r.headers
    .getSetCookie()
    .map((value) => value.split(";")[0])
    .join("; ");

describe("local identity provider boundary", () => {
  it.each(["missing", "wrong"])(
    "rejects a %s issuer before exchanging any upstream code",
    async (kind) => {
      const provider = createLocalIdentityProvider(origin);
      const exchange = vi.spyOn(provider, "exchangeCode");
      const app = createPlayground(
        {
          OAUTH_KV: env.OAUTH_KV,
          PUBLIC_ORIGIN: origin,
          ENABLE_DCR: true,
          AUTH_RATE_LIMITER: { limit: async () => ({ success: true }) },
        },
        provider,
      );
      const request = (path: string, init?: RequestInit) =>
        app.fetch(new Request(new URL(path, origin), init), createExecutionContext());
      const registration = await request("/oauth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_name: "Issuer test",
          redirect_uris: ["http://localhost:3456/callback"],
          token_endpoint_auth_method: "none",
        }),
      });
      expect(registration.status).toBe(201);
      const { client_id: clientId } = (await registration.json()) as { client_id: string };
      const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: "http://localhost:3456/callback",
        response_type: "code",
        resource: `${origin}/mcp`,
        scope: "mcp:read",
        state: "outer-state",
        code_challenge: await s256("v".repeat(64)),
        code_challenge_method: "S256",
      });
      const page = await request(`/authorize?${params}`);
      const handle = (await page.text()).match(/name="handle" value="([^"]+)"/)![1];
      const consent = await request("/authorize", {
        method: "POST",
        headers: { Origin: origin, Cookie: cookie(page) },
        body: new URLSearchParams({ handle, decision: "approve" }),
      });
      const upstream = new URL(consent.headers.get("Location")!);
      const callback = new URLSearchParams({
        code: "stolen",
        state: upstream.searchParams.get("state")!,
      });
      if (kind === "wrong") callback.set("iss", "https://attacker.example");
      try {
        const response = await request(`/oauth/callback?${callback}`, {
          headers: { Cookie: cookie(consent) },
        });
        expect(response.status).toBe(400);
        expect(response.headers.get("Location")).toBeNull();
        expect(exchange).not.toHaveBeenCalled();
      } finally {
        exchange.mockRestore();
      }
    },
  );
});
