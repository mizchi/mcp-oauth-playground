import type { Identity } from "../src/contracts";
import { randomSecret, s256 } from "../src/pkce";
import { boundedAuthBody, inputErrorResponse, RequestInputError } from "../src/http-guards";

export interface LocalAuthorizationServerOptions {
  issuer: string;
  clientId: string;
  redirectUri: string;
  now?: () => number;
}

interface Authorization {
  clientId: string;
  redirectUri: string;
  state: string;
  challenge: string;
  resource: string;
  expiresAt: number;
}
interface Pending extends Authorization {
  binding: string;
}
interface AccessToken {
  identity: Identity;
  resource: string;
  expiresAt: number;
}

const ALICE: Identity = { id: "local-alice", login: "alice", name: "Local Alice" };
const noStore = { "Cache-Control": "no-store", Pragma: "no-cache" };
const jsonError = (error: string, status = 400) =>
  Response.json({ error }, { status, headers: noStore });
const escape = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
async function readForm(request: Request) {
  const form = await request.formData();
  return new URLSearchParams([...form].map(([key, value]) => [key, String(value)]));
}

/** Educational, development-only AS. Stores are ephemeral, bounded and process-local. */
export function createLocalAuthorizationServer(options: LocalAuthorizationServerOptions) {
  const issuerUrl = new URL(options.issuer);
  const issuer = issuerUrl.href.replace(/\/$/, "");
  const base = issuerUrl.pathname.replace(/\/$/, "");
  const resource = `${issuer}/userinfo`;
  const now = options.now ?? Date.now;
  const pending = new Map<string, Pending>();
  const codes = new Map<string, Authorization>();
  const tokens = new Map<string, AccessToken>();
  const metadataPath = `/.well-known/oauth-authorization-server${base}`;
  const cookieName = (handle: string) => `local-idp-${handle}`;
  const cookiePath = base || "/";
  const secure = issuerUrl.protocol === "https:" ? "; Secure" : "";
  const cookie = (handle: string, value: string, age: number) =>
    `${cookieName(handle)}=${value}; HttpOnly; SameSite=Lax; Path=${cookiePath}; Max-Age=${age}${secure}`;

  function clean() {
    for (const store of [pending, codes, tokens]) {
      for (const [key, value] of store) if (value.expiresAt <= now()) store.delete(key);
    }
  }

  function redirect(auth: Authorization, result: Record<string, string>, handle: string) {
    const target = new URL(auth.redirectUri);
    for (const [key, value] of Object.entries({ ...result, state: auth.state, iss: issuer }))
      target.searchParams.set(key, value);
    return new Response(null, {
      status: 302,
      headers: { ...noStore, Location: target.href, "Set-Cookie": cookie(handle, "", 0) },
    });
  }

  async function authorize(request: Request, url: URL): Promise<Response> {
    if (request.method === "GET") {
      const q = url.searchParams;
      if (
        [...q.keys()].some((key) => q.getAll(key).length > 1) ||
        q.get("client_id") !== options.clientId ||
        q.get("redirect_uri") !== options.redirectUri ||
        q.get("response_type") !== "code" ||
        q.get("code_challenge_method") !== "S256" ||
        !/^[A-Za-z0-9_-]{43}$/.test(q.get("code_challenge") ?? "") ||
        q.get("resource") !== resource ||
        q.get("scope") !== "profile" ||
        !q.get("state") ||
        q.get("state")!.length > 512
      )
        return jsonError("invalid_request");
      if (pending.size >= 1024) return jsonError("temporarily_unavailable", 503);
      const handle = randomSecret();
      const binding = randomSecret();
      pending.set(handle, {
        clientId: options.clientId,
        redirectUri: options.redirectUri,
        challenge: q.get("code_challenge")!,
        state: q.get("state")!,
        resource,
        binding,
        expiresAt: now() + 600_000,
      });
      return new Response(
        `<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ローカル認可サーバー</title><body><main><h1>ローカル認可サーバー</h1><p>開発用の固定アカウントでログインします。</p><p><strong>Local Alice (@alice)</strong></p><p>クライアント: ${escape(options.clientId)}</p><p>リダイレクト先: ${escape(options.redirectUri)}</p><p>権限: profile</p><form method="post" action="${escape(base)}/authorize"><input type="hidden" name="handle" value="${handle}"><button name="decision" value="approve">Alice としてログイン</button><button name="decision" value="deny">ログインを拒否</button></form></main></body></html>`,
        {
          headers: {
            ...noStore,
            "Content-Type": "text/html; charset=utf-8",
            "Set-Cookie": cookie(handle, binding, 600),
            "Content-Security-Policy":
              "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
          },
        },
      );
    }
    if (request.method !== "POST") return jsonError("invalid_request", 405);
    if (request.headers.get("Origin") !== issuerUrl.origin) return jsonError("invalid_request");
    if (!request.headers.get("Content-Type")?.startsWith("application/x-www-form-urlencoded"))
      return jsonError("invalid_request");
    const form = await readForm(request);
    const handle = form.get("handle") ?? "";
    const auth = pending.get(handle);
    const bound = request.headers
      .get("Cookie")
      ?.split(";")
      .some((part) => part.trim() === `${cookieName(handle)}=${auth?.binding}`);
    if (
      !auth ||
      !bound ||
      auth.expiresAt <= now() ||
      !["approve", "deny"].includes(form.get("decision") ?? "")
    )
      return jsonError("invalid_request");
    pending.delete(handle);
    if (form.get("decision") === "deny") return redirect(auth, { error: "access_denied" }, handle);
    if (codes.size >= 1024) return jsonError("temporarily_unavailable", 503);
    const code = randomSecret();
    codes.set(code, { ...auth, expiresAt: now() + 60_000 });
    return redirect(auth, { code }, handle);
  }

  async function token(request: Request): Promise<Response> {
    if (request.method !== "POST") return jsonError("invalid_request", 405);
    if (!request.headers.get("Content-Type")?.startsWith("application/x-www-form-urlencoded"))
      return jsonError("invalid_request");
    const form = await readForm(request);
    if (form.get("grant_type") !== "authorization_code") return jsonError("unsupported_grant_type");
    const code = form.get("code") ?? "";
    const auth = codes.get(code);
    // Consume synchronously before awaiting SHA-256: concurrent redemption cannot win twice.
    codes.delete(code);
    const verifier = form.get("code_verifier") ?? "";
    if (
      !auth ||
      auth.expiresAt <= now() ||
      [...form.keys()].some((key) => form.getAll(key).length > 1) ||
      form.get("client_id") !== auth.clientId ||
      form.get("redirect_uri") !== auth.redirectUri ||
      form.get("resource") !== auth.resource ||
      !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) ||
      (await s256(verifier)) !== auth.challenge
    )
      return jsonError("invalid_grant");
    if (tokens.size >= 1024) return jsonError("temporarily_unavailable", 503);
    const accessToken = randomSecret();
    tokens.set(accessToken, {
      identity: ALICE,
      resource: auth.resource,
      expiresAt: now() + 300_000,
    });
    return Response.json(
      { access_token: accessToken, token_type: "Bearer", expires_in: 300, scope: "profile" },
      { headers: noStore },
    );
  }

  return {
    issuer,
    async fetch(request: Request): Promise<Response> {
      const url = new URL(request.url);
      if (url.origin !== issuerUrl.origin) return jsonError("invalid_request", 403);
      if (
        request.method === "POST" &&
        (url.pathname === `${base}/authorize` || url.pathname === `${base}/token`)
      ) {
        try {
          request = await boundedAuthBody(request, "application/x-www-form-urlencoded");
        } catch (error) {
          if (error instanceof RequestInputError) return inputErrorResponse(error);
          throw error;
        }
      }
      clean();
      if (url.pathname === metadataPath && request.method === "GET")
        return Response.json(
          {
            issuer,
            authorization_endpoint: `${issuer}/authorize`,
            token_endpoint: `${issuer}/token`,
            userinfo_endpoint: resource,
            response_types_supported: ["code"],
            grant_types_supported: ["authorization_code"],
            code_challenge_methods_supported: ["S256"],
            token_endpoint_auth_methods_supported: ["none"],
            scopes_supported: ["profile"],
            authorization_response_iss_parameter_supported: true,
          },
          { headers: noStore },
        );
      if (url.pathname === `${base}/authorize`) return authorize(request, url);
      if (url.pathname === `${base}/token`) return token(request);
      if (url.pathname === `${base}/userinfo` && request.method === "GET") {
        if (url.searchParams.has("access_token")) return jsonError("invalid_request");
        const bearer = request.headers
          .get("Authorization")
          ?.match(/^Bearer ([A-Za-z0-9_-]+)$/i)?.[1];
        const access = bearer ? tokens.get(bearer) : undefined;
        if (!access || access.expiresAt <= now() || access.resource !== resource)
          return Response.json(
            { error: "invalid_token" },
            {
              status: 401,
              headers: { ...noStore, "WWW-Authenticate": 'Bearer error="invalid_token"' },
            },
          );
        return Response.json(access.identity, { headers: noStore });
      }
      return jsonError("not_found", 404);
    },
  };
}
