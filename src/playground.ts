import {
  AuthorizationError,
  CimdFetchError,
  OAuthAuthorizationServer,
  OAuthError,
} from "@cloudflare/workers-oauth-provider";
import { SCOPES, supportedScopes, authorizationErrorUrl, type PlaygroundEnv } from "./contracts";
import {
  authRateLimit,
  boundedAuthBody,
  inputErrorResponse,
  RequestInputError,
} from "./http-guards";
import { consentPage } from "./consent";
import { createGitHubIdentityProvider } from "./github";
import { s256 } from "./pkce";
import { IdentityProviderError, type IdentityProvider } from "./identity-provider";
import { createResourceServer } from "./mcp";
import { isIP } from "node:net";

const localError = (message: string, status = 400) =>
  new Response(message, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });

export function createPlayground(
  env: PlaygroundEnv,
  identityProvider: IdentityProvider = createGitHubIdentityProvider(env),
) {
  const issuer = new URL(env.PUBLIC_ORIGIN);
  if (issuer.origin !== env.PUBLIC_ORIGIN)
    throw new TypeError("PUBLIC_ORIGIN must be an origin without a trailing slash or path");
  const authorizationServer = new OAuthAuthorizationServer<PlaygroundEnv>({
    issuer: env.PUBLIC_ORIGIN,
    resources: [`${env.PUBLIC_ORIGIN}/mcp`],
    scopesSupported: SCOPES,
    clientIdMetadataDocumentEnabled: true,
    ...(env.ENABLE_DCR ? { clientRegistrationEndpoint: "/oauth/register" } : {}),
    accessTokenTTL: 600,
    refreshTokenTTL: 604800,
    tokenExchangeCallback: ({ grantType, scope, props }) => {
      // invalid_grant also revokes the underlying grant in the provider.
      if (!identityProvider.isAllowed(props) || !supportedScopes(scope))
        throw new OAuthError("invalid_grant", {
          description: "Authorization is no longer allowed",
        });
      if (grantType === "authorization_code" && !scope.includes("offline_access")) {
        return { refreshTokenTTL: 0 };
      }
    },
  });
  const resourceServer = createResourceServer(env, authorizationServer, identityProvider);
  const oauth = authorizationServer.getOAuthApi(env);

  async function authorize(request: Request): Promise<Response> {
    if (request.method === "GET") {
      const clientId = new URL(request.url).searchParams.get("client_id");
      if (clientId && URL.canParse(clientId)) {
        const client = new URL(clientId);
        const host = client.hostname.replace(/^\[|\]$/g, "");
        // Reject IP literals before fetch; the runtime also blocks private DNS answers.
        if (
          (client.protocol === "http:" || client.protocol === "https:") &&
          (client.protocol !== "https:" ||
            isIP(host) ||
            host === "localhost" ||
            host.endsWith(".localhost"))
        ) {
          return localError("クライアントのメタデータには公開 HTTPS ドメインを指定してください。");
        }
      }
      const parsed = await oauth.parseAuthRequest(request);
      if (!supportedScopes(parsed.scope))
        return Response.redirect(authorizationErrorUrl(parsed, "invalid_scope"), 302);
      if (
        !new URL(request.url).searchParams.has("resource") ||
        !parsed.codeChallenge ||
        parsed.codeChallengeMethod !== "S256"
      ) {
        return Response.redirect(authorizationErrorUrl(parsed, "invalid_request"), 302);
      }
      const description = await oauth.describeConsent(parsed);
      const consent = await oauth.beginConsent(parsed);
      consent.headers.set("Content-Type", "text/html; charset=utf-8");
      return new Response(consentPage(description, consent.handle, identityProvider.name), {
        headers: consent.headers,
      });
    }
    if (request.method !== "POST")
      return new Response(null, { status: 405, headers: { Allow: "GET, POST" } });
    if (request.headers.get("Origin") !== env.PUBLIC_ORIGIN)
      return localError("同意画面から操作をやり直してください。");
    const form = await request.formData();
    const handle = String(form.get("handle") ?? "");
    if (form.get("decision") === "deny") {
      const denied = await oauth.denyConsent(request, handle);
      return new Response(null, { status: 302, headers: denied.headers });
    }
    if (form.get("decision") !== "approve") return localError("不正な操作です。");
    if (!identityProvider.configured)
      return localError(
        "ログイン先と許可ユーザーを設定してください。README のセットアップ手順を確認できます。",
        503,
      );
    const approved = await oauth.approveConsent(request, handle);
    if (!supportedScopes(approved.request.scope)) {
      approved.headers.set("Location", authorizationErrorUrl(approved.request, "invalid_scope"));
      return new Response(null, { status: 302, headers: approved.headers });
    }
    const verifier = crypto.randomUUID() + crypto.randomUUID();
    const upstream = await oauth.beginUpstream(approved.request, {
      data: { verifier },
      headers: approved.headers,
    });
    upstream.headers.set(
      "Location",
      identityProvider.authorizeUrl(upstream.state, await s256(verifier)),
    );
    return new Response(null, { status: 302, headers: upstream.headers });
  }

  async function callback(request: Request): Promise<Response> {
    if (request.method !== "GET")
      return new Response(null, { status: 405, headers: { Allow: "GET" } });
    const {
      request: original,
      data,
      headers,
    } = await oauth.finishUpstream<{ verifier: string }>(request);
    const url = new URL(request.url);
    if (identityProvider.issuer && url.searchParams.get("iss") !== identityProvider.issuer) {
      return localError("ログイン先の issuer を検証できませんでした。");
    }
    const deny = (error: string) => {
      headers.set("Location", authorizationErrorUrl(original, error));
      return new Response(null, { status: 302, headers });
    };
    if (url.searchParams.has("error") || !url.searchParams.get("code"))
      return deny("access_denied");
    if (!supportedScopes(original.scope)) return deny("invalid_scope");
    let identity;
    try {
      identity = await identityProvider.exchangeCode(url.searchParams.get("code")!, data.verifier);
    } catch (error) {
      if (error instanceof IdentityProviderError) return deny("temporarily_unavailable");
      throw error;
    }
    if (!identityProvider.isAllowed(identity)) return deny("access_denied");
    const completed = await oauth.completeAuthorization({
      request: original,
      userId: identity.id,
      metadata: { login: identity.login },
      scope: original.scope,
      props: identity,
    });
    headers.set("Location", completed.redirectTo);
    return new Response(null, { status: 302, headers });
  }

  return {
    authorizationServer,
    async fetch(request: Request, ctx: ExecutionContext): Promise<Response> {
      const url = new URL(request.url);
      if (url.origin !== env.PUBLIC_ORIGIN) return localError("Invalid host", 403);
      if (
        url.pathname === "/mcp" &&
        request.headers.has("Origin") &&
        request.headers.get("Origin") !== env.PUBLIC_ORIGIN
      )
        return localError("Invalid origin", 403);
      if (url.pathname === "/mcp" && url.searchParams.has("access_token"))
        return localError("Bearer トークンは Authorization ヘッダーで送信してください。");
      try {
        if (
          url.pathname === "/authorize" ||
          url.pathname === "/oauth/token" ||
          url.pathname === "/oauth/callback" ||
          (env.ENABLE_DCR && url.pathname === "/oauth/register")
        ) {
          const limited = await authRateLimit(request, env);
          if (limited) return limited;
          if (request.method === "POST" && url.pathname !== "/oauth/callback")
            request = await boundedAuthBody(
              request,
              url.pathname === "/oauth/register"
                ? "application/json"
                : "application/x-www-form-urlencoded",
            );
        }
        if (url.pathname === "/authorize") return await authorize(request);
        if (url.pathname === "/oauth/callback") return await callback(request);
        if (url.pathname === "/oauth/token" && request.method === "POST") {
          const form = await request.clone().formData();
          if (form.has("grant_type") && !form.get("resource"))
            return Response.json(
              { error: "invalid_target", error_description: "resource is required" },
              { status: 400, headers: { "Cache-Control": "no-store" } },
            );
        }
        if (
          url.pathname === "/mcp" ||
          url.pathname.startsWith("/.well-known/oauth-protected-resource")
        )
          return await resourceServer.fetch(request, env, ctx);
        return await authorizationServer.fetch(request, env, ctx);
      } catch (error) {
        if (error instanceof RequestInputError) return inputErrorResponse(error);
        if (error instanceof AuthorizationError && error.redirectTo)
          return Response.redirect(error.redirectTo, 302);
        if (error instanceof AuthorizationError) return localError(error.description);
        if (error instanceof CimdFetchError)
          return localError("クライアントのメタデータを検証できませんでした。");
        throw error;
      }
    },
  };
}
