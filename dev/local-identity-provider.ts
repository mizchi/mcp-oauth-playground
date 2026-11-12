import { z } from "zod";
import { createLocalAuthorizationServer } from "./local-authorization-server";
import { IdentityProviderError, type IdentityProvider } from "../src/identity-provider";

const providers = new Map<string, ReturnType<typeof createLocalAuthorizationServer>>();

export function localAuthorizationServer(origin: string) {
  let server = providers.get(origin);
  if (!server) {
    server = createLocalAuthorizationServer({
      issuer: `${origin}/local-idp`,
      clientId: "playground-local",
      redirectUri: `${origin}/oauth/callback`,
    });
    providers.set(origin, server);
  }
  return server;
}

/** Real AS handler shared by the dev HTTP routes and the in-Worker adapter; no fetch mock. */
export function createLocalIdentityProvider(origin: string): IdentityProvider {
  const server = localAuthorizationServer(origin);
  const resource = `${server.issuer}/userinfo`;
  return {
    name: "ローカル認可サーバー",
    configured: true,
    issuer: server.issuer,
    authorizeUrl(state, challenge) {
      return `${server.issuer}/authorize?${new URLSearchParams({ client_id: "playground-local", redirect_uri: `${origin}/oauth/callback`, response_type: "code", state, scope: "profile", resource, code_challenge: challenge, code_challenge_method: "S256" })}`;
    },
    async exchangeCode(code, verifier) {
      const response = await server.fetch(
        new Request(`${server.issuer}/token`, {
          method: "POST",
          body: new URLSearchParams({
            grant_type: "authorization_code",
            client_id: "playground-local",
            redirect_uri: `${origin}/oauth/callback`,
            code,
            code_verifier: verifier,
            resource,
          }),
        }),
      );
      if (!response.ok)
        throw new IdentityProviderError("ローカル認可サーバーで PKCE の検証に失敗しました。");
      const token = z.object({ access_token: z.string() }).parse(await response.json());
      const user = await server.fetch(
        new Request(resource, { headers: { Authorization: `Bearer ${token.access_token}` } }),
      );
      if (!user.ok)
        throw new IdentityProviderError("ローカル認可サーバーでトークンの検証に失敗しました。");
      return z
        .object({ id: z.string(), login: z.string(), name: z.string() })
        .parse(await user.json());
    },
    isAllowed: (identity) => identity.id === "local-alice",
  };
}
