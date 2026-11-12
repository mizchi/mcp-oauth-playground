import { z } from "zod";
import type { Identity, PlaygroundEnv } from "./contracts";
import { IdentityProviderError, type IdentityProvider } from "./identity-provider";

export { s256 } from "./pkce";

export function githubAuthorizeUrl(env: PlaygroundEnv, state: string, challenge: string): string {
  const url = new URL("https://github.com/login/oauth/authorize");
  url.search = new URLSearchParams({
    client_id: env.GITHUB_CLIENT_ID!,
    redirect_uri: `${env.PUBLIC_ORIGIN}/oauth/callback`,
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    // No repository or email scope: only the public identity is needed.
    scope: "",
  }).toString();
  return url.href;
}

export class GitHubError extends IdentityProviderError {}

async function githubJson(url: string, init: RequestInit): Promise<unknown> {
  try {
    const response = await fetch(url, {
      ...init,
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new GitHubError("GitHub API request failed");
    return await response.json();
  } catch {
    // Don't include upstream bodies or credentials in OAuth errors or logs.
    throw new GitHubError("GitHub のログイン処理を完了できませんでした。");
  }
}

export async function githubIdentity(
  env: PlaygroundEnv,
  code: string,
  verifier: string,
): Promise<Identity> {
  const tokenResponse = await githubJson("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.GITHUB_CLIENT_ID!,
      client_secret: env.GITHUB_CLIENT_SECRET!,
      code,
      code_verifier: verifier,
      redirect_uri: `${env.PUBLIC_ORIGIN}/oauth/callback`,
    }),
  });
  const token = z
    .object({ access_token: z.string().min(1), token_type: z.string() })
    .safeParse(tokenResponse);
  if (!token.success) throw new GitHubError("GitHub の認可コードを交換できませんでした。");
  const userResponse = await githubJson("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${token.data.access_token}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "mcp-oauth-playground",
    },
  });
  const user = z
    .object({
      id: z.number().int().positive(),
      login: z.string().min(1),
      name: z.string().nullable(),
    })
    .safeParse(userResponse);
  if (!user.success) throw new GitHubError("GitHub のユーザー情報が不正です。");
  // The upstream token is used only here and is never stored or passed to MCP clients.
  return {
    id: String(user.data.id),
    login: user.data.login,
    name: user.data.name ?? user.data.login,
  };
}

export function isAllowed(identity: Identity, allowlist: string | undefined): boolean {
  if (!/^[1-9]\d*$/.test(identity.id)) return false;
  return (allowlist ?? "")
    .split(",")
    .map((id) => id.trim())
    .includes(identity.id);
}

export function createGitHubIdentityProvider(env: PlaygroundEnv): IdentityProvider {
  return {
    name: "GitHub",
    configured: Boolean(
      env.GITHUB_CLIENT_ID &&
      env.GITHUB_CLIENT_SECRET &&
      env.ALLOWED_GITHUB_USER_IDS?.split(",").some((id) => /^[1-9]\d*$/.test(id.trim())),
    ),
    authorizeUrl: (state, challenge) => githubAuthorizeUrl(env, state, challenge),
    exchangeCode: (code, verifier) => githubIdentity(env, code, verifier),
    isAllowed: (identity) => isAllowed(identity, env.ALLOWED_GITHUB_USER_IDS),
  };
}
