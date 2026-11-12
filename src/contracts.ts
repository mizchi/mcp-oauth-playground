import type { AuthRequest } from "@cloudflare/workers-oauth-provider";

export const MCP_SPEC_VERSION = "2026-07-28";
export const SCOPES = ["mcp:read", "offline_access"];

export function supportedScopes(scopes: readonly string[]): boolean {
  return scopes.every((scope) => SCOPES.includes(scope));
}

export interface Identity {
  id: string;
  login: string;
  name: string;
}

export interface PlaygroundEnv {
  OAUTH_KV: KVNamespace;
  AUTH_RATE_LIMITER: Pick<RateLimit, "limit">;
  PUBLIC_ORIGIN: string;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  ALLOWED_GITHUB_USER_IDS?: string;
  ENABLE_DCR: boolean;
}

export function authorizationErrorUrl(request: AuthRequest, error: string): string {
  const url = new URL(request.redirectUri);
  url.searchParams.set("error", error);
  url.searchParams.set("state", request.state);
  url.searchParams.set("iss", request.issuer!);
  return url.href;
}
