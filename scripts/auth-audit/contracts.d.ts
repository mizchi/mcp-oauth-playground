export type CheckStatus = "pass" | "fail" | "skip" | "error";
export type CheckId =
  | "discovery"
  | "malformed-token-body"
  | "pkce"
  | "forbidden-scope"
  | "policy-access"
  | "policy-refresh"
  | "identity-reuse"
  | "request-body-limit"
  | "rate-limit";
export interface CheckResult {
  id: string;
  status: CheckStatus;
  detail: string;
}
export interface Identity {
  id: string;
  login: string;
}
export interface Session {
  accessToken: string;
  refreshToken?: string;
  scope?: string;
}
export interface HookContext {
  resource: string;
  session: Session;
  signal: AbortSignal;
}
export interface AuditAdapter {
  /** Return the final callback URL; runner validates redirect URI, state and issuer. */
  authorize(input: {
    authorizationUrl: string;
    redirectUri: string;
    scenario: string;
    signal: AbortSignal;
  }): Promise<string>;
  /** Read the actual authenticated identity from the target, never a fixed test value. */
  readIdentity?(input: HookContext): Promise<Identity>;
  /** Operate only on a dedicated test account. Runner always attempts the matching restore. */
  removeAccess?(input: HookContext): Promise<void>;
  restoreAccess?(input: HookContext): Promise<void>;
  prepareIdentityReuse?(input: HookContext & { original: Identity }): Promise<Identity>;
  restoreIdentity?(input: HookContext): Promise<void>;
  dispose?(): Promise<void>;
}
export interface AuditConfig {
  resource: string;
  issuer?: string;
  allowedOrigins?: string[];
  clientId?: string;
  clientSecret?: string;
  redirectUri?: string;
  register?: boolean;
  scopes?: string[];
  /** An explicitly forbidden scope according to the target's policy, not metadata alone. */
  forbiddenScope?: string;
  allowStateChanges?: boolean;
  adapter?: AuditAdapter;
  timeoutMs?: number;
  maxRequests?: number;
  maxResponseBytes?: number;
  expectedBodyLimit?: number;
  protocolVersion?: string;
  checks?: CheckId[];
  probe?: { method: string; params?: Record<string, unknown> };
}
export interface AuditReport {
  version: 1;
  target: string;
  outcome: "pass" | "fail" | "incomplete";
  requestedChecks: string[];
  omittedChecks: string[];
  checks: CheckResult[];
  requests: number;
  cleanup: { issuedTokens: number; revocation: string; failed: number };
}
