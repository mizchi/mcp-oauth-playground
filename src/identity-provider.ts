import type { Identity } from "./contracts";

export class IdentityProviderError extends Error {}

export interface IdentityProvider {
  name: string;
  configured: boolean;
  /** When advertised by an upstream AS, validate RFC 9207 issuer before code exchange. */
  issuer?: string;
  authorizeUrl(state: string, challenge: string): string;
  exchangeCode(code: string, verifier: string): Promise<Identity>;
  isAllowed(identity: Identity): boolean;
}
