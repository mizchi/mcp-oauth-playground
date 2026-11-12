/**
 * Implement only the hooks supported by your dedicated test environment.
 * AuditAdapter is defined in ../contracts.d.ts. This module is trusted local code.
 * Do not log callback URLs, access/refresh tokens, client secrets or admin credentials.
 */
export function createAdapter() {
  return {
    async authorize({ authorizationUrl, redirectUri, scenario, signal }) {
      // Drive the real login/consent UI using Playwright or your HTTP test harness.
      // Use a fresh browser context or explicitly select the intended test identity.
      // Return the actual final callback URL. Do not fabricate code/state/issuer values.
      void authorizationUrl;
      void redirectUri;
      void scenario;
      void signal;
      throw new Error("Implement authorize for your test server");
    },
    // Optional hooks (do not define placeholders that return success):
    // readIdentity({ resource, session, signal }) -> { id, login } observed from the target
    // removeAccess({ resource, session, signal }) -> remove this test user's allowlist entry
    // restoreAccess({ resource, session, signal }) -> restore it, including after partial failure
    // prepareIdentityReuse({ resource, session, original, signal }) -> { id, login } for a
    //   controlled replacement identity with the same login and a different durable ID
    // restoreIdentity({ resource, session, signal }) -> restore controlled IdP state
    // dispose() -> close browser / sockets
  };
}
