import { AuditError, createHttpClient } from "./http.mjs";
import { invoke } from "./hooks.mjs";
import {
  authorize,
  createClient,
  discover,
  obtainSession,
  rpcRequest,
  tokenRequest,
} from "./protocol.mjs";

export const CHECK_IDS = [
  "discovery",
  "malformed-token-body",
  "pkce",
  "forbidden-scope",
  "policy-access",
  "policy-refresh",
  "identity-reuse",
  "request-body-limit",
  "rate-limit",
];

/** @param {import('./contracts').AuditConfig} config @returns {Promise<import('./contracts').AuditReport>} */
export async function auditServer(config) {
  const requested = [...new Set(["discovery", ...(config.checks ?? CHECK_IDS)])];
  if (requested.some((id) => !CHECK_IDS.includes(id))) throw new AuditError("unknown_check_id");
  const http = createHttpClient(config);
  const checks = new Map();
  const wanted = (id) => requested.includes(id);
  const record = (id, status, detail) => checks.set(id, { id, status, detail });
  const skip = (id, reason) => {
    if (wanted(id) && !checks.has(id)) record(id, "skip", reason);
  };
  const attempt = async (id, fn) => {
    if (!wanted(id)) return;
    try {
      await fn();
    } catch (error) {
      record(id, "error", error instanceof AuditError ? error.code : "check_failed");
    }
  };
  const scopes = config.scopes ?? ["mcp:read", "offline_access"];
  const hook = (name, args) => invoke(config.adapter, name, args, config.timeoutMs);
  let metadata;
  let client;
  const cleanup = { issuedTokens: 0, revocation: "no-tokens", failed: 0 };

  async function validSession(scenario) {
    const session = await obtainSession(config, metadata, client, http, scopes, scenario);
    if (session.denied) throw new AuditError("positive_authorization_baseline_denied");
    const response = await http.request(config.resource, rpcRequest(config, session.accessToken));
    if (response.status !== 200 || !response.json?.result || response.json.error)
      throw new AuditError("positive_resource_baseline_failed_use_read_only_probe");
    return session;
  }

  async function malformedBody() {
    const control = await http.request(metadata.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", resource: config.resource }),
    });
    if (![400, 401, 415].includes(control.status))
      throw new AuditError("token_endpoint_error_control_unavailable");
    const response = await http.request(metadata.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    if ([400, 401, 415].includes(response.status) && !response.json?.access_token)
      record(
        "malformed-token-body",
        "pass",
        "Bounded JSON input is rejected without a server error.",
      );
    else if (response.status >= 500 || response.json?.access_token)
      record(
        "malformed-token-body",
        "fail",
        `Malformed input produced HTTP ${response.status}; inspect input handling.`,
      );
    else
      record(
        "malformed-token-body",
        "error",
        "Unexpected response; no safe conclusion about malformed input.",
      );
  }

  async function pkce() {
    await validSession("pkce-positive-control");
    const auth = await authorize(config, metadata, client, scopes, "pkce-wrong-verifier");
    if (auth.denied) throw new AuditError("negative_authorization_did_not_reach_code_exchange");
    const response = await tokenRequest(http, metadata, client, {
      grant_type: "authorization_code",
      redirect_uri: client.redirectUri,
      code: auth.code,
      code_verifier: "x".repeat(64),
      resource: config.resource,
    });
    if (response.status === 400 && response.json?.error === "invalid_grant")
      record("pkce", "pass", "A valid baseline works and a wrong verifier is rejected.");
    else if (response.status === 200 && response.json?.access_token)
      record("pkce", "fail", "The token endpoint accepted a wrong code_verifier.");
    else record("pkce", "error", "The wrong-verifier exchange was inconclusive.");
  }

  async function forbiddenScope() {
    if (!config.forbiddenScope || scopes.includes(config.forbiddenScope))
      return skip(
        "forbidden-scope",
        "Specify a scope that the target's policy explicitly forbids; metadata is not an exhaustive policy.",
      );
    await validSession("scope-positive-control");
    const result = await obtainSession(
      config,
      metadata,
      client,
      http,
      [...scopes, config.forbiddenScope],
      "forbidden-scope",
    );
    if (result.denied === "invalid_scope")
      return record("forbidden-scope", "pass", "The explicitly forbidden scope was rejected.");
    if (result.denied)
      return record(
        "forbidden-scope",
        "skip",
        "The login/consent was denied for another reason; scope enforcement was not established.",
      );
    if (typeof result.scope !== "string")
      return record(
        "forbidden-scope",
        "skip",
        "No authoritative granted scope was returned; opaque tokens are not decoded or assumed safe.",
      );
    if (result.scope.split(" ").includes(config.forbiddenScope))
      record(
        "forbidden-scope",
        "fail",
        "The explicitly forbidden scope was included in the granted scope.",
      );
    else
      record("forbidden-scope", "pass", "The returned granted scope excludes the forbidden scope.");
  }

  async function policyRemoval() {
    if (!wanted("policy-access") && !wanted("policy-refresh")) return true;
    if (
      !config.allowStateChanges ||
      !config.adapter?.removeAccess ||
      !config.adapter?.restoreAccess
    ) {
      for (const id of ["policy-access", "policy-refresh"])
        skip(
          id,
          "Requires removeAccess/restoreAccess hooks and explicit state-change opt-in for a test account.",
        );
      return true;
    }
    let session;
    let refreshSupported = false;
    let changed = false;
    let restored = true;
    try {
      session = await validSession("before-policy-removal");
      if (wanted("policy-refresh") && session.refreshToken) {
        const response = await tokenRequest(http, metadata, client, {
          grant_type: "refresh_token",
          refresh_token: session.refreshToken,
          resource: config.resource,
        });
        if (
          response.status === 200 &&
          typeof response.json?.access_token === "string" &&
          typeof response.json.refresh_token === "string"
        ) {
          session = {
            ...session,
            accessToken: response.json.access_token,
            refreshToken: response.json.refresh_token,
          };
          refreshSupported = true;
        }
      }
      const baseline = await http.request(config.resource, rpcRequest(config, session.accessToken));
      if (baseline.status !== 200 || !baseline.json?.result)
        throw new AuditError("policy_positive_control_failed");
      changed = true; // Restore is attempted even if the mutating hook partially fails.
      await hook("removeAccess", { resource: config.resource, session });
      await attempt("policy-access", async () => {
        const response = await http.request(
          config.resource,
          rpcRequest(config, session.accessToken),
        );
        if ([401, 403].includes(response.status))
          record(
            "policy-access",
            "pass",
            "Existing access was rejected after the adapter removed access.",
          );
        else if (response.status === 200 && response.json?.result)
          record(
            "policy-access",
            "fail",
            "Existing access still succeeds after the adapter removed access.",
          );
        else record("policy-access", "error", "Post-removal access was inconclusive.");
      });
      if (!refreshSupported)
        skip("policy-refresh", "A working refresh baseline was not available.");
      else
        await attempt("policy-refresh", async () => {
          const response = await tokenRequest(http, metadata, client, {
            grant_type: "refresh_token",
            refresh_token: session.refreshToken,
            resource: config.resource,
          });
          if (
            [400, 401, 403].includes(response.status) &&
            ["invalid_grant", "access_denied", "invalid_token"].includes(response.json?.error)
          )
            record(
              "policy-refresh",
              "pass",
              "Refresh is rejected after the adapter removed access.",
            );
          else if (response.status === 200 && response.json?.access_token)
            record(
              "policy-refresh",
              "fail",
              "Refresh still issues an access token after the adapter removed access.",
            );
          else record("policy-refresh", "error", "Post-removal refresh was inconclusive.");
        });
    } catch (error) {
      for (const id of ["policy-access", "policy-refresh"])
        if (wanted(id) && !checks.has(id))
          record(id, "error", error instanceof AuditError ? error.code : "policy_check_failed");
    } finally {
      if (changed) {
        try {
          await hook("restoreAccess", { resource: config.resource, session });
        } catch {
          record(
            "policy-cleanup",
            "error",
            "Access restoration failed; inspect the dedicated test account before continuing.",
          );
          restored = false;
        }
      }
    }
    return restored;
  }

  async function identityReuse() {
    if (
      !config.allowStateChanges ||
      !config.adapter?.readIdentity ||
      !config.adapter?.prepareIdentityReuse ||
      !config.adapter?.restoreIdentity
    )
      return skip(
        "identity-reuse",
        "Requires identity-reading and identity-reuse/restore hooks on a controlled IdP; cannot infer immutable-ID policy from HTTP alone.",
      );
    const session = await validSession("identity-original");
    const context = { resource: config.resource, session };
    const original = await hook("readIdentity", context);
    if (typeof original?.id !== "string" || typeof original.login !== "string")
      throw new AuditError("identity_hook_did_not_return_id_and_login");
    try {
      const replacement = await hook("prepareIdentityReuse", { ...context, original });
      if (
        typeof replacement?.id !== "string" ||
        replacement.id === original.id ||
        replacement.login !== original.login
      )
        throw new AuditError("replacement_must_have_same_login_and_different_durable_id");
      const result = await obtainSession(
        config,
        metadata,
        client,
        http,
        scopes,
        "identity-replacement",
      );
      if (result.denied === "access_denied")
        return record(
          "identity-reuse",
          "pass",
          "The controlled replacement identity was denied authorization.",
        );
      if (result.denied) throw new AuditError("identity_denied_for_unrelated_reason");
      const observed = await hook("readIdentity", { resource: config.resource, session: result });
      if (observed?.id !== replacement.id || observed.login !== replacement.login)
        throw new AuditError("replacement_login_not_observed_clear_browser_sessions");
      record(
        "identity-reuse",
        "fail",
        "A different durable identity using the allowlisted login was authorized.",
      );
    } finally {
      try {
        await hook("restoreIdentity", context);
      } catch {
        record(
          "identity-cleanup",
          "error",
          "Identity restoration failed; inspect the dedicated test identity.",
        );
      }
    }
  }

  try {
    await attempt("discovery", async () => {
      try {
        metadata = await discover(config, http);
        record(
          "discovery",
          "pass",
          "Protected resource, issuer, endpoints and S256 metadata were validated.",
        );
      } catch (error) {
        if (
          [
            "protected_resource_did_not_challenge",
            "pkce_s256_not_advertised",
            "invalid_resource_metadata",
            "invalid_authorization_metadata",
          ].includes(error.code)
        )
          record("discovery", "fail", error.code);
        else throw error;
      }
    });
    if (metadata) {
      await attempt("malformed-token-body", malformedBody);
      await attempt("request-body-limit", async () => {
        if (
          !Number.isInteger(config.expectedBodyLimit) ||
          config.expectedBodyLimit < 1 ||
          config.expectedBodyLimit > 65_536
        )
          return skip(
            "request-body-limit",
            "Supply an expected body limit of at most 65536 bytes; no unbounded load is sent.",
          );
        const response = await http.request(metadata.token_endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: "p=" + "x".repeat(config.expectedBodyLimit),
        });
        if (response.status === 413)
          record(
            "request-body-limit",
            "pass",
            "The bounded request above the configured limit was rejected with 413.",
          );
        else if (response.status >= 500)
          record(
            "request-body-limit",
            "fail",
            "The bounded oversized request produced a server error.",
          );
        else
          skip(
            "request-body-limit",
            "A different rejection does not prove a body limit exists; inspect configuration.",
          );
      });
      const loginChecks = [
        "pkce",
        "forbidden-scope",
        "policy-access",
        "policy-refresh",
        "identity-reuse",
      ];
      if (loginChecks.some(wanted) && config.adapter?.authorize) {
        try {
          client = await createClient(config, metadata, http);
        } catch (error) {
          for (const id of loginChecks)
            if (wanted(id))
              record(id, "error", error instanceof AuditError ? error.code : "client_setup_failed");
        }
        if (client) {
          await attempt("pkce", pkce);
          await attempt("forbidden-scope", forbiddenScope);
          if (await policyRemoval()) await attempt("identity-reuse", identityReuse);
          else
            skip("identity-reuse", "Previous policy cleanup failed; further mutation is disabled.");
        }
      }
      for (const id of loginChecks)
        skip(
          id,
          "Requires an authorization adapter and a dedicated pre-registered/CIMD client or explicit DCR registration.",
        );
    }
    skip(
      "rate-limit",
      "Rate limiting needs a configuration review or separately authorized load test; this runner does not send bursts.",
    );
  } finally {
    if (client?.issuedTokens.size) {
      cleanup.issuedTokens = client.issuedTokens.size;
      cleanup.revocation = metadata.revocation_endpoint
        ? "attempted"
        : "manual-required-no-revocation-endpoint";
      if (metadata.revocation_endpoint) {
        for (const token of client.issuedTokens) {
          try {
            const response = await tokenRequest(http, metadata, client, { token });
            if (response.status !== 200) cleanup.failed++;
          } catch {
            cleanup.failed++;
          }
        }
        if (cleanup.failed)
          record(
            "token-cleanup",
            "error",
            "Some token revocations failed; clean up the dedicated test account manually.",
          );
      }
    }
    if (config.adapter?.dispose) {
      try {
        await hook("dispose", {});
      } catch {
        record("adapter-cleanup", "error", "Adapter cleanup failed.");
      }
    }
  }
  for (const id of requested) skip(id, "A required discovery or setup step did not complete.");
  const results = [...checks.values()];
  return {
    version: 1,
    target: new URL(config.resource).origin + new URL(config.resource).pathname,
    outcome: results.some((c) => c.status === "fail")
      ? "fail"
      : results.some((c) => ["skip", "error"].includes(c.status))
        ? "incomplete"
        : "pass",
    requestedChecks: requested,
    omittedChecks: CHECK_IDS.filter((id) => !requested.includes(id)),
    checks: results,
    requests: http.requests,
    cleanup,
  };
}
