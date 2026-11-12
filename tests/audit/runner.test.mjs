import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { once } from "node:events";
import { test } from "node:test";
import { auditServer } from "../../scripts/auth-audit/runner.mjs";
import { createHttpClient } from "../../scripts/auth-audit/http.mjs";

async function fixture(options = {}) {
  const codes = new Map();
  const access = new Set();
  const refresh = new Set();
  const seen = [];
  let allowed = true;
  let identity = { id: "user-1", login: "same-login" };
  let next = 0;
  let origin;
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, origin);
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString();
    const form = new URLSearchParams(body);
    seen.push({ path: url.pathname, body, authorization: req.headers.authorization });
    const send = (status, data, headers = {}) => {
      res.writeHead(status, { "content-type": "application/json", ...headers });
      res.end(JSON.stringify(data));
    };
    if (url.pathname === "/redirect") return send(302, {}, { location: `${origin}/capture` });
    if (url.pathname === "/large") return send(200, { padding: "x".repeat(1024) });
    if (url.pathname === "/.well-known/oauth-protected-resource/mcp")
      return send(200, {
        resource: `${origin}/mcp`,
        authorization_servers: [options.untrustedIssuer ? "https://untrusted.invalid" : origin],
        scopes_supported: ["mcp:read"],
      });
    if (url.pathname === "/.well-known/oauth-authorization-server")
      return send(200, {
        issuer: origin,
        authorization_endpoint: `${origin}/authorize`,
        token_endpoint: `${origin}/token`,
        revocation_endpoint: `${origin}/revoke`,
        registration_endpoint: `${origin}/register`,
        code_challenge_methods_supported: ["S256"],
        authorization_response_iss_parameter_supported: true,
      });
    if (url.pathname === "/revoke") {
      access.delete(form.get("token"));
      refresh.delete(form.get("token"));
      return send(200, {});
    }
    if (url.pathname === "/register")
      return send(201, { client_id: "audit-client", token_endpoint_auth_method: "none" });
    if (url.pathname === "/mcp") {
      if (
        !access.has(req.headers.authorization?.replace(/^Bearer /, "")) ||
        (!allowed && !options.stalePolicy)
      )
        return send(
          401,
          { error: "invalid_token" },
          {
            "www-authenticate": `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp"`,
          },
        );
      return send(200, { jsonrpc: "2.0", id: 1, result: { tools: [] } });
    }
    if (url.pathname === "/token") {
      if (req.headers["content-type"]?.startsWith("application/json"))
        return send(options.jsonCrash ? 500 : 400, { error: "invalid_request" });
      if (form.get("grant_type") === "refresh_token") {
        if (!refresh.has(form.get("refresh_token")) || (!allowed && !options.stalePolicy))
          return send(400, { error: "invalid_grant" });
      } else {
        const code = form.get("code");
        const record = codes.get(code);
        codes.delete(code);
        if (options.rejectAll) return send(400, { error: "invalid_grant" });
        if (
          !record ||
          createHash("sha256")
            .update(form.get("code_verifier") ?? "")
            .digest("base64url") !== record.challenge
        )
          return send(400, { error: "invalid_grant" });
        if (record.scope.includes("mcp:forbidden") && !options.unknownScope)
          return send(400, { error: "invalid_scope" });
        const token = `secret-access-${++next}`;
        access.add(token);
        const rt = `secret-refresh-${next}`;
        refresh.add(rt);
        return send(200, {
          access_token: token,
          refresh_token: rt,
          token_type: "Bearer",
          scope: options.omitScope ? undefined : record.scope,
        });
      }
      const token = `secret-access-${++next}`;
      access.add(token);
      const rt = `secret-refresh-${next}`;
      refresh.add(rt);
      return send(200, { access_token: token, refresh_token: rt, token_type: "Bearer" });
    }
    return send(404, { error: "not_found" });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  origin = `http://127.0.0.1:${server.address().port}`;
  const adapter = {
    async authorize({ authorizationUrl, redirectUri }) {
      const url = new URL(authorizationUrl);
      const target = new URL(redirectUri);
      target.searchParams.set(
        "state",
        options.badState ? "wrong-state" : url.searchParams.get("state"),
      );
      target.searchParams.set("iss", options.badIssuer ? "https://attacker.invalid" : origin);
      if (!allowed || (identity.id === "user-2" && !options.usernameReuse)) {
        target.searchParams.set("error", "access_denied");
      } else {
        const code = `secret-code-${++next}`;
        codes.set(code, {
          challenge: url.searchParams.get("code_challenge"),
          scope: url.searchParams.get("scope"),
        });
        target.searchParams.set("code", code);
      }
      return target.href;
    },
    readIdentity: async () => ({ ...identity }),
    removeAccess: async () => {
      allowed = false;
    },
    restoreAccess: async () => {
      allowed = true;
    },
    prepareIdentityReuse: async () => {
      identity = { id: "user-2", login: "same-login" };
      return { ...identity };
    },
    restoreIdentity: async () => {
      identity = { id: "user-1", login: "same-login" };
    },
  };
  return {
    config: {
      resource: `${origin}/mcp`,
      redirectUri: "http://localhost:3456/callback",
      register: true,
      scopes: ["mcp:read", "offline_access"],
      forbiddenScope: "mcp:forbidden",
      allowStateChanges: true,
      adapter,
    },
    seen,
    adapter,
    close: () =>
      new Promise((resolve) => {
        server.close(resolve);
        server.closeAllConnections();
      }),
  };
}

test("discovers endpoints, checks PKCE and scope, and verifies policy removal over HTTP", async () => {
  const f = await fixture();
  try {
    const report = await auditServer(f.config);
    for (const id of [
      "discovery",
      "malformed-token-body",
      "pkce",
      "forbidden-scope",
      "policy-access",
      "policy-refresh",
      "identity-reuse",
    ]) {
      assert.equal(report.checks.find((c) => c.id === id)?.status, "pass", id);
    }
    assert.equal(report.outcome, "incomplete"); // Rate limits require a separate configuration/load review.
    assert.equal(JSON.stringify(report).includes("secret-"), false);
    assert.equal(report.cleanup.revocation, "attempted");
    assert.equal(report.cleanup.failed, 0);
  } finally {
    await f.close();
  }
});

test("detects the reviewed flaws instead of treating reproduction as a pass", async () => {
  const f = await fixture({
    stalePolicy: true,
    unknownScope: true,
    jsonCrash: true,
    usernameReuse: true,
  });
  try {
    const report = await auditServer(f.config);
    for (const id of [
      "malformed-token-body",
      "forbidden-scope",
      "policy-access",
      "policy-refresh",
      "identity-reuse",
    ]) {
      assert.equal(report.checks.find((c) => c.id === id)?.status, "fail", id);
    }
    assert.equal(report.outcome, "fail");
    assert.equal(JSON.stringify(report).includes("secret-"), false);
  } finally {
    await f.close();
  }
});

test("missing hooks are skipped and are never reported as safe", async () => {
  const f = await fixture();
  try {
    const report = await auditServer({ ...f.config, adapter: undefined, register: false });
    assert.equal(report.checks.find((c) => c.id === "policy-access").status, "skip");
    assert.equal(report.checks.find((c) => c.id === "identity-reuse").status, "skip");
    assert.equal(report.outcome, "incomplete");
    assert.equal(
      f.seen.some((r) => r.path === "/register"),
      false,
    );
  } finally {
    await f.close();
  }
});

test("never exchanges a code after a state or issuer mismatch", async () => {
  for (const option of ["badState", "badIssuer"]) {
    const f = await fixture({ [option]: true });
    try {
      const report = await auditServer(f.config);
      assert.equal(report.checks.find((c) => c.id === "pkce").status, "error");
      assert.equal(
        f.seen.some((r) => r.path === "/token" && r.body.includes("code=secret-code")),
        false,
      );
    } finally {
      await f.close();
    }
  }
});

test("does not run mutation hooks without explicit state-change opt-in", async () => {
  const f = await fixture();
  let called = false;
  f.adapter.removeAccess = async () => {
    called = true;
  };
  f.adapter.prepareIdentityReuse = async () => {
    called = true;
  };
  try {
    const report = await auditServer({ ...f.config, allowStateChanges: false });
    assert.equal(called, false);
    assert.equal(report.checks.find((c) => c.id === "policy-access").status, "skip");
  } finally {
    await f.close();
  }
});

test("rejects unapproved metadata origins before making a request to them", async () => {
  const f = await fixture({ untrustedIssuer: true });
  try {
    const report = await auditServer(f.config);
    assert.equal(
      report.checks.find((c) => c.id === "discovery").detail,
      "origin_not_explicitly_allowed",
    );
    assert.equal(report.outcome, "incomplete");
  } finally {
    await f.close();
  }
});

test("the HTTP client does not follow redirects carrying credentials and bounds response size", async () => {
  const f = await fixture();
  try {
    const http = createHttpClient({ ...f.config, maxResponseBytes: 64 });
    const origin = new URL(f.config.resource).origin;
    const response = await http.request(`${origin}/redirect`, {
      method: "POST",
      headers: { Authorization: "Bearer secret-test" },
      body: "secret-test",
    });
    assert.equal(response.status, 302);
    assert.equal(
      f.seen.some((r) => r.path === "/capture"),
      false,
    );
    await assert.rejects(http.request(`${origin}/large`), { code: "response_size_limit_exceeded" });
  } finally {
    await f.close();
  }
});

test("a server that rejects every code does not get a PKCE pass", async () => {
  const f = await fixture({ rejectAll: true });
  try {
    const report = await auditServer({ ...f.config, checks: ["pkce"] });
    assert.equal(report.checks.find((c) => c.id === "pkce").status, "error");
  } finally {
    await f.close();
  }
});

test("an opaque token without returned scope is inconclusive", async () => {
  const f = await fixture({ unknownScope: true, omitScope: true });
  try {
    const report = await auditServer({ ...f.config, checks: ["forbidden-scope"] });
    assert.equal(report.checks.find((c) => c.id === "forbidden-scope").status, "skip");
  } finally {
    await f.close();
  }
});

test("cleanup failures are visible and stop further identity mutation", async () => {
  const f = await fixture();
  let mutated = false;
  f.adapter.restoreAccess = async () => {
    throw new Error("secret-admin-token");
  };
  f.adapter.prepareIdentityReuse = async () => {
    mutated = true;
  };
  try {
    const report = await auditServer(f.config);
    assert.equal(report.checks.find((c) => c.id === "policy-cleanup").status, "error");
    assert.equal(mutated, false);
    assert.equal(JSON.stringify(report).includes("secret-admin-token"), false);
  } finally {
    await f.close();
  }
});

test("an authorization hook that ignores its signal is bounded by a deadline", async () => {
  const f = await fixture();
  f.adapter.authorize = async () => new Promise(() => {});
  try {
    const report = await auditServer({ ...f.config, checks: ["pkce"], timeoutMs: 100 });
    assert.equal(report.checks.find((c) => c.id === "pkce").detail, "adapter_timed_out");
    assert.equal(report.outcome, "incomplete");
  } finally {
    await f.close();
  }
});
