import { createHash, randomBytes } from "node:crypto";
import { AuditError, validateUrl } from "./http.mjs";
import { invoke } from "./hooks.mjs";

export const secret = () => randomBytes(32).toString("base64url");

export function rpcRequest(config, token) {
  const probe = config.probe ?? { method: "tools/list" };
  const modern = (config.protocolVersion ?? "2026-07-28") >= "2026-07-28";
  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
    "MCP-Protocol-Version": config.protocolVersion ?? "2026-07-28",
    "Mcp-Method": probe.method,
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (probe.params?.name) headers["Mcp-Name"] = String(probe.params.name);
  const params = { ...probe.params };
  if (modern)
    params._meta = {
      "io.modelcontextprotocol/protocolVersion": headers["MCP-Protocol-Version"],
      "io.modelcontextprotocol/clientCapabilities": {},
    };
  return {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: probe.method, params }),
  };
}

export async function discover(config, http) {
  const resource = http.validate(config.resource);
  const challenge = await http.request(resource, rpcRequest(config));
  if (challenge.status !== 401)
    throw new AuditError(
      challenge.status >= 500 ? "resource_unavailable" : "protected_resource_did_not_challenge",
    );
  const metadataUrl = challenge.headers
    .get("www-authenticate")
    ?.match(/\bresource_metadata="([^"]+)"/i)?.[1];
  const paths = metadataUrl
    ? [metadataUrl]
    : [
        ...new Set([
          new URL(
            `/.well-known/oauth-protected-resource${resource.pathname === "/" ? "" : resource.pathname}`,
            resource,
          ).href,
          new URL("/.well-known/oauth-protected-resource", resource).href,
        ]),
      ];
  let metadata;
  for (const path of paths) {
    const response = await http.request(path);
    if (response.status === 200) {
      metadata = response.json;
      break;
    }
    if (response.status !== 404) throw new AuditError("resource_metadata_unavailable");
  }
  if (
    metadata?.resource !== config.resource ||
    !Array.isArray(metadata.authorization_servers) ||
    !metadata.authorization_servers.length
  )
    throw new AuditError("invalid_resource_metadata");
  const issuer = config.issuer ?? metadata.authorization_servers[0];
  if (!metadata.authorization_servers.includes(issuer))
    throw new AuditError("issuer_not_advertised_by_resource");
  const as = http.validate(issuer);
  const path = as.pathname === "/" ? "" : as.pathname.replace(/\/$/, "");
  const urls = [
    new URL(`/.well-known/oauth-authorization-server${path}`, as),
    new URL(`/.well-known/openid-configuration${path}`, as),
    new URL(`${path}/.well-known/openid-configuration`, as),
  ];
  let auth;
  for (const url of new Set(urls.map((u) => u.href))) {
    const response = await http.request(url);
    if (response.status === 200) {
      auth = response.json;
      break;
    }
    if (response.status !== 404) throw new AuditError("authorization_metadata_unavailable");
  }
  if (
    auth?.issuer !== issuer ||
    typeof auth.authorization_endpoint !== "string" ||
    typeof auth.token_endpoint !== "string"
  )
    throw new AuditError("invalid_authorization_metadata");
  if (
    !Array.isArray(auth.code_challenge_methods_supported) ||
    !auth.code_challenge_methods_supported.includes("S256")
  )
    throw new AuditError("pkce_s256_not_advertised");
  http.validate(auth.authorization_endpoint);
  http.validate(auth.token_endpoint);
  return auth;
}

export async function createClient(config, metadata, http) {
  const redirectUri = config.redirectUri ?? "http://localhost:3456/callback";
  validateUrl(redirectUri);
  if (config.clientId)
    return {
      id: config.clientId,
      redirectUri,
      secret: config.clientSecret,
      issuedTokens: new Set(),
    };
  if (!config.register) throw new AuditError("client_id_or_explicit_registration_required");
  if (!metadata.registration_endpoint)
    throw new AuditError("registration_not_supported_use_pre_registered_or_cimd_client");
  const response = await http.request(metadata.registration_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: `MCP Auth Audit ${secret().slice(0, 8)}`,
      redirect_uris: [redirectUri],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      application_type: "native",
    }),
  });
  if (response.status !== 201 || typeof response.json?.client_id !== "string")
    throw new AuditError("registration_failed");
  return { id: response.json.client_id, redirectUri, issuedTokens: new Set() };
}

export async function authorize(config, metadata, client, scopes, scenario) {
  const verifier = secret();
  const state = secret();
  const url = new URL(metadata.authorization_endpoint);
  for (const [key, value] of Object.entries({
    client_id: client.id,
    redirect_uri: client.redirectUri,
    response_type: "code",
    resource: config.resource,
    scope: scopes.join(" "),
    state,
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
  }))
    url.searchParams.set(key, value);
  const callback = await invoke(
    config.adapter,
    "authorize",
    { authorizationUrl: url.href, redirectUri: client.redirectUri, scenario },
    config.timeoutMs,
  );
  let received;
  try {
    received = new URL(callback);
  } catch {
    throw new AuditError("invalid_callback_url");
  }
  const expected = new URL(client.redirectUri);
  if (
    received.origin !== expected.origin ||
    received.pathname !== expected.pathname ||
    received.hash ||
    [...expected.searchParams].some(([k, v]) => received.searchParams.get(k) !== v)
  )
    throw new AuditError("callback_redirect_uri_mismatch");
  if (
    received.searchParams.getAll("state").length !== 1 ||
    received.searchParams.get("state") !== state
  )
    throw new AuditError("callback_state_mismatch");
  const issuer = received.searchParams.get("iss");
  if (
    (metadata.authorization_response_iss_parameter_supported && !issuer) ||
    (issuer !== null && issuer !== metadata.issuer) ||
    received.searchParams.getAll("iss").length > 1
  )
    throw new AuditError("callback_issuer_mismatch");
  if (received.searchParams.has("error")) {
    if (received.searchParams.has("code") || received.searchParams.getAll("error").length !== 1)
      throw new AuditError("ambiguous_callback");
    return { denied: received.searchParams.get("error") };
  }
  if (received.searchParams.getAll("code").length !== 1 || !received.searchParams.get("code"))
    throw new AuditError("callback_code_missing");
  return { code: received.searchParams.get("code"), verifier };
}

export async function tokenRequest(http, metadata, client, parameters) {
  const headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    Accept: "application/json",
  };
  const body = new URLSearchParams(parameters);
  if (client.secret) {
    const encode = (s) => new URLSearchParams({ v: s }).toString().slice(2);
    headers.Authorization = `Basic ${Buffer.from(`${encode(client.id)}:${encode(client.secret)}`).toString("base64")}`;
  } else body.set("client_id", client.id);
  const response = await http.request(
    parameters.token ? metadata.revocation_endpoint : metadata.token_endpoint,
    { method: "POST", headers, body },
  );
  if (response.status === 200) {
    for (const token of [response.json?.access_token, response.json?.refresh_token]) {
      if (typeof token === "string") client.issuedTokens.add(token);
    }
  }
  return response;
}

export async function obtainSession(config, metadata, client, http, scopes, scenario) {
  const auth = await authorize(config, metadata, client, scopes, scenario);
  if (auth.denied) return auth;
  const response = await tokenRequest(http, metadata, client, {
    grant_type: "authorization_code",
    redirect_uri: client.redirectUri,
    code: auth.code,
    code_verifier: auth.verifier,
    resource: config.resource,
  });
  if (response.status >= 400 && response.status < 500 && typeof response.json?.error === "string")
    return { denied: response.json.error };
  if (
    response.status !== 200 ||
    typeof response.json?.access_token !== "string" ||
    !/^bearer$/i.test(response.json.token_type ?? "")
  )
    throw new AuditError("token_exchange_failed");
  return {
    accessToken: response.json.access_token,
    refreshToken: response.json.refresh_token,
    scope: response.json.scope,
  };
}
