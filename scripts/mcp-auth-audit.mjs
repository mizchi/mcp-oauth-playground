#!/usr/bin/env node
import { parseArgs } from "node:util";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { auditServer, CHECK_IDS } from "./auth-audit/runner.mjs";
import { AuditError, validateUrl } from "./auth-audit/http.mjs";

const help = `Usage: node scripts/mcp-auth-audit.mjs --resource URL [options]

  --config FILE               JSON settings; adapter paths are relative to this file
  --resource URL              Protected MCP endpoint (HTTPS or loopback HTTP)
  --issuer URL                Select an advertised authorization server
  --allow-origin ORIGIN       Explicitly trust another discovery/endpoint origin; repeatable
  --client-id ID              Pre-registered client ID or HTTPS CIMD URL
  --client-secret-env NAME    Read a confidential client's Basic secret from an env var
  --redirect-uri URL          Registered callback URL (default http://localhost:3456/callback)
  --register                 Explicitly create a dedicated public DCR test client
  --adapter FILE             Trusted local module providing login/policy hooks
  --scope SCOPES             Space-separated baseline scopes
  --forbidden-scope SCOPE    A scope explicitly forbidden by target policy
  --allow-state-changes      Enable remove/restore and identity-reuse hooks on test accounts
  --expected-body-limit N    Send one bounded body above this expected limit (N <= 65536)
  --checks IDS               Comma-separated requested checks (discovery always included)
  --timeout-ms N             Per-request/hook timeout (1..120000; default 10000)
  --protocol-version VERSION MCP revision (default 2026-07-28)
  --json FILE                Write a credential-free JSON report; '-' writes JSON to stdout
  --help                     Show this help

Checks: ${CHECK_IDS.join(", ")}
Exit: 0=requested checks passed; 1=findings; 2=incomplete, error or invalid settings.
No request bursts are sent. A skipped/omitted check does not establish safety.
`;

const configKeys = new Set([
  "resource",
  "issuer",
  "allowedOrigins",
  "clientId",
  "clientSecretEnv",
  "redirectUri",
  "register",
  "adapter",
  "adapterOptions",
  "scopes",
  "forbiddenScope",
  "allowStateChanges",
  "timeoutMs",
  "maxRequests",
  "maxResponseBytes",
  "expectedBodyLimit",
  "protocolVersion",
  "checks",
  "probe",
]);

export async function main(argv = process.argv.slice(2)) {
  let values;
  try {
    ({ values } = parseArgs({
      args: argv,
      options: {
        help: { type: "boolean" },
        config: { type: "string" },
        resource: { type: "string" },
        issuer: { type: "string" },
        "allow-origin": { type: "string", multiple: true },
        "client-id": { type: "string" },
        "client-secret-env": { type: "string" },
        "redirect-uri": { type: "string" },
        register: { type: "boolean" },
        adapter: { type: "string" },
        scope: { type: "string" },
        "forbidden-scope": { type: "string" },
        "allow-state-changes": { type: "boolean" },
        "expected-body-limit": { type: "string" },
        checks: { type: "string" },
        "timeout-ms": { type: "string" },
        "protocol-version": { type: "string" },
        json: { type: "string" },
      },
    }));
  } catch {
    throw new AuditError("invalid_cli_arguments_use_help");
  }
  if (values.help) {
    process.stdout.write(help);
    return 0;
  }
  let settings = {};
  const base = values.config ? dirname(resolve(values.config)) : process.cwd();
  if (values.config) {
    try {
      settings = JSON.parse(await readFile(values.config, "utf8"));
    } catch {
      throw new AuditError("invalid_config_file");
    }
    if (
      !settings ||
      Array.isArray(settings) ||
      typeof settings !== "object" ||
      Object.keys(settings).some((key) => !configKeys.has(key))
    )
      throw new AuditError("unknown_config_field");
  }
  for (const [flag, key] of Object.entries({
    resource: "resource",
    issuer: "issuer",
    "client-id": "clientId",
    "redirect-uri": "redirectUri",
    register: "register",
    "forbidden-scope": "forbiddenScope",
    "allow-state-changes": "allowStateChanges",
    "protocol-version": "protocolVersion",
    "client-secret-env": "clientSecretEnv",
  })) {
    if (values[flag] !== undefined) settings[key] = values[flag];
  }
  if (values["allow-origin"]) settings.allowedOrigins = values["allow-origin"];
  if (values.scope !== undefined) settings.scopes = values.scope.split(" ").filter(Boolean);
  if (values.checks !== undefined) settings.checks = values.checks.split(",").filter(Boolean);
  if (values["timeout-ms"] !== undefined) settings.timeoutMs = Number(values["timeout-ms"]);
  if (values["expected-body-limit"] !== undefined)
    settings.expectedBodyLimit = Number(values["expected-body-limit"]);
  if (typeof settings.resource !== "string") throw new AuditError("resource_is_required");
  validateUrl(settings.resource);
  for (const key of ["allowedOrigins", "scopes", "checks"]) {
    if (
      settings[key] !== undefined &&
      (!Array.isArray(settings[key]) || settings[key].some((v) => typeof v !== "string"))
    )
      throw new AuditError("invalid_config_array");
  }
  for (const key of ["register", "allowStateChanges"]) {
    if (settings[key] !== undefined && typeof settings[key] !== "boolean")
      throw new AuditError("invalid_config_boolean");
  }
  if (settings.clientSecretEnv) {
    if (typeof settings.clientSecretEnv !== "string" || !process.env[settings.clientSecretEnv])
      throw new AuditError("client_secret_env_is_unset");
    settings.clientSecret = process.env[settings.clientSecretEnv];
  }
  const adapterPath = values.adapter
    ? resolve(values.adapter)
    : settings.adapter
      ? resolve(base, settings.adapter)
      : undefined;
  if (adapterPath) {
    try {
      const module = await import(pathToFileURL(adapterPath).href);
      settings.adapter = module.createAdapter
        ? await module.createAdapter(settings.adapterOptions ?? {})
        : module.default;
      if (!settings.adapter || typeof settings.adapter.authorize !== "function") throw new Error();
    } catch {
      throw new AuditError("adapter_load_failed");
    }
  } else settings.adapter = undefined;
  const report = await auditServer(settings);
  if (values.json) {
    const serialized = JSON.stringify(report, null, 2) + "\n";
    if (values.json === "-") process.stdout.write(serialized);
    else await writeFile(values.json, serialized, { mode: 0o600 });
  }
  if (values.json !== "-") {
    process.stdout.write(
      `Auth audit: ${report.outcome} (${report.requests} runner HTTP requests)\n`,
    );
    for (const check of report.checks)
      process.stdout.write(
        `${check.status.toUpperCase().padEnd(5)} ${check.id}: ${check.detail}\n`,
      );
    if (report.omittedChecks.length)
      process.stdout.write(`Not requested: ${report.omittedChecks.join(", ")}\n`);
  }
  return report.outcome === "fail" ? 1 : report.outcome === "incomplete" ? 2 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    process.exitCode = await main();
  } catch (error) {
    process.stderr.write(
      `Auth audit could not complete: ${error instanceof AuditError ? error.code : "runner_failed"}\n`,
    );
    process.exitCode = 2;
  }
}
