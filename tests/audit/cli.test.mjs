import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createServer } from "node:http";
import { once } from "node:events";
import { test } from "node:test";

const exec = promisify(execFile);
const script = new URL("../../scripts/mcp-auth-audit.mjs", import.meta.url).pathname;
async function run(args) {
  try {
    const result = await exec(process.execPath, [script, ...args]);
    return { ...result, code: 0 };
  } catch (error) {
    return { stdout: error.stdout, stderr: error.stderr, code: error.code };
  }
}

test("CLI help is standalone and invalid arguments exit 2 without echoing secrets", async () => {
  const help = await run(["--help"]);
  assert.equal(help.code, 0);
  assert.match(help.stdout, /--resource/);
  const missing = await run([]);
  assert.equal(missing.code, 2);
  const invalid = await run(["--unknown-secret-argument=secret-do-not-echo"]);
  assert.equal(invalid.code, 2);
  assert.equal(invalid.stderr.includes("secret-do-not-echo"), false);
});

test("CLI JSON output and exit codes distinguish selected pass, findings and incomplete", async () => {
  let origin;
  let protectedResource = true;
  const server = createServer((req, res) => {
    const send = (status, body, headers = {}) => {
      res.writeHead(status, { "content-type": "application/json", ...headers });
      res.end(JSON.stringify(body));
    };
    if (req.url === "/mcp")
      return send(
        protectedResource ? 401 : 200,
        {},
        {
          "www-authenticate": `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp"`,
        },
      );
    if (req.url === "/.well-known/oauth-protected-resource/mcp")
      return send(200, { resource: `${origin}/mcp`, authorization_servers: [origin] });
    if (req.url === "/.well-known/oauth-authorization-server")
      return send(200, {
        issuer: origin,
        authorization_endpoint: `${origin}/authorize`,
        token_endpoint: `${origin}/token`,
        code_challenge_methods_supported: ["S256"],
      });
    return send(404, {});
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  origin = `http://127.0.0.1:${server.address().port}`;
  try {
    const args = ["--resource", `${origin}/mcp`, "--json", "-"];
    const passed = await run([...args, "--checks", "discovery"]);
    assert.equal(passed.code, 0);
    const report = JSON.parse(passed.stdout);
    assert.equal(report.outcome, "pass");
    assert.ok(report.omittedChecks.includes("policy-access"));
    const incomplete = await run([...args, "--checks", "discovery,rate-limit"]);
    assert.equal(incomplete.code, 2);
    assert.equal(JSON.parse(incomplete.stdout).outcome, "incomplete");
    protectedResource = false;
    const failed = await run([...args, "--checks", "discovery"]);
    assert.equal(failed.code, 1);
    assert.equal(JSON.parse(failed.stdout).outcome, "fail");
  } finally {
    await new Promise((resolve) => {
      server.close(resolve);
      server.closeAllConnections();
    });
  }
});
