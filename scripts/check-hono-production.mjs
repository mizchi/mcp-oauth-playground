import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { createTestHarness } from "wrangler";

const root = resolve("hono");
const output = resolve(root, ".wrangler/hono-build");
const source = await readFile(resolve(output, "index.js"), "utf8");
const metadata = JSON.parse(await readFile(resolve(output, "bundle-meta.json"), "utf8"));
assert.doesNotMatch(source, /local-alice|playground-local/, "Local issuer included in production");
for (const input of Object.keys(metadata.inputs)) {
  assert.doesNotMatch(input, /\/node_modules\/(?:void|@void\/react|react|react-dom)\//);
  assert.doesNotMatch(input, /\/dev\/local-/);
}

// Wrangler resolves its tsconfig relative to cwd as well as the config's directory.
process.chdir(root);
const origin = "http://localhost:8791";
for (const login of ["github", "local"]) {
  const server = createTestHarness({
    workers: [
      {
        configPath: "wrangler.jsonc",
        prebuiltWorkerDir: ".wrangler/hono-build",
        vars: { PUBLIC_ORIGIN: origin, LOGIN_PROVIDER: login },
      },
    ],
  });
  try {
    await server.listen();
    const request = (path, init) => server.getWorker().fetch(`${origin}${path}`, init);
    for (const path of [
      "/local-idp/authorize",
      "/local-idp/token",
      "/.well-known/oauth-authorization-server/local-idp",
    ])
      assert.equal((await request(path)).status, 404);
    if (login === "local") {
      assert.equal((await request("/authorize")).status, 503);
      continue;
    }
    const metadataResponse = await request("/.well-known/oauth-protected-resource/mcp");
    assert.equal(metadataResponse.status, 200);
    assert.equal((await metadataResponse.json()).resource, `${origin}/mcp`);
    assert.equal((await request("/mcp")).status, 401);
    let throttled = false;
    for (let i = 0; i < 80; i++) {
      const response = await request("/oauth/token", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      if (response.status === 429) {
        assert.equal(response.headers.get("Retry-After"), "60");
        throttled = true;
        break;
      }
      assert.equal(response.status, 400, await response.clone().text());
    }
    assert.ok(throttled, "Built Hono worker must enforce the auth rate limit");
  } finally {
    await server.close();
  }
}
console.log(
  "Hono production: discovery and rate limit work; Void, React and local issuer excluded.",
);
