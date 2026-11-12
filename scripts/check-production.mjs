import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Miniflare } from "miniflare";

const bundle = resolve(".cloudflare/output/v0/workers/default/bundle");
const config = JSON.parse(await readFile(resolve(bundle, "../worker.config.json"), "utf8"));
const modules = {};
for (const file of await readdir(bundle, { recursive: true })) {
  if (!file.endsWith(".js")) continue;
  const source = await readFile(resolve(bundle, file), "utf8");
  assert.doesNotMatch(
    source,
    /local-alice|playground-local/,
    `${file}: dev issuer included in production`,
  );
  modules[file] = { type: "esm", contents: source };
}

for (const bindings of [{}, { LOGIN_PROVIDER: "local" }]) {
  const runtime = new Miniflare({
    workers: [
      {
        config: {
          ...config,
          manifest: { mainModule: "index.js", modulesRoot: bundle, modules },
          assets: {
            ...config.assets,
            directory: resolve(bundle, "../assets"),
            hasUserWorker: true,
          },
          env: {
            ...config.env,
            ...Object.fromEntries(
              Object.entries(bindings).map(([key, value]) => [key, { type: "text", value }]),
            ),
          },
        },
      },
    ],
  });
  try {
    const request = (path) => runtime.dispatchFetch(`http://localhost:5173${path}`);
    for (const path of ["/local-idp/authorize", "/local-idp/token"]) {
      assert.equal((await request(path)).status, 404, path);
    }
    if (bindings.LOGIN_PROVIDER === "local") {
      const blocked = await request("/authorize");
      assert.equal(blocked.status, 503);
      assert.match(await blocked.text(), /Local login is available only during development/);
    } else {
      // No raw PUBLIC_ORIGIN binding: this must use the env schema default.
      const metadata = await request("/.well-known/oauth-protected-resource/mcp");
      assert.equal(metadata.status, 200, await metadata.clone().text());
      assert.equal((await metadata.json()).resource, "http://localhost:5173/mcp");
      assert.equal((await request("/mcp")).status, 401);
      // Exercise the real rate-limit binding in the built worker, before OAuth validation.
      let throttled = false;
      for (let i = 0; i < 80; i++) {
        const response = await runtime.dispatchFetch("http://localhost:5173/oauth/token", {
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
      assert.ok(throttled, "Production worker must enforce the auth rate limit");
      assert.equal(
        (await request("/.well-known/oauth-authorization-server/local-idp")).status,
        404,
      );
    }
  } finally {
    await runtime.dispose();
  }
}

console.log(
  "Production bundle: env defaults and auth rate limit work; local issuer excluded and disabled.",
);
