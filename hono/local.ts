import { createHonoApp } from "./app";
import {
  createLocalIdentityProvider,
  localAuthorizationServer,
} from "../dev/local-identity-provider";
import { authRateLimit } from "../src/http-guards";
import type { Handler } from "hono";
import type { HonoEnv } from "./app";

// Only wrangler.local.jsonc uses this entry point.
const app = createHonoApp({
  localIdentityProvider: (env) => createLocalIdentityProvider(env.PUBLIC_ORIGIN),
});
const localIdp: Handler<HonoEnv> = async (c) => {
  const settings = c.get("settings");
  if (settings.LOGIN_PROVIDER !== "local") return c.notFound();
  const limited = await authRateLimit(c.req.raw, settings);
  if (limited) return limited;
  return localAuthorizationServer(settings.PUBLIC_ORIGIN).fetch(c.req.raw);
};
app.all("/local-idp/*", localIdp);
app.all("/.well-known/oauth-authorization-server/local-idp", localIdp);
export default app;
