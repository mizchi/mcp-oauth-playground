import { defineHandler } from "void";
import { env } from "void/env";
import { localAuthorizationServer } from "./local-identity-provider";
import { authRateLimit } from "../src/http-guards";

export const handleLocalIdp = defineHandler(async (c) => {
  if (env.LOGIN_PROVIDER !== "local") return new Response("Not found", { status: 404 });
  const limited = await authRateLimit(c.req.raw, {
    PUBLIC_ORIGIN: env.PUBLIC_ORIGIN,
    AUTH_RATE_LIMITER: c.env.AUTH_RATE_LIMITER as RateLimit,
  });
  if (limited) return limited;
  return localAuthorizationServer(env.PUBLIC_ORIGIN).fetch(c.req.raw);
});
