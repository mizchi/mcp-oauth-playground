import { boolean, defineEnv, oneOf, string, url } from "void/env";

export default defineEnv({
  PUBLIC_ORIGIN: url().default("http://localhost:5173"),
  LOGIN_PROVIDER: oneOf(["github", "local"]).default("github"),
  GITHUB_CLIENT_ID: string().optional(),
  GITHUB_CLIENT_SECRET: string().optional(),
  ALLOWED_GITHUB_USER_IDS: string().optional(),
  ENABLE_DCR: boolean().default(false),
});
