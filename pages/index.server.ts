import { defineHandler, defineHead, type InferProps } from "void";
import { env } from "void/env";
import { MCP_SPEC_VERSION } from "../src/contracts";

export const loader = defineHandler(() => ({
  origin: env.PUBLIC_ORIGIN,
  specVersion: MCP_SPEC_VERSION,
  providerName: env.LOGIN_PROVIDER === "local" ? "ローカル認可サーバー" : "GitHub",
  loginConfigured:
    (import.meta.env.DEV && env.LOGIN_PROVIDER === "local") ||
    Boolean(
      env.LOGIN_PROVIDER === "github" &&
      env.GITHUB_CLIENT_ID &&
      env.GITHUB_CLIENT_SECRET &&
      env.ALLOWED_GITHUB_USER_IDS,
    ),
  dcrEnabled: env.ENABLE_DCR,
}));
export type Props = InferProps<typeof loader>;
export const head = defineHead(() => ({ title: "MCP OAuth Playground" }));
