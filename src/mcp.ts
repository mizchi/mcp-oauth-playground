import {
  OAuthResourceServer,
  insufficientScope,
  type OAuthAuthorizationServer,
} from "@cloudflare/workers-oauth-provider";
import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { supportedScopes, type Identity, type PlaygroundEnv } from "./contracts";
import type { IdentityProvider } from "./identity-provider";

export function createResourceServer(
  env: PlaygroundEnv,
  authorizationServer: OAuthAuthorizationServer<PlaygroundEnv>,
  identityProvider: IdentityProvider,
) {
  return new OAuthResourceServer<PlaygroundEnv, Identity>({
    resourceMetadata: {
      resource: `${env.PUBLIC_ORIGIN}/mcp`,
      authorization_servers: [env.PUBLIC_ORIGIN],
      resource_name: "MCP OAuth Playground",
    },
    requiredScopes: ["mcp:read"],
    validateToken: (bindings) => async (resource, token) => {
      const validated = await authorizationServer.validateToken<Identity>(
        resource,
        token,
        bindings,
      );
      if (
        !validated ||
        !identityProvider.isAllowed(validated.props) ||
        !supportedScopes(validated.scope ?? [])
      )
        return null;
      return validated;
    },
    handler: {
      fetch(request, _bindings, ctx) {
        if (!ctx.auth.scope.includes("mcp:read")) return insufficientScope(ctx.auth, ["mcp:read"]);
        // Fresh server per request: no user identity or session is shared across requests.
        const handler = createMcpHandler(() => {
          const server = new McpServer({ name: "mcp-oauth-playground", version: "0.1.0" });
          server.registerTool(
            "whoami",
            {
              title: "ログイン中のユーザー",
              description: "この MCP 接続を許可したユーザーを返します。",
              inputSchema: z.object({}),
              annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
            },
            () => ({ content: [{ type: "text", text: JSON.stringify(ctx.props) }] }),
          );
          return server;
        });
        return handler.fetch(request);
      },
    },
  });
}
