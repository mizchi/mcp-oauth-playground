import { createServer } from "../../snippets/mcp-oauth/server";

// Only GitHub's external API is simulated. The published server, Node client,
// PKCE, cookies, KV, MCP, refresh and revocation all execute their real code.
export default createServer({
  fetchGitHub: async (input, init) => {
    const url = String(input);
    if (url === "https://github.com/login/oauth/access_token") {
      const form = new URLSearchParams(String(init?.body));
      if (form.get("code") !== "fixture-github-code" || !form.get("code_verifier"))
        return Response.json({ error: "invalid_grant" }, { status: 400 });
      return Response.json({ access_token: "fixture-github-token", token_type: "bearer" });
    }
    if (url === "https://api.github.com/user")
      return Response.json({ id: 73962, login: "mizchi", name: "Test User" });
    throw new Error("Unexpected GitHub API URL");
  },
});
