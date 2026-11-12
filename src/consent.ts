import type { ConsentDescription } from "@cloudflare/workers-oauth-provider";

const escape = (value: string) =>
  value.replace(
    /[&<>"']/g,
    (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]!,
  );

export function consentPage(
  details: ConsentDescription,
  handle: string,
  providerName = "GitHub",
): string {
  const scopes: Record<string, string> = {
    "mcp:read": "ログインしたアカウントのプロフィールを確認",
    offline_access: "再ログインせずに MCP の接続を更新",
  };
  return `<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>MCP へのアクセスを許可</title><style>
  *{box-sizing:border-box}body{margin:0;background:#f6f7f9;color:#16202f;font:16px/1.7 system-ui,sans-serif}main{max-width:640px;margin:8vh auto;padding:32px;background:white;border:1px solid #dbe0e7;border-radius:16px}h1{font-size:26px;line-height:1.4}code{overflow-wrap:anywhere}.muted{color:#526074}.warning{padding:16px;background:#fff5d6;border-radius:8px}button{padding:12px 18px;border-radius:8px;border:1px solid #cad1da;cursor:pointer;font:inherit}button[value=approve]{background:#1749d1;color:white;border-color:#1749d1}form p{display:flex;gap:12px}@media(max-width:680px){main{margin:20px;padding:24px}}
  </style></head><body><main><p class="muted">MCP OAuth Playground</p><h1>${escape(details.clientName)} にアクセスを許可しますか？</h1>
  <p>${details.clientDomain ? `クライアントの公開元: <strong>${escape(details.clientDomain)}</strong>` : "このクライアント名は自己申告です。提供元の確認には使えません。"}</p>
  <p>認可後のリダイレクト先: <strong>${escape(details.redirectHost)}</strong></p>
  ${details.redirectIsLoopback ? '<p class="warning">この操作は、お使いのコンピューターのアプリにアクセスを許可します。そのアプリからログインを開始したことを確認してください。</p>' : ""}
  <h2>許可する操作</h2><ul>${details.scope.map((scope) => `<li>${escape(scopes[scope] ?? scope)} <code>${escape(scope)}</code></li>`).join("")}</ul>
  <p>許可すると ${escape(providerName)} のログイン画面に進みます。</p>
  <form method="post" action="/authorize"><input type="hidden" name="handle" value="${escape(handle)}"><p><button name="decision" value="approve">許可して ${escape(providerName)} へ</button><button name="decision" value="deny">拒否</button></p></form>
  </main></body></html>`;
}
