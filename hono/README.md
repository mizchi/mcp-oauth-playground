# Hono 版 MCP OAuth Playground

Hono 4.13.16 と Wrangler で動く Cloudflare Worker です。ルートは `app.ts` に明示し、トップページは HTML を返します。認可と MCP の処理はルートディレクトリの `src/` を Void 版と共有します。

## 起動する

リポジトリのルートから実行します。Node.js 24 以上と pnpm を使います。

```sh
pnpm install
just dev-hono-local
```

`http://localhost:8791/mcp` に MCP クライアントから接続します。同意後に「Alice としてログイン」を押し、`whoami` を実行すると `local-alice` のプロフィールを返します。GitHub の資格情報は不要です。既存の開発サーバーと衝突しないよう、Void 版の 5173 と別に 8791 を使っています。

Hono 版の起動・ビルド・専用の型チェックでは Void CLI、Vite、React、`.void/` の型生成を使いません。ルートの `pnpm install` は既存の Void 版の prepare も実行しますが、Hono の Worker にはこれらの依存を含めません。

## コードを読む順序

1. `index.ts`：本番の入口。`createHonoApp()` を export します。
2. `app.ts`：bindings を検証し、Hono にルートを登録します。
3. `../src/playground.ts`：同意画面、上流ログイン、callback、認可コード・トークン発行を追います。
4. `../src/mcp.ts`：Bearer token、許可ユーザー、スコープを検査して `whoami` を実行します。
5. `local.ts` と `../dev/local-authorization-server.ts`：検証用の上流認可サーバーを追います。

入口のルート定義は次の形です。

```ts
app.all("/authorize", oauth);
app.all("/oauth/*", oauth);
app.all("/mcp", oauth);
app.all("/.well-known/oauth-authorization-server", oauth);
app.all("/.well-known/oauth-protected-resource", oauth);
app.all("/.well-known/oauth-protected-resource/*", oauth);
```

`oauth` ハンドラーでは、`createPlayground(settings, provider).fetch(c.req.raw, c.executionCtx)` に Web 標準のリクエストと Workers の実行コンテキストを渡します。共通コアがパスごとの処理を選び、PKCE、Cookie/state、resource、スコープ、許可 ID、body・頻度制限を適用します。Hono はその `Response` を Cookie・リダイレクト・challenge ヘッダーごと返します。

| 経路                   | 処理                                                               |
| ---------------------- | ------------------------------------------------------------------ |
| `GET /`                | JavaScript を使わない接続案内                                      |
| `GET /authorize`       | クライアント・redirect URI・PKCE・スコープを検証して同意画面を表示 |
| `POST /authorize`      | Cookie と Origin を確認し、許可なら上流ログインへ遷移              |
| `GET /oauth/callback`  | state と本人情報を検証し、MCP 用の認可コードを発行                 |
| `POST /oauth/token`    | コード交換・トークン更新・失効                                     |
| `POST /oauth/register` | `ENABLE_DCR=true` の場合に専用クライアントを登録                   |
| `/mcp`                 | トークンを検証して MCP ツールを実行                                |
| `/.well-known/*`       | リソースと認可サーバーの discovery 情報                            |

認可サーバーのプロトコル処理と KV 管理には `@cloudflare/workers-oauth-provider` を使います。アプリが担当する認可判断と、ライブラリが担当するコード・トークンの検証は Void 版と同じです。対応表は [認可の実装](../docs/authorization.md) にあります。

## ローカル検証用の入口

`wrangler.local.jsonc` は `local.ts` を起動します。この入口が `/local-idp/*` とローカル issuer の discovery を追加し、共通コアへ `createLocalIdentityProvider` を注入します。

本番用の `wrangler.jsonc` は `index.ts` を起動します。検証用サーバーを import せず、`LOGIN_PROVIDER=local` を指定しても認可を拒否します。本番ビルドの依存グラフと実行結果でこの境界を検査します。

## GitHub で試す

```sh
cp hono/.dev.vars.example hono/.dev.vars
just dev-hono
```

`hono/.dev.vars` の Client ID と Secret を設定し、GitHub OAuth App の callback を `http://localhost:8791/oauth/callback` にします。許可 ID は `wrangler.jsonc` の `ALLOWED_GITHUB_USER_IDS=73962` です。Wrangler の設定に本番用の origin を置き、開発コマンドの `--var PUBLIC_ORIGIN:http://localhost:8791` で上書きします。

Void 版のルート `.env` と Hono 版の `hono/.dev.vars` は別の設定です。`ENABLE_DCR` の既定は文字列 `"false"` で、アプリの入口で boolean に変換します。DCR が必要なら設定を `"true"` に変更します。

## 検証する

```sh
pnpm test                 # 共通コア + Hono アダプター + 汎用検証器
pnpm typecheck:hono       # Void の生成型に依存しない型チェック
just e2e-hono             # 同じ Playwright シナリオを Hono に向ける
just test-production-hono # dry-run build と本番成果物の実行検査
```

E2E はローカル認証用 8791 と GitHub 境界確認用 8792 のサーバーを起動します。モバイル・デスクトップで同意、拒否、PKCE、MCP 呼び出し、更新、失効を確認します。

汎用検証 CLI もそのまま使えます。`just dev-hono-local` を別のターミナルで起動してから実行します。

```sh
just audit-auth --config scripts/auth-audit/examples/playground-local.json \
  --resource http://localhost:8791/mcp \
  --redirect-uri http://localhost:8791/oauth/audit-callback \
  --checks discovery,malformed-token-body,pkce,forbidden-scope,request-body-limit \
  --expected-body-limit 16384 --json /tmp/hono-auth-audit.json
```

## 公開環境への設定

`wrangler.jsonc` の `PUBLIC_ORIGIN` と `OAUTH_KV` のゼロ埋め ID は設定例です。公開する場合は実際の HTTPS origin と作成した KV namespace ID に変更し、本番用 GitHub OAuth App の資格情報を Wrangler の secrets に設定します。Rate Limiting の namespace ID もアカウント内で重複しない値にしてください。ローカル版の設定は公開用に使用しません。

`just build-hono` はアップロードしない dry-run build です。公開環境へのデプロイは実行していません。

参照: [Hono on Cloudflare Workers](https://hono.dev/docs/getting-started/cloudflare-workers)、[Wrangler configuration](https://developers.cloudflare.com/workers/wrangler/configuration/)。
