# 認可仕様との対応

確認日: 2026-11-05。基準は [MCP 2026-07-28 Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) です。draft は実装の基準に含めていません。

## 参考記事からの更新点

[参考記事](https://zenn.dev/luoxi/articles/mcp-auth-oauth-from-scratch) は公開時点の仕様と draft を扱っています。現行の公開版では次の点を追加で確認しました。

- [クライアント登録](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration)：CIMD を推奨し、DCR は後方互換用として非推奨。この実装では CIMD を有効化し、DCR は設定による opt-in にした。
- [認可レスポンス](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation)：AS による `iss` の付与は SHOULD。対応を広告する場合、クライアントは `iss` を必ず検証する。この AS は成功・拒否・検証済み redirect へのエラーで `iss` を返す。
- [基本プロトコル](https://modelcontextprotocol.io/specification/2026-07-28/basic)：接続単位の初期化に依存せず、各リクエストの `params._meta` に protocol version と client capabilities を含める。SDK v2 の `createMcpHandler` が処理し、従来の 2025 系クライアントには stateless fallback を使う。

Cloudflare 側も [OAuthAuthorizationServer / OAuthResourceServer](https://developers.cloudflare.com/agents/model-context-protocol/protocol/authorization/) の API に更新されています。同じ Worker で両ロールを構成できるため、Void のルーティングの内側でそれぞれを作成しています。将来別 Worker に分離する場合は、トークン検証の関数を Service Binding に置き換えられます。

## 仕様要件とコード

| 要件                                 | 実装・検証                                                                                                                                                                                     |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| RFC 9728 Protected Resource Metadata | `/mcp` に対応する `/.well-known/oauth-protected-resource/mcp` を公開。401 の `WWW-Authenticate` に URL と `mcp:read` を載せる                                                                  |
| RFC 8414 AS Metadata                 | issuer、認可／トークンエンドポイント、S256、CIMD、`iss` 対応を広告                                                                                                                             |
| PKCE S256                            | 認可時に必須化。verifier の検証とコードの一回使用は公式 Provider が担当                                                                                                                        |
| RFC 8707 resource                    | 認可とトークン取得・更新で必須化。単一 resource のライブラリ既定動作より厳密にチェック                                                                                                         |
| audience・有効期限                   | 公式 Provider が保存済みトークンを検証し、ResourceServer が対象 resource と期限を確認。他の MCP 向けの token は 401                                                                            |
| scope                                | アプリで `mcp:read` を明示的に検証。不足時は 403 と `insufficient_scope` challenge                                                                                                             |
| Bearer token                         | ヘッダーでのみ受付。query の `access_token` は拒否                                                                                                                                             |
| redirect URI                         | Provider が登録済み URI と照合。未検証の URI にはリダイレクトしない                                                                                                                            |
| 明示的な同意                         | クライアント名、CIMD のドメイン、権限、redirect host、loopback の注意を表示。外部 metadata は HTML エスケープ                                                                                  |
| 同意・上流 OAuth の CSRF             | Provider のブラウザに紐づく Cookie とサーバー側 handle/state に加え、同意 POST の Origin を検証                                                                                                |
| token passthrough 禁止               | GitHub token を `/user` にだけ使用し破棄。MCP には別 token を発行。whoami は identity だけ返す                                                                                                 |
| refresh / revocation                 | 10 分の access token、7 日の refresh token。rotation と RFC 7009 失効は Provider が担当                                                                                                        |
| CIMD と SSRF                         | IP リテラル・localhost・HTTP の client URL を認可時の fetch 前に拒否。`global_fetch_strictly_public` で private network への fetch も制限。ライブラリが文書の内容、URI、サイズ、timeout を検証 |

対応する主なテストは `tests/auth.test.ts` にあります。同意・GitHub state、コード再利用、PKCE 不一致、resource 不一致、scope 不足、トークンの期限切れ・更新・失効、CIMD、DCR 設定、untrusted Origin を Workers ランタイムで検証します。

## この実験の境界

GitHub と独立に PKCE の検証側を実装するため、[自作のローカル認可サーバー](local-authorization-server.md) を追加しています。`just dev-local` ではこのサーバーでログインし、MCP 呼び出しまでモックなしで検証します。ここに記載する MCP 向けの認可サーバーは引き続き Cloudflare Provider を使用し、自作サーバーは別 issuer の上流認可サーバーとして動作します。

これは OAuth の実装方法を確認する playground です。ユーザー管理や任意の上流 API 操作は追加していません。許可リストと grant の本人識別には GitHub の数値 ID を使い、login は表示用です。許可ポリシーはログイン完了時、コード交換・更新時、MCP アクセス時に再検査します。拒否されたコード交換・更新では grant も失効させます。

KV は強整合なトランザクションストアではありません。Provider の [同意／上流ヘルパーの保証](https://github.com/cloudflare/workers-oauth-provider/blob/main/docs/upstream-sign-in.md) も、同一ブラウザからの完全同時実行について原子的な single-use を保証していません。厳密な同時実行制御が必要な用途では、Durable Object などを用いた設計を別途検討します。

GitHub をログインにだけ使うため、GitHub 側で OAuth App の認可を取り消しても、既に発行済みの MCP grant を自動失効させる連携はありません。MCP token の失効は公開 AS metadata の `revocation_endpoint` に対して行います。

## 一次資料

- [MCP Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [MCP Authorization Security Considerations](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)
- [Cloudflare Workers OAuth Provider](https://github.com/cloudflare/workers-oauth-provider)
- [Consent helpers](https://github.com/cloudflare/workers-oauth-provider/blob/main/docs/consent-page.md)
- [Upstream sign-in](https://github.com/cloudflare/workers-oauth-provider/blob/main/docs/upstream-sign-in.md)
- [MCP TypeScript SDK v2](https://ts.sdk.modelcontextprotocol.io/v2/)
- [GitHub OAuth App web application flow](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#web-application-flow)
