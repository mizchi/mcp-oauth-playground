# 他のサーバーに使える認証検証 CLI

```sh
node scripts/mcp-auth-audit.mjs --help
```

Node.js 24 以上で動き、検証器の本体は標準ライブラリだけを使用します。アプリの `src/`、Cloudflare の KV、Void、Vitest には依存しません。別のリポジトリに `scripts/mcp-auth-audit.mjs` と隣の `scripts/auth-audit/` を一緒にコピーできます。

検証するのは自分が管理するテスト環境と専用アカウントです。既存の実ユーザー用 OAuth client を流用すると、認可のやり直しによってその client の既存 grant を失効させる実装もあります。テスト用 client を使ってください。

## この playground に対して実行する

別のターミナルで起動します。

```sh
just dev-local
```

検証を実行します。

```sh
just audit-auth --config scripts/auth-audit/examples/playground-local.json --json /tmp/auth-audit.json
```

同梱の UI アダプターは Playwright を使用します。このリポジトリでは依存関係に含まれています。ブラウザが未導入なら `pnpm exec playwright install chromium` を実行します。

このアプリでは指摘された不備を修正済みです。`discovery`、`malformed-token-body`、`pkce`、`forbidden-scope` は PASS が期待値です。許可ポリシーや本人情報を変更するフックのない項目は SKIP になり、全項目を指定した場合の終了コードは 2 です。検証器のユニットテストでは、不備のある fixture で FAIL、対策済み fixture で PASS になることも確認します。

自動実行できる項目だけに絞り、16 KiB の body 制限も確認する例です。

```sh
just audit-auth --config scripts/auth-audit/examples/playground-local.json \
  --checks discovery,malformed-token-body,pkce,forbidden-scope,request-body-limit \
  --expected-body-limit 16384 --json /tmp/auth-audit.json
```

サンプルの redirect URI は `http://localhost:5173/oauth/audit-callback` です。ログイン画面の CSP に合わせて同じ origin を使い、アダプターは最終 callback リクエストの URL を観測します。受信 endpoint の実装や、固定の code を返すモックは必要ありません。ポートを変える場合は `--resource` と `--redirect-uri` の両方を変更します。

## 別のサーバーに対して実行する

認可サーバーも同じ origin にある場合の例です。

```sh
node scripts/mcp-auth-audit.mjs \
  --resource https://mcp.example.com/mcp \
  --client-id dedicated-audit-client \
  --redirect-uri http://localhost:3456/callback \
  --adapter ./my-server-adapter.mjs \
  --scope 'mcp:read offline_access' \
  --forbidden-scope 'mcp:admin' \
  --json ./auth-audit-result.json
```

`--forbidden-scope` には、そのサーバーのポリシーで明示的に禁止されている scope を指定します。`scopes_supported` は動的 scope を網羅しないことがあるため、「メタデータにない」という理由だけで権限昇格を断定しません。

認可サーバーが別 origin の場合は `--allow-origin https://auth.example.com` を追加します。複数の AS から選ぶ場合は `--issuer https://auth.example.com` を指定します。issuer は Protected Resource Metadata に載っているものと照合します。AS の endpoint がさらに別 origin にある場合も、明示的な `--allow-origin` が必要です。

HTTPS の CIMD URL は `--client-id https://client.example.com/client.json` として使用できます。DCR で client を作成するときは、client ID を省略して `--register` を指定します。DCR を勝手に有効化したり、実行ごとに無断で登録したりはしません。DCR で作った client 自体の削除 API はサーバーごとに異なるため、必要なら管理側で削除してください。

confidential client は `--client-secret-env AUDIT_CLIENT_SECRET` で環境変数から secret を読み込みます。現在サポートするクライアント認証は public client の `none` と `client_secret_basic` です。`private_key_jwt` や `client_secret_post` の追加は別途必要です。

古い MCP 実装では `--protocol-version 2025-11-25` など、実際に対応する revision を指定します。認証後の正常系プローブは既定で読み取り専用の `tools/list` です。別の操作が必要なら JSON 設定の `probe` を変更します。

```json
{
  "resource": "https://mcp.example.com/mcp",
  "clientId": "dedicated-audit-client",
  "redirectUri": "http://localhost:3456/callback",
  "adapter": "./my-server-adapter.mjs",
  "scopes": ["mcp:read", "offline_access"],
  "forbiddenScope": "mcp:admin",
  "probe": { "method": "tools/call", "params": { "name": "whoami", "arguments": {} } }
}
```

JSON の `adapter` は設定ファイルの場所からの相対パス、CLI の `--adapter` は実行ディレクトリからの相対パスです。secret の値は設定ファイルに入れず、`clientSecretEnv` と環境変数を使います。

## 判定と終了コード

| 状態  | 意味                                                           |
| ----- | -------------------------------------------------------------- |
| PASS  | 選択した条件について、正常系を含む検証が成立して防御を確認した |
| FAIL  | 対象の不備を観測した。再現に成功したことを PASS にはしない     |
| SKIP  | フック、資格情報、ポリシー情報などがなく、その項目は未検証     |
| ERROR | タイムアウトや前提条件の不成立で、判定できなかった             |

終了コードは 0 が要求した検査の全 PASS、1 が FAIL あり、2 が SKIP／ERROR を含む未完了、または設定エラーです。FAIL と未完了が両方ある場合は 1 を返し、JSON には両方を残します。

全項目を選ぶ既定モードでは rate limit の設定レビューなどが残るため、問題を検出しなくても未完了になる場合があります。CI で自動化済みの項目に絞るときは `--checks` を明示します。

```sh
node scripts/mcp-auth-audit.mjs --config ./audit.json \
  --checks discovery,malformed-token-body,pkce,forbidden-scope
```

`discovery` は前提として常に実行します。選ばなかった項目は JSON の `omittedChecks` に残し、PASS の対象には含めません。終了コード 0 は検査範囲全体や実装全体の安全宣言ではありません。

## 検査項目

| ID                     | 検証すること                                                             | 必要なもの                                         |
| ---------------------- | ------------------------------------------------------------------------ | -------------------------------------------------- |
| `discovery`            | 未認証時の challenge、PRM、issuer、AS metadata、S256 の広告              | MCP URL と、追加 origin の明示許可                 |
| `malformed-token-body` | 通常の不正 form は処理できるのに、小さな JSON body で 500 等にならないか | 公開 token endpoint                                |
| `pkce`                 | 正しいログインと MCP 呼び出しが成立し、不一致 verifier は拒否されるか    | テスト client と `authorize`                       |
| `forbidden-scope`      | 明示的に禁止した scope を token endpoint が付与しないか                  | `authorize` と `forbiddenScope`                    |
| `policy-access`        | 許可リストから削除した後、既存 token の利用が拒否されるか                | 削除・復元フックと状態変更の opt-in                |
| `policy-refresh`       | 正常に更新できることを確認した後、許可削除後の更新が拒否されるか         | 上と同じ、加えて refresh token                     |
| `identity-reuse`       | 同じ login を持つ別の不変 ID が認可されないか                            | 制御できる IdP、本人情報読取・入れ替え・復元フック |
| `request-body-limit`   | 期待する上限を少し超えた有限サイズの body が 413 になるか                | `expectedBodyLimit`、最大 65536 バイトまで         |
| `rate-limit`           | 設定レビュー／別途許可した負荷試験が必要                                 | この CLI は burst を送らず SKIP にする             |

未知の scope について、返された `scope` が省略されている場合は opaque token の権限を勝手に推測せず SKIP にします。署名を検証せず JWT をデコードして権限を断定することもしません。

PKCE 検査は不一致 verifier の確認です。plain への downgrade、コード再利用、期限切れ、CSRF、CIMD の SSRF、署名検証などをこのチェックだけで網羅したことにはなりません。

## アダプターの契約

型定義は `scripts/auth-audit/contracts.d.ts`、雛形は `scripts/auth-audit/adapters/template.mjs` です。アダプターはローカルの信頼したコードとして読み込み、URL から取得したコードは実行しません。

必須の `authorize` は実際のログイン・同意操作を行い、最終 callback URL を返します。検証器が redirect URI、state、`iss` を照合してから code を交換します。callback の code や state を作り替えて成功を装う実装にはしません。

任意のフックは次のとおりです。未実装なら export しないでください。何も操作しない成功用の stub を置くと検証の意味が失われます。

```js
export function createAdapter() {
  return {
    async authorize({ authorizationUrl, redirectUri, scenario, signal }) {
      // 実際のログイン画面を操作して最終 URL を返す。
    },
    async readIdentity({ resource, session, signal }) {
      // session.accessToken で対象を呼び、実際に返った { id, login } を返す。
    },
    async removeAccess({ resource, session, signal }) {
      // 専用アカウントの許可リストを管理 API 等で変更する。
    },
    async restoreAccess({ resource, session, signal }) {
      // removeAccess が途中で失敗した場合も復元する。失敗時は throw する。
    },
    async prepareIdentityReuse({ original, resource, session, signal }) {
      // 制御下の IdP で別 ID に同じ login を与え、その { id, login } を返す。
      // 実 GitHub のユーザー名取得を自動で試す用途には使わない。
    },
    async restoreIdentity({ resource, session, signal }) {
      // IdP 側の状態を元に戻す。
    },
    async dispose() {
      // ブラウザや接続を閉じる。
    },
  };
}
```

`policy-*` と `identity-reuse` は `--allow-state-changes` がある場合だけ変更フックを呼びます。復元は `finally` で試みます。復元失敗は ERROR にし、その後の identity 変更は中止します。管理 API の 4xx／5xx を成功とみなさず、アダプターで例外にしてください。

フックには `AbortSignal` を渡します。検証器にも期限がありますが、任意の JavaScript の副作用を強制的に取り消すことはできないので、アダプター自身も signal を尊重し、通信を止めて復元できるように実装します。

## 検証器自身の制限

- 既定は 1 HTTP request／フックにつき 10 秒、本文読取 64 KiB、runner の HTTP 通信は合計 60 回まで。上限を指定しても request 数は最大 200、response は最大 1 MiB です。ブラウザや管理 API などアダプター自身の通信は、この HTTP request 数とは別です。
- metadata や token endpoint の HTTP redirect は自動追従しません。URL は canonical なものを設定します。元の資格情報を redirect 先へ転送しません。
- HTTPS を要求し、HTTP は loopback だけ許可します。別 origin は明示許可が必要です。この origin 制限は、任意のネットワーク環境に対する DNS rebinding 対策の完全な代替にはなりません。
- レポートには token、code、secret、callback URL、相手の response body や例外の生文字列を出しません。アダプター側でも秘密情報をログに出さないでください。
- 発行された token はメモリだけに保持し、revocation endpoint が広告されていれば最後に失効を試みます。結果は JSON の `cleanup` に残します。endpoint がなければ `manual-required-no-revocation-endpoint` とし、専用アカウントを管理側で片付けます。

## 検証器のテスト

```sh
just test-audit
```

実 HTTP の正常・不備あり fixture、ログインの正例、state／issuer 不一致で交換しないこと、redirect に資格情報を送らないこと、body 上限、未検証の扱い、復元失敗、timeout、CLI の終了コードを検証します。通常の `just test` にも含まれています。

参照した仕様は [MCP Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)、[RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html)、[RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html) です。これは今回のレビューで見つけた境界を再検査するツールで、MCP/OAuth 全体の適合性試験や包括的な脆弱性スキャナーではありません。
