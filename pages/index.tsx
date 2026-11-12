import { useState } from "react";
import type { Props } from "./index.server";

export default function Home({
  origin,
  specVersion,
  providerName,
  loginConfigured,
  dcrEnabled,
}: Props) {
  const [copied, setCopied] = useState(false);
  const endpoint = `${origin}/mcp`;
  return (
    <main>
      <p className="eyebrow">CLOUDFLARE WORKERS · VOID</p>
      <h1>
        MCP OAuth
        <br />
        Playground<span>.</span>
      </h1>
      <p className="intro">
        {providerName}でログインして、MCP クライアントに必要なアクセスを許可する。
      </p>
      <section aria-labelledby="connect-title">
        <h2 id="connect-title">クライアントから接続</h2>
        <p>MCP 対応クライアントに次の URL を登録してください。接続すると認可画面が開きます。</p>
        <div className="endpoint">
          <code>{endpoint}</code>
          <button
            onClick={async () => {
              await navigator.clipboard.writeText(endpoint);
              setCopied(true);
            }}
          >
            {copied ? "コピー済み" : "コピー"}
          </button>
        </div>
        <p className="status">
          {loginConfigured
            ? `● ${providerName}を利用できます`
            : "○ ログインは未設定です。README のセットアップ手順で設定してください。"}
        </p>
      </section>
      <section aria-labelledby="flow-title">
        <h2 id="flow-title">認可の流れ</h2>
        <ol className="flow">
          <li>
            <b>発見</b>
            <span>MCP サーバーが認可先と必要な権限を返します。</span>
          </li>
          <li>
            <b>確認</b>
            <span>クライアント名とリダイレクト先を確認し、{providerName}でログインします。</span>
          </li>
          <li>
            <b>接続</b>
            <span>
              MCP 専用のトークンを使い、<code>whoami</code> でユーザー情報を確認できます。
            </span>
          </li>
        </ol>
      </section>
      <section aria-labelledby="metadata-title">
        <h2 id="metadata-title">公開メタデータ</h2>
        <div className="links">
          <a href="/.well-known/oauth-protected-resource/mcp">Protected Resource Metadata ↗</a>
          <a href="/.well-known/oauth-authorization-server">Authorization Server Metadata ↗</a>
        </div>
        <p className="muted">
          MCP {specVersion} · PKCE S256 · CIMD{dcrEnabled ? " · DCR（互換用）" : ""}
        </p>
      </section>
      <footer>プロフィールの確認だけを行います。GitHub のリポジトリ権限は要求しません。</footer>
    </main>
  );
}
