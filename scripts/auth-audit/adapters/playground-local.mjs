/** UI-only example. Optional dependency: @playwright/test (already installed in this repo). */
export async function createAdapter(options = {}) {
  const { chromium } = await import("@playwright/test");
  let browser;
  return {
    async authorize({ authorizationUrl, redirectUri, signal }) {
      browser ??= await chromium.launch({ headless: options.headless !== false });
      const context = await browser.newContext();
      const page = await context.newPage();
      const expected = new URL(redirectUri);
      let finalUrl;
      let resolveCallback;
      let rejectCallback;
      const callback = new Promise((resolve, reject) => {
        resolveCallback = resolve;
        rejectCallback = reject;
      });
      // Attach a rejection handler immediately; an abort may precede awaiting the callback.
      callback.catch(() => {});
      const aborted = () => {
        rejectCallback(new Error("authorization aborted"));
        void context.close().catch(() => {});
      };
      signal.addEventListener("abort", aborted, { once: true });
      if (signal.aborted) aborted();
      page.on("request", (request) => {
        const url = new URL(request.url());
        if (url.origin === expected.origin && url.pathname === expected.pathname) {
          finalUrl = url.href;
          resolveCallback(finalUrl);
        }
      });
      try {
        // Observe the callback request before any network failure at a CLI client's loopback port.
        await page.goto(authorizationUrl, { waitUntil: "domcontentloaded" }).catch((error) => {
          if (!finalUrl) throw error;
        });
        for (const name of options.buttons ?? [
          "許可して ローカル認可サーバー へ",
          "Alice としてログイン",
        ]) {
          if (finalUrl) break;
          await Promise.race([callback, page.getByRole("button", { name, exact: true }).click()]);
        }
        return await callback;
      } finally {
        signal.removeEventListener("abort", aborted);
        await context.close();
      }
    },
    async dispose() {
      await browser?.close();
    },
  };
}
