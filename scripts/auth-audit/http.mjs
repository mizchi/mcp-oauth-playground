/** Errors intentionally exclude raw URLs, response bodies, credentials and exception messages. */
export class AuditError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

export function validateUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new AuditError("invalid_url");
  }
  const loopback =
    url.hostname === "localhost" ||
    url.hostname === "[::1]" ||
    /^127\.\d+\.\d+\.\d+$/.test(url.hostname);
  if (
    url.username ||
    url.password ||
    url.hash ||
    (url.protocol !== "https:" && !(url.protocol === "http:" && loopback))
  )
    throw new AuditError("https_required_except_loopback");
  return url;
}

export function createHttpClient(config) {
  const allowed = new Set([validateUrl(config.resource).origin]);
  if (config.issuer) allowed.add(validateUrl(config.issuer).origin);
  for (const origin of config.allowedOrigins ?? []) allowed.add(validateUrl(origin).origin);
  let requests = 0;
  const timeoutMs = config.timeoutMs ?? 10_000;
  const maxRequests = config.maxRequests ?? 60;
  const maxBytes = config.maxResponseBytes ?? 65_536;
  if (
    !Number.isInteger(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > 120_000 ||
    !Number.isInteger(maxRequests) ||
    maxRequests < 1 ||
    maxRequests > 200 ||
    !Number.isInteger(maxBytes) ||
    maxBytes < 1 ||
    maxBytes > 1_048_576
  )
    throw new AuditError("invalid_request_limits");
  return {
    get requests() {
      return requests;
    },
    validate(value) {
      const url = validateUrl(value);
      if (!allowed.has(url.origin)) throw new AuditError("origin_not_explicitly_allowed");
      return url;
    },
    async request(value, init = {}) {
      const url = this.validate(value);
      if (++requests > maxRequests) throw new AuditError("request_budget_exceeded");
      const signal = AbortSignal.timeout(timeoutMs);
      try {
        const response = await fetch(url, { ...init, redirect: "manual", signal });
        const reader = response.body?.getReader();
        const chunks = [];
        let length = 0;
        if (reader) {
          while (true) {
            const { value: chunk, done } = await reader.read();
            if (done) break;
            length += chunk.byteLength;
            if (length > maxBytes) {
              await reader.cancel();
              throw new AuditError("response_size_limit_exceeded");
            }
            chunks.push(chunk);
          }
        }
        let json;
        try {
          json = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        } catch {
          /* Never print arbitrary response bodies. */
        }
        return { status: response.status, headers: response.headers, json };
      } catch (error) {
        if (error instanceof AuditError) throw error;
        throw new AuditError(signal.aborted ? "request_timed_out" : "request_failed");
      }
    },
  };
}
