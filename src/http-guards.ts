import type { PlaygroundEnv } from "./contracts";

export const AUTH_BODY_LIMIT = 16_384;

export class RequestInputError extends Error {
  constructor(
    message: string,
    readonly status = 400,
  ) {
    super(message);
  }
}

export function inputErrorResponse(error: RequestInputError): Response {
  return Response.json(
    { error: "invalid_request", error_description: error.message },
    { status: error.status, headers: { "Cache-Control": "no-store" } },
  );
}

/** Bound the streamed bytes before any form/JSON parser buffers the body. */
export async function boundedAuthBody(request: Request, contentType: string): Promise<Request> {
  const actualType = request.headers.get("Content-Type")?.split(";")[0].trim().toLowerCase();
  if (actualType !== contentType) throw new RequestInputError("Unsupported Content-Type");
  if (Number(request.headers.get("Content-Length")) > AUTH_BODY_LIMIT)
    throw new RequestInputError("Request body is too large", 413);
  if (!request.body) return request;
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > AUTH_BODY_LIMIT) {
        void reader.cancel().catch(() => {});
        throw new RequestInputError("Request body is too large", 413);
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof RequestInputError) throw error;
    throw new RequestInputError("Could not read request body");
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new Request(request, { method: request.method, body });
}

/** CF-Connecting-IP is overwritten by Cloudflare at ingress. Never use X-Forwarded-For. */
export async function authRateLimit(
  request: Request,
  env: Pick<PlaygroundEnv, "AUTH_RATE_LIMITER" | "PUBLIC_ORIGIN">,
): Promise<Response | undefined> {
  const route = new URL(request.url).pathname;
  const ip = request.headers.get("CF-Connecting-IP") ?? "anonymous";
  try {
    const { success } = await env.AUTH_RATE_LIMITER.limit({
      key: `${env.PUBLIC_ORIGIN}:${route}:${ip}`,
    });
    if (success) return;
    return Response.json(
      { error: "temporarily_unavailable" },
      {
        status: 429,
        headers: { "Retry-After": "60", "Cache-Control": "no-store" },
      },
    );
  } catch {
    // A missing binding or backend failure must not silently disable protection.
    return Response.json(
      { error: "temporarily_unavailable" },
      {
        status: 503,
        headers: { "Retry-After": "60", "Cache-Control": "no-store" },
      },
    );
  }
}
