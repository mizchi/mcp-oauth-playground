import { AuditError } from "./http.mjs";

export async function invoke(adapter, name, args, timeoutMs = 10_000) {
  const controller = new AbortController();
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(() => adapter[name]({ ...args, signal: controller.signal })),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(new AuditError("adapter_timed_out"));
        }, timeoutMs);
      }),
    ]);
  } catch (error) {
    if (error instanceof AuditError) throw error;
    throw new AuditError("adapter_failed");
  } finally {
    clearTimeout(timer);
  }
}
