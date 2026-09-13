import { spawn } from "node:child_process";
import path from "node:path";

export const MEMORY_IPC_LIMIT = 64 * 1024;
const PARAMETERS: Record<string, { allowed: readonly string[]; required: readonly string[] }> = {
  memory_bootstrap: { allowed: [], required: [] }, memory_search: { allowed: ["query", "limit"], required: ["query"] }, memory_read: { allowed: ["id"], required: ["id"] },
  memory_remember: { allowed: ["candidate"], required: ["candidate"] }, memory_forget: { allowed: ["id"], required: ["id"] }, memory_status: { allowed: [], required: [] },
  memory_enqueue: { allowed: ["version", "event", "sessionId", "turnId", "transcriptPath", "createdAt"], required: ["version", "event", "sessionId", "turnId", "transcriptPath", "createdAt"] }, memory_disconnect: { allowed: [], required: [] },
};

export function encodeMemoryRequest(method: string, params: Record<string, unknown>): string {
  const schema = Object.hasOwn(PARAMETERS, method) ? PARAMETERS[method] : undefined;
  if (!schema) throw new Error("Unsupported memory method.");
  if (!params || Array.isArray(params) || Object.keys(params).some((key) => !schema.allowed.includes(key)) || schema.required.some((key) => !Object.hasOwn(params, key))) {
    throw new Error("Invalid memory parameters.");
  }
  let request: string;
  try { request = JSON.stringify({ version: 1, method, params }); }
  catch { throw new Error("Invalid memory parameters."); }
  // JSON serialization can call an inherited `toJSON`. Parse the resulting
  // bytes and reapply the envelope allowlist before they cross the process
  // boundary, so serialization cannot add privileged top-level fields.
  try {
    const encoded = JSON.parse(request) as { version?: unknown; method?: unknown; params?: unknown };
    if (encoded.version !== 1 || encoded.method !== method || !encoded.params || typeof encoded.params !== "object" || Array.isArray(encoded.params)
      || Object.keys(encoded.params).some((key) => !schema.allowed.includes(key)) || schema.required.some((key) => !Object.hasOwn(encoded.params as object, key))) {
      throw new Error("Invalid memory parameters.");
    }
  } catch (error) {
    if (error instanceof Error && error.message === "Invalid memory parameters.") throw error;
    throw new Error("Invalid memory parameters.");
  }
  request += "\n";
  if (Buffer.byteLength(request) > MEMORY_IPC_LIMIT) throw new Error("Memory request exceeds its size limit.");
  return request;
}

export function decodeMemoryResponse(text: string): unknown {
  if (Buffer.byteLength(text) > MEMORY_IPC_LIMIT) throw new Error("Memory response exceeds its size limit.");
  let value: unknown;
  try { value = JSON.parse(text); } catch { throw new Error("Invalid memory response."); }
  if (!value || typeof value !== "object") throw new Error("Invalid memory response.");
  const response = value as Record<string, unknown>;
  if (response.version !== 1 || typeof response.ok !== "boolean") throw new Error("Invalid memory response.");
  if (!response.ok) {
    const code = (response.error as { code?: unknown } | undefined)?.code;
    // Native diagnostics never become a path/content echo channel.
    throw new Error(typeof code === "string" && /^[A-Z_]{1,48}$/u.test(code) ? `Memory request refused (${code}).` : "Memory request refused.");
  }
  if (!Object.hasOwn(response, "result")) throw new Error("Invalid memory response.");
  return response.result;
}

/** Only the native executable loads pairing credentials; Node sends public requests. */
export function callMemoryNative(executable: string, method: string, params: Record<string, unknown> = {}, signal?: AbortSignal): Promise<unknown> {
  if (!path.isAbsolute(executable) || /[\0\r\n]/u.test(executable)) throw new Error("An absolute native executable path is required.");
  const request = encodeMemoryRequest(method, params);
  if (signal?.aborted) return Promise.reject(new Error("Memory request cancelled."));
  return new Promise((resolve, reject) => {
    const env: NodeJS.ProcessEnv = {};
    for (const key of ["SystemRoot", "WINDIR", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "TEMP", "TMP"]) {
      if (process.env[key]) env[key] = process.env[key];
    }
    const child = spawn(executable, ["--memory-client"], { shell: false, windowsHide: true, stdio: ["pipe", "pipe", "pipe"], env });
    const chunks: Buffer[] = [];
    let size = 0;
    let settled = false;
    const finish = (error?: Error, result?: unknown): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      for (const chunk of chunks) chunk.fill(0);
      if (error) { child.kill(); reject(error); } else resolve(result);
    };
    const abort = (): void => finish(new Error("Memory request cancelled."));
    const timer = setTimeout(() => finish(new Error("Memory request timed out.")), method === "memory_enqueue" ? 2500 : 10_000);
    signal?.addEventListener("abort", abort, { once: true });
    child.on("error", () => finish(new Error("Memory desktop unavailable.")));
    child.stdin.on("error", () => finish(new Error("Memory desktop unavailable.")));
    child.stderr.on("data", () => { /* Deliberately drain without retaining diagnostics. */ });
    child.stdout.on("data", (chunk: Buffer) => {
      if (settled) return;
      size += chunk.length;
      if (size > MEMORY_IPC_LIMIT) return finish(new Error("Memory response exceeds its size limit."));
      chunks.push(chunk);
    });
    child.on("close", (code) => {
      if (settled) return;
      if (code !== 0) return finish(new Error("Memory desktop unavailable."));
      try { finish(undefined, decodeMemoryResponse(Buffer.concat(chunks).toString("utf8"))); }
      catch { finish(new Error("Memory request refused or returned an invalid response.")); }
    });
    child.stdin.end(request);
  });
}
