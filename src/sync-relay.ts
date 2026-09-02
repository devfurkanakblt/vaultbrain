import crypto from "node:crypto";
import fs from "node:fs";
import http, { type IncomingMessage, type ServerResponse } from "node:http";
import path from "node:path";
import { assertNoSymlinkComponents, assertNotSymlink } from "./fs-safe.js";
import { resolveInside } from "./safety.js";
import {
  validateRelayArtifactEnvelope,
  validateRelayEnvelope,
  type EncryptedSyncChange,
} from "./sync.js";

const OPAQUE_ID = /^[a-f0-9]{64}$/u;
const ARTIFACT_KINDS = new Set(["registry", "checkpoint"]);
const DEFAULT_MAX_REQUEST_BYTES = 12 * 1024 * 1024;
const DEFAULT_MAX_VAULT_BYTES = 512 * 1024 * 1024;
const DEFAULT_MAX_CHANGES = 50_000;
const MAX_PAGE_SIZE = 64;
const MAX_RESPONSE_BYTES = 64 * 1024 * 1024;

export interface SyncRelayOptions {
  storageDir: string;
  token: string;
  host?: string;
  port?: number;
  maxRequestBytes?: number;
  maxVaultBytes?: number;
  maxChanges?: number;
}

export interface RunningSyncRelay {
  url: string;
  close(): Promise<void>;
}

export type SyncRelayArtifactKind = "registry" | "checkpoint";

interface RelayPage {
  changes: EncryptedSyncChange[];
  nextCursor: string | null;
}

function positiveInteger(value: number | undefined, fallback: number, label: string): number {
  const candidate = value ?? fallback;
  if (!Number.isSafeInteger(candidate) || candidate < 1) throw new Error(`${label} must be a positive integer.`);
  return candidate;
}

function tokenDigest(value: string): Buffer {
  return crypto.createHash("sha256").update(value, "utf8").digest();
}

function authorized(request: IncomingMessage, expectedDigest: Buffer): boolean {
  const header = request.headers.authorization;
  if (!header?.startsWith("Bearer ")) return false;
  return crypto.timingSafeEqual(tokenDigest(header.slice(7)), expectedDigest);
}

function responseHeaders(response: ServerResponse): void {
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("Content-Security-Policy", "default-src 'none'");
  response.setHeader("X-Content-Type-Options", "nosniff");
}

function json(response: ServerResponse, status: number, value: unknown): void {
  const body = JSON.stringify(value);
  responseHeaders(response);
  response.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Content-Length": Buffer.byteLength(body) });
  response.end(body);
}

async function requestBody(request: IncomingMessage, limit: number): Promise<Buffer> {
  const declared = request.headers["content-length"];
  if (declared !== undefined) {
    const bytes = Number(declared);
    if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > limit) throw new Error("Relay request exceeds its byte limit.");
  }
  const parts: Buffer[] = [];
  let total = 0;
  for await (const part of request) {
    const chunk = Buffer.isBuffer(part) ? part : Buffer.from(part);
    total += chunk.length;
    if (total > limit) throw new Error("Relay request exceeds its byte limit.");
    parts.push(chunk);
  }
  return Buffer.concat(parts, total);
}

function immutableWrite(destination: string, body: Buffer): boolean {
  assertNotSymlink(destination);
  let descriptor: number | undefined;
  try {
    descriptor = fs.openSync(destination, "wx", 0o600);
    fs.writeFileSync(descriptor, body);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    assertNotSymlink(destination);
    const existing = fs.readFileSync(destination);
    if (!existing.equals(body)) {
      throw new Error("Relay content ID collision or immutable artifact mismatch.", { cause: error });
    }
    return false;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function directoryUsage(root: string): { bytes: number; changes: number } {
  if (!fs.existsSync(root)) return { bytes: 0, changes: 0 };
  let bytes = 0;
  let changes = 0;
  const pending = [root];
  while (pending.length > 0) {
    const current = pending.pop()!;
    assertNotSymlink(current);
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const child = resolveInside(root, path.relative(root, path.join(current, entry.name)));
      if (entry.isSymbolicLink()) throw new Error("Relay storage contains a symbolic link.");
      if (entry.isDirectory()) pending.push(child);
      else if (entry.isFile()) {
        bytes += fs.statSync(child).size;
        if (path.basename(path.dirname(child)) === "changes") changes += 1;
      }
    }
  }
  return { bytes, changes };
}

function parseRoute(urlValue: string): { vaultId: string; section: string; kind?: string; id?: string } | undefined {
  const url = new URL(urlValue, "http://relay.invalid");
  const parts = url.pathname.split("/").filter(Boolean);
  if (parts.length < 4 || parts[0] !== "v1" || parts[1] !== "vaults" || !OPAQUE_ID.test(parts[2])) return undefined;
  if (parts[3] === "changes" && (parts.length === 4 || (parts.length === 5 && OPAQUE_ID.test(parts[4])))) {
    return { vaultId: parts[2], section: "changes", ...(parts[4] ? { id: parts[4] } : {}) };
  }
  if (
    parts[3] === "artifacts" &&
    parts[4] &&
    ARTIFACT_KINDS.has(parts[4]) &&
    (parts.length === 5 || (parts.length === 6 && OPAQUE_ID.test(parts[5])))
  ) {
    return { vaultId: parts[2], section: "artifacts", kind: parts[4], ...(parts[5] ? { id: parts[5] } : {}) };
  }
  return undefined;
}

export async function startSyncRelay(options: SyncRelayOptions): Promise<RunningSyncRelay> {
  if (Buffer.byteLength(options.token, "utf8") < 32) throw new Error("Relay bearer token must contain at least 32 bytes.");
  const storageDir = path.resolve(options.storageDir);
  fs.mkdirSync(storageDir, { recursive: true, mode: 0o700 });
  assertNotSymlink(storageDir);
  const expectedToken = tokenDigest(options.token);
  const maxRequestBytes = positiveInteger(options.maxRequestBytes, DEFAULT_MAX_REQUEST_BYTES, "Relay request limit");
  const maxVaultBytes = positiveInteger(options.maxVaultBytes, DEFAULT_MAX_VAULT_BYTES, "Relay vault limit");
  const maxChanges = positiveInteger(options.maxChanges, DEFAULT_MAX_CHANGES, "Relay change limit");
  const queues = new Map<string, Promise<void>>();

  const serialize = async <T>(vaultId: string, action: () => Promise<T>): Promise<T> => {
    const previous = queues.get(vaultId) ?? Promise.resolve();
    let release!: () => void;
    const next = new Promise<void>((resolve) => {
      release = resolve;
    });
    const queued = previous.then(() => next);
    queues.set(vaultId, queued);
    await previous;
    try {
      return await action();
    } finally {
      release();
      if (queues.get(vaultId) === queued) queues.delete(vaultId);
    }
  };

  const server = http.createServer((request, response) => {
    void (async () => {
      responseHeaders(response);
      if (request.url === "/health" && request.method === "GET") {
        json(response, 200, { ok: true });
        return;
      }
      if (!authorized(request, expectedToken)) {
        response.setHeader("WWW-Authenticate", "Bearer");
        json(response, 401, { error: "Unauthorized." });
        return;
      }
      const route = parseRoute(request.url ?? "/");
      if (!route) {
        json(response, 404, { error: "Not found." });
        return;
      }
      const vaultDir = resolveInside(storageDir, route.vaultId);
      assertNoSymlinkComponents(storageDir, vaultDir);
      const sectionDir = resolveInside(vaultDir, route.section === "changes" ? "changes" : path.join("artifacts", route.kind!));
      assertNoSymlinkComponents(storageDir, sectionDir);

      if (request.method === "PUT" && route.id) {
        const receivedBody = await requestBody(request, maxRequestBytes);
        let storedBody = receivedBody;
        if (crypto.createHash("sha256").update(receivedBody).digest("hex") !== route.id && route.section === "artifacts") {
          throw new Error("Relay artifact ID does not match its bytes.");
        }
        if (route.section === "artifacts") {
          validateRelayArtifactEnvelope(JSON.parse(receivedBody.toString("utf8")));
        }
        if (route.section === "changes") {
          const envelope = validateRelayEnvelope(JSON.parse(receivedBody.toString("utf8")));
          if (envelope.id !== route.id) throw new Error("Relay change ID does not match its envelope.");
          storedBody = Buffer.from(JSON.stringify(envelope), "utf8");
        }
        const created = await serialize(route.vaultId, async () => {
          fs.mkdirSync(sectionDir, { recursive: true, mode: 0o700 });
          assertNoSymlinkComponents(storageDir, sectionDir);
          const usage = directoryUsage(vaultDir);
          const destination = resolveInside(sectionDir, `${route.id}.json`);
          const exists = fs.existsSync(destination);
          if (!exists && usage.bytes + storedBody.length > maxVaultBytes) throw new Error("Relay vault byte quota exceeded.");
          if (!exists && route.section === "changes" && usage.changes >= maxChanges) throw new Error("Relay change quota exceeded.");
          return immutableWrite(destination, storedBody);
        });
        json(response, created ? 201 : 200, { stored: created });
        return;
      }

      if (request.method === "GET" && route.id) {
        const filePath = resolveInside(sectionDir, `${route.id}.json`);
        if (!fs.existsSync(filePath)) {
          json(response, 404, { error: "Not found." });
          return;
        }
        assertNotSymlink(filePath);
        if (fs.statSync(filePath).size > maxRequestBytes) throw new Error("Stored relay object exceeds its byte limit.");
        const body = fs.readFileSync(filePath);
        responseHeaders(response);
        response.writeHead(200, { "Content-Type": "application/json", "Content-Length": body.length });
        response.end(body);
        return;
      }

      if (request.method === "GET" && !route.id) {
        const url = new URL(request.url ?? "/", "http://relay.invalid");
        const cursor = url.searchParams.get("cursor");
        if (cursor !== null && !OPAQUE_ID.test(cursor)) throw new Error("Relay cursor is invalid.");
        const requestedLimit = Number(url.searchParams.get("limit") ?? "32");
        if (!Number.isSafeInteger(requestedLimit) || requestedLimit < 1 || requestedLimit > MAX_PAGE_SIZE) {
          throw new Error(`Relay page limit must be between 1 and ${MAX_PAGE_SIZE}.`);
        }
        const ids = fs.existsSync(sectionDir)
          ? fs.readdirSync(sectionDir).filter((name) => /^[a-f0-9]{64}\.json$/u.test(name)).map((name) => name.slice(0, -5)).sort()
          : [];
        const start = cursor === null ? 0 : ids.findIndex((id) => id > cursor);
        const pageIds = start < 0 ? [] : ids.slice(start, start + requestedLimit);
        if (route.section === "artifacts") {
          json(response, 200, { ids: pageIds, nextCursor: start >= 0 && start + requestedLimit < ids.length ? pageIds.at(-1) : null });
          return;
        }
        const changes = pageIds.map((id) => {
          const filePath = resolveInside(sectionDir, `${id}.json`);
          assertNotSymlink(filePath);
          if (fs.statSync(filePath).size > maxRequestBytes) {
            throw new Error("Stored relay object exceeds its byte limit.");
          }
          return validateRelayEnvelope(JSON.parse(fs.readFileSync(filePath, "utf8")));
        });
        json(response, 200, { changes, nextCursor: start >= 0 && start + requestedLimit < ids.length ? pageIds.at(-1) : null });
        return;
      }

      json(response, 405, { error: "Method not allowed." });
    })().catch((error: unknown) => {
      if (!response.headersSent) json(response, 400, { error: error instanceof Error ? error.message : "Relay request failed." });
      else response.destroy();
    });
  });
  server.headersTimeout = 15_000;
  server.requestTimeout = 30_000;
  server.keepAliveTimeout = 5_000;
  server.maxRequestsPerSocket = 100;

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port ?? 0, options.host ?? "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Relay did not bind a TCP address.");
  const host = options.host ?? "127.0.0.1";
  const displayHost = host.includes(":") ? `[${host}]` : host;
  return {
    url: `http://${displayHost}:${address.port}`,
    close: () => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}

async function responseJson(response: Response, limit = MAX_RESPONSE_BYTES): Promise<unknown> {
  if (!response.body) throw new Error("Relay response has no body.");
  const reader = response.body.getReader();
  const parts: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > limit) {
      await reader.cancel();
      throw new Error("Relay response exceeds its byte limit.");
    }
    parts.push(value);
  }
  const body = Buffer.concat(parts.map((part) => Buffer.from(part)), total).toString("utf8");
  const parsed: unknown = JSON.parse(body);
  if (!response.ok) {
    const message = parsed && typeof parsed === "object" && "error" in parsed ? String((parsed as { error: unknown }).error) : `HTTP ${response.status}`;
    throw new Error(`Relay rejected the request: ${message}`);
  }
  return parsed;
}

export class SyncRelayClient {
  private readonly baseUrl: string;

  constructor(baseUrl: string, private readonly token: string, private readonly vaultId: string) {
    const parsed = new URL(baseUrl);
    if (
      !["http:", "https:"].includes(parsed.protocol) ||
      parsed.username ||
      parsed.password ||
      parsed.pathname !== "/" ||
      parsed.search ||
      parsed.hash
    ) {
      throw new Error("Relay URL must be an HTTP(S) origin without credentials, query or fragment.");
    }
    if (parsed.protocol === "http:" && !["127.0.0.1", "localhost", "[::1]"].includes(parsed.hostname)) {
      throw new Error("A non-loopback relay URL must use HTTPS to protect its bearer token.");
    }
    if (Buffer.byteLength(token, "utf8") < 32) throw new Error("Relay bearer token must contain at least 32 bytes.");
    if (!OPAQUE_ID.test(vaultId)) throw new Error("Relay vault ID must be 64 lowercase hexadecimal characters.");
    this.baseUrl = parsed.origin;
  }

  private async request(pathname: string, init: RequestInit = {}): Promise<unknown> {
    const response = await fetch(`${this.baseUrl}${pathname}`, {
      ...init,
      headers: { Authorization: `Bearer ${this.token}`, ...(init.headers ?? {}) },
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    });
    return responseJson(response);
  }

  async uploadChanges(envelopes: readonly EncryptedSyncChange[]): Promise<{ stored: number; existing: number }> {
    let stored = 0;
    let existing = 0;
    for (const candidate of envelopes) {
      const envelope = validateRelayEnvelope(candidate);
      const result = await this.request(`/v1/vaults/${this.vaultId}/changes/${envelope.id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(envelope),
      }) as { stored?: unknown };
      if (result.stored === true) stored += 1;
      else existing += 1;
    }
    return { stored, existing };
  }

  async downloadChanges(): Promise<EncryptedSyncChange[]> {
    const changes: EncryptedSyncChange[] = [];
    let cursor: string | null = null;
    do {
      const suffix = cursor ? `?limit=${MAX_PAGE_SIZE}&cursor=${cursor}` : `?limit=${MAX_PAGE_SIZE}`;
      const page = await this.request(`/v1/vaults/${this.vaultId}/changes${suffix}`) as RelayPage;
      if (!page || !Array.isArray(page.changes) || (page.nextCursor !== null && !OPAQUE_ID.test(page.nextCursor))) {
        throw new Error("Relay returned an invalid change page.");
      }
      changes.push(...page.changes.map(validateRelayEnvelope));
      cursor = page.nextCursor;
    } while (cursor);
    return changes;
  }

  async uploadArtifact(kind: SyncRelayArtifactKind, value: unknown): Promise<string> {
    if (!ARTIFACT_KINDS.has(kind)) throw new Error("Unsupported relay artifact kind.");
    const body = JSON.stringify(value);
    const id = crypto.createHash("sha256").update(body).digest("hex");
    await this.request(`/v1/vaults/${this.vaultId}/artifacts/${kind}/${id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body,
    });
    return id;
  }

  async downloadArtifacts(kind: SyncRelayArtifactKind): Promise<unknown[]> {
    if (!ARTIFACT_KINDS.has(kind)) throw new Error("Unsupported relay artifact kind.");
    const values: unknown[] = [];
    let cursor: string | null = null;
    do {
      const suffix = cursor ? `?limit=${MAX_PAGE_SIZE}&cursor=${cursor}` : `?limit=${MAX_PAGE_SIZE}`;
      const page = await this.request(`/v1/vaults/${this.vaultId}/artifacts/${kind}${suffix}`) as { ids?: unknown; nextCursor?: unknown };
      if (!Array.isArray(page.ids) || page.ids.some((id) => typeof id !== "string" || !OPAQUE_ID.test(id))) {
        throw new Error("Relay returned an invalid artifact page.");
      }
      for (const id of page.ids as string[]) {
        values.push(await this.request(`/v1/vaults/${this.vaultId}/artifacts/${kind}/${id}`));
      }
      cursor = page.nextCursor === null ? null : typeof page.nextCursor === "string" && OPAQUE_ID.test(page.nextCursor) ? page.nextCursor : (() => { throw new Error("Relay returned an invalid artifact cursor."); })();
    } while (cursor);
    return values;
  }
}
