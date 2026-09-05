import crypto from "node:crypto";
import fs from "node:fs";
import http, { type IncomingMessage, type ServerResponse } from "node:http";
import path from "node:path";
import { assertNoSymlinkComponents, assertNotSymlink } from "./fs-safe.js";
import { resolveInside } from "./safety.js";
import { MAX_BLOB_BYTES, SyncBlobStore } from "./sync-blobs.js";
import {
  isBlobAttachmentSnapshot,
  parseAttachmentSnapshot,
  validateRelayArtifactEnvelope,
  validateRelayEnvelope,
  type EncryptedSyncChange,
  type SyncChange,
} from "./sync.js";

const OPAQUE_ID = /^[a-f0-9]{64}$/u;
const ARTIFACT_KINDS = new Set(["registry", "checkpoint"]);
const DEFAULT_MAX_REQUEST_BYTES = 12 * 1024 * 1024;
const DEFAULT_MAX_VAULT_BYTES = 512 * 1024 * 1024;
const DEFAULT_MAX_CHANGES = 50_000;
const MAX_PAGE_SIZE = 64;
const MAX_RESPONSE_BYTES = 64 * 1024 * 1024;
/** Blob transfers move up to 2 MiB per request, so they get a longer budget than a JSON call. */
const BLOB_REQUEST_TIMEOUT_MS = 30_000;

/**
 * An error that carries the HTTP status the relay must answer with. Anything
 * else thrown out of a handler stays a 400, exactly as it did before.
 */
class RelayHttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "RelayHttpError";
  }
}

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

async function requestBody(request: IncomingMessage, limit: number, overLimitStatus = 400): Promise<Buffer> {
  const tooLarge = (): Error => new RelayHttpError(overLimitStatus, "Relay request exceeds its byte limit.");
  const declared = request.headers["content-length"];
  if (declared !== undefined) {
    const bytes = Number(declared);
    if (!Number.isSafeInteger(bytes) || bytes < 0) throw new Error("Relay request exceeds its byte limit.");
    if (bytes > limit) throw tooLarge();
  }
  const parts: Buffer[] = [];
  let total = 0;
  for await (const part of request) {
    const chunk = Buffer.isBuffer(part) ? part : Buffer.from(part);
    total += chunk.length;
    if (total > limit) throw tooLarge();
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

function directoryUsage(root: string): { bytes: number; objects: number; changes: number } {
  if (!fs.existsSync(root)) return { bytes: 0, objects: 0, changes: 0 };
  let bytes = 0;
  let objects = 0;
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
        const collection = path.basename(path.dirname(child));
        if (collection === "changes") changes += 1;
        // Blobs are stored objects like any other and count toward the caps.
        if (collection === "changes" || collection === "blobs") objects += 1;
      }
    }
  }
  return { bytes, objects, changes };
}

function parseRoute(urlValue: string): { vaultId: string; section: string; kind?: string; id?: string } | undefined {
  const url = new URL(urlValue, "http://relay.invalid");
  const parts = url.pathname.split("/").filter(Boolean);
  if (parts.length < 4 || parts[0] !== "v1" || parts[1] !== "vaults" || !OPAQUE_ID.test(parts[2])) return undefined;
  if (parts[3] === "changes" && (parts.length === 4 || (parts.length === 5 && OPAQUE_ID.test(parts[4])))) {
    return { vaultId: parts[2], section: "changes", ...(parts[4] ? { id: parts[4] } : {}) };
  }
  if (parts[3] === "blobs" && parts.length === 5 && OPAQUE_ID.test(parts[4])) {
    return { vaultId: parts[2], section: "blobs", id: parts[4] };
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

      // Blobs are opaque bytes: the relay holds no key, verifies only that the
      // content hashes to the id it is filed under, and never lists them.
      if (route.section === "blobs") {
        const blobsDir = resolveInside(vaultDir, "blobs");
        const destination = resolveInside(blobsDir, route.id!);
        if (request.method === "PUT") {
          const body = await requestBody(request, Math.min(maxRequestBytes, MAX_BLOB_BYTES), 413);
          if (crypto.createHash("sha256").update(body).digest("hex") !== route.id) {
            throw new Error("Blob content does not match its id.");
          }
          const created = await serialize(route.vaultId, async () => {
            fs.mkdirSync(blobsDir, { recursive: true, mode: 0o700 });
            assertNoSymlinkComponents(storageDir, blobsDir);
            const usage = directoryUsage(vaultDir);
            const exists = fs.existsSync(destination);
            if (!exists && usage.bytes + body.length > maxVaultBytes) throw new Error("Relay vault byte quota exceeded.");
            if (!exists && usage.objects >= maxChanges) throw new Error("Relay object quota exceeded.");
            return immutableWrite(destination, body);
          });
          json(response, created ? 201 : 200, { stored: created });
          return;
        }
        if (request.method === "GET" || request.method === "HEAD") {
          if (!fs.existsSync(destination)) {
            json(response, 404, { error: "Not found." });
            return;
          }
          assertNotSymlink(destination);
          const size = fs.statSync(destination).size;
          if (size > MAX_BLOB_BYTES) throw new Error("Stored relay object exceeds its byte limit.");
          responseHeaders(response);
          response.writeHead(200, { "Content-Type": "application/octet-stream", "Content-Length": size });
          response.end(request.method === "HEAD" ? undefined : fs.readFileSync(destination));
          return;
        }
        json(response, 405, { error: "Method not allowed." });
        return;
      }

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
          if (!exists && route.section === "changes" && usage.objects >= maxChanges) throw new Error("Relay change quota exceeded.");
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
      const status = error instanceof RelayHttpError ? error.status : 400;
      if (!response.headersSent) json(response, status, { error: error instanceof Error ? error.message : "Relay request failed." });
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

async function responseBytes(response: Response, limit: number): Promise<Buffer> {
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
  return Buffer.concat(parts.map((part) => Buffer.from(part)), total);
}

/**
 * The blob ids a change references, or an empty list for anything that is not
 * a blob-form attachment snapshot. A caller that has decrypted its own changes
 * uses this to learn which bytes must travel with them.
 */
export function attachmentBlobIds(change: SyncChange): string[] {
  if (change.mutation.objectType !== "attachment" || change.mutation.operation !== "put") return [];
  const snapshot = parseAttachmentSnapshot(change.mutation.value);
  return isBlobAttachmentSnapshot(snapshot) ? [...snapshot.blobs] : [];
}

async function responseJson(response: Response, limit = MAX_RESPONSE_BYTES): Promise<unknown> {
  const parsed: unknown = JSON.parse((await responseBytes(response, limit)).toString("utf8"));
  if (!response.ok) {
    const message = parsed && typeof parsed === "object" && "error" in parsed ? String((parsed as { error: unknown }).error) : `HTTP ${response.status}`;
    throw new Error(`Relay rejected the request: ${message}`);
  }
  return parsed;
}

export class SyncRelayClient {
  private readonly baseUrl: string;
  /** Present only when the client was given a vault directory to stage blobs in. */
  private readonly blobStore: SyncBlobStore | undefined;

  constructor(
    baseUrl: string,
    private readonly token: string,
    private readonly vaultId: string,
    vaultDir?: string,
  ) {
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
    this.blobStore = vaultDir === undefined ? undefined : new SyncBlobStore(vaultDir);
  }

  private blobs(): SyncBlobStore {
    if (!this.blobStore) {
      throw new Error("A relay client needs a vault directory to transfer attachment blobs.");
    }
    return this.blobStore;
  }

  private async blobRequest(id: string, method: "GET" | "HEAD" | "PUT", body?: Buffer): Promise<Response> {
    if (!OPAQUE_ID.test(id)) throw new Error("A blob id must be 64 lowercase hexadecimal characters.");
    // `fetch` wants a plain ArrayBuffer-backed view, which a Buffer is not.
    let payload: Uint8Array<ArrayBuffer> | undefined;
    if (body !== undefined) {
      payload = new Uint8Array(new ArrayBuffer(body.length));
      payload.set(body);
    }
    return fetch(`${this.baseUrl}/v1/vaults/${this.vaultId}/blobs/${id}`, {
      method,
      headers: {
        Authorization: `Bearer ${this.token}`,
        ...(payload ? { "Content-Type": "application/octet-stream" } : {}),
      },
      ...(payload ? { body: payload } : {}),
      redirect: "error",
      signal: AbortSignal.timeout(BLOB_REQUEST_TIMEOUT_MS),
    });
  }

  /**
   * Upload every staged blob the relay does not already hold. Idempotent: a
   * re-run after an interruption re-sends only what is genuinely missing.
   */
  /**
   * Whether the relay already holds this blob. This is a `HEAD` on an id the
   * caller must already know, not a listing: it discloses nothing that a change
   * the caller could already decrypt had not told it. There is deliberately no
   * route that enumerates blobs.
   */
  async hasBlob(id: string): Promise<boolean> {
    if (!OPAQUE_ID.test(id)) throw new Error("A blob id must be 64 lowercase hexadecimal characters.");
    const probe = await this.blobRequest(id, "HEAD");
    await probe.body?.cancel();
    if (probe.status === 200) return true;
    if (probe.status === 404) return false;
    throw new Error(`Relay rejected the request: HTTP ${probe.status}`);
  }

  async pushBlobs(ids: readonly string[]): Promise<{ uploaded: number; skipped: number }> {
    const store = this.blobs();
    let uploaded = 0;
    let skipped = 0;
    for (const id of new Set(ids)) {
      if (await this.hasBlob(id)) {
        skipped += 1;
        continue;
      }
      const result = (await responseJson(await this.blobRequest(id, "PUT", store.read(id)))) as {
        stored?: unknown;
      };
      if (result.stored === true) uploaded += 1;
      else skipped += 1;
    }
    return { uploaded, skipped };
  }

  /**
   * Stage every referenced blob that is not already on disk. `SyncBlobStore.put`
   * re-verifies SHA-256(body) === id, so a relay cannot substitute bytes.
   */
  async pullBlobs(ids: readonly string[]): Promise<{ fetched: number; skipped: number }> {
    const store = this.blobs();
    let fetched = 0;
    let skipped = 0;
    for (const id of new Set(ids)) {
      if (!OPAQUE_ID.test(id)) throw new Error("A blob id must be 64 lowercase hexadecimal characters.");
      if (store.has(id)) {
        skipped += 1;
        continue;
      }
      const response = await this.blobRequest(id, "GET");
      if (response.status === 404) {
        await response.body?.cancel();
        throw new Error(`Relay is missing blob ${id}.`);
      }
      if (!response.ok) {
        await responseJson(response);
        throw new Error(`Relay rejected the request: HTTP ${response.status}`);
      }
      store.put(id, await responseBytes(response, MAX_BLOB_BYTES));
      fetched += 1;
    }
    return { fetched, skipped };
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

  /**
   * Upload change envelopes. When the caller also supplies the decrypted
   * changes, every blob an attachment change references is uploaded *before*
   * that change's envelope, so the relay never advertises a change whose bytes
   * it cannot serve.
   */
  async uploadChanges(
    envelopes: readonly EncryptedSyncChange[],
    changes: readonly SyncChange[] = [],
  ): Promise<{ stored: number; existing: number }> {
    const blobsByChange = new Map(changes.map((change) => [change.id, attachmentBlobIds(change)]));
    let stored = 0;
    let existing = 0;
    for (const candidate of envelopes) {
      const envelope = validateRelayEnvelope(candidate);
      const referenced = blobsByChange.get(envelope.id);
      if (referenced && referenced.length > 0) await this.pushBlobs(referenced);
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
