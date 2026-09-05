# Resumable Attachment Blob Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let attachments of any size the vault accepts (up to 250 MiB) synchronize between devices, by moving the bytes out of the 8 MiB change envelope and into resumable, content-addressed blob transfers.

**Architecture:** A new `version: 3` sync change body carries an attachment *manifest* — `filename`, `mime`, `size`, `chunks`, and one blob id per chunk — instead of base64 bytes. Each blob is one AEAD-sealed 1 MiB chunk, sealed with the existing `attachmentChunkAad(id, index)` binding, and named by the SHA-256 of its own sealed bytes. Blobs live in a local staging store and move through a new `blobs` collection on the relay, which verifies `SHA-256(body) === id` without holding any key. Plaintext integrity still comes from the existing content-addressed check: after reassembly the receiver recomputes `HMAC-SHA256(attachmentIdKey, AAD.attachmentId || data)` and refuses anything that is not the change's `objectId`.

**Tech Stack:** TypeScript (Node >= 20, `tsc -p .` to `dist/`), `node:test` + `node:assert/strict`, `node:crypto`, `node:http` for the relay, Commander for the CLI. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-04-resumable-attachment-blob-transport-design.md`

## Global Constraints

- Node `>= 20`; no new runtime dependencies.
- Tests import the **built** output (`../dist/*.js`), so every test run is `npm run build && node --test <files>`.
- Every new test file must be appended to the `test` script's file list in `package.json`, or CI will not run it.
- Sync writes stay gated behind `--experimental-trusted-sync` at the CLI.
- `ATTACHMENT_CHUNK_SIZE` = `1024 * 1024`; `MAX_ATTACHMENT_SIZE` = `250 * 1024 * 1024` (`src/documents.ts`).
- `MAX_CHANGE_BYTES` = `8 * 1024 * 1024` stays as it is; only `MAX_SYNC_ATTACHMENT_BYTES` is removed.
- A `blobs` array holds at most **256** entries; a blob id is exactly 64 lowercase hex characters.
- Relay per-blob body limit: **2 MiB** (matches the `readTextFileLimited` bound `src/documents.ts` already applies to a chunk file).
- Attachment id derivation is `HMAC-SHA256(session.attachmentIdKey, "secondbrain-vault:attachment-id:v1\0" || data)`. It is **not** keyed by the document key. See `docs/FORMAT-1.0.md`.
- Never write a partial attachment into live storage. Missing chunks fail closed.
- Prettier does not format `.md` or `.ts` in this repo's `format:check`; ESLint does lint `src` and `test`.

---

### Task 1: Attachment snapshot gains a blob form

The format layer only. No transport, no relay, no storage changes — this task makes the parser and the equality check understand both snapshot shapes.

**Files:**
- Modify: `src/sync.ts:265-269` (the `AttachmentSyncSnapshot` interface)
- Modify: `src/sync.ts:1861-1876` (`parseAttachmentSnapshot`)
- Modify: `src/sync.ts:1792-1794` (`attachmentSnapshot`)
- Test: `test/sync.test.mjs`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `type AttachmentSyncSnapshot = InlineAttachmentSyncSnapshot | BlobAttachmentSyncSnapshot`
  - `interface InlineAttachmentSyncSnapshot { filename: string; mime: string; data: string }`
  - `interface BlobAttachmentSyncSnapshot { filename: string; mime: string; size: number; chunks: number; blobs: string[] }`
  - `function parseAttachmentSnapshot(value: SyncJson): AttachmentSyncSnapshot` — accepts either form, rejects a mixed one
  - `function isBlobAttachmentSnapshot(snapshot: AttachmentSyncSnapshot): snapshot is BlobAttachmentSyncSnapshot`
  - `function sameAttachmentSnapshot(a: SyncJson, b: SyncJson): boolean` — compares `filename` and `mime` only

**Why `sameAttachmentSnapshot` compares only two fields:** the attachment's `objectId` *is* an HMAC over its plaintext, and every call site already compares snapshots for one fixed `objectId`. Content equality is therefore implied, and the blob ids are not reproducible locally (AEAD nonces are random per seal), so comparing them would report two identical attachments as different.

- [ ] **Step 1: Write the failing tests**

Append to `test/sync.test.mjs`:

```js
test("an attachment sync snapshot parses in both the inline and the blob form", async () => {
  const { parseAttachmentSnapshot, isBlobAttachmentSnapshot, sameAttachmentSnapshot } = await import("../dist/sync.js");
  const blobId = "a".repeat(64);

  const inline = parseAttachmentSnapshot({ filename: "a.txt", mime: "text/plain", data: "aGk=" });
  assert.equal(isBlobAttachmentSnapshot(inline), false);
  assert.equal(inline.data, "aGk=");

  const blob = parseAttachmentSnapshot({
    filename: "a.bin",
    mime: "application/octet-stream",
    size: 2,
    chunks: 1,
    blobs: [blobId],
  });
  assert.equal(isBlobAttachmentSnapshot(blob), true);
  assert.deepEqual(blob.blobs, [blobId]);

  // A snapshot may not claim both forms.
  assert.throws(
    () => parseAttachmentSnapshot({ filename: "a", mime: "text/plain", data: "aGk=", size: 2, chunks: 1, blobs: [blobId] }),
    /exactly one/i,
  );
  // chunks must agree with blobs.length.
  assert.throws(
    () => parseAttachmentSnapshot({ filename: "a", mime: "text/plain", size: 2, chunks: 2, blobs: [blobId] }),
    /chunk count/i,
  );
  // chunks must agree with size.
  assert.throws(
    () => parseAttachmentSnapshot({ filename: "a", mime: "text/plain", size: 5 * 1024 * 1024, chunks: 1, blobs: [blobId] }),
    /chunk count/i,
  );
  // size must be at least 1: an empty attachment is refused at the storage layer too.
  assert.throws(
    () => parseAttachmentSnapshot({ filename: "a", mime: "text/plain", size: 0, chunks: 1, blobs: [blobId] }),
    /size/i,
  );
  // blob ids are 64 lowercase hex characters.
  assert.throws(
    () => parseAttachmentSnapshot({ filename: "a", mime: "text/plain", size: 2, chunks: 1, blobs: ["NOTHEX"] }),
    /blob id/i,
  );
  // at most 256 blobs.
  assert.throws(
    () =>
      parseAttachmentSnapshot({
        filename: "a",
        mime: "text/plain",
        size: 257 * 1024 * 1024,
        chunks: 257,
        blobs: Array.from({ length: 257 }, () => blobId),
      }),
    /at most 256/i,
  );

  // Equality ignores the form and the blob ids.
  assert.equal(
    sameAttachmentSnapshot(
      { filename: "a.bin", mime: "text/plain", data: "aGk=" },
      { filename: "a.bin", mime: "text/plain", size: 2, chunks: 1, blobs: [blobId] },
    ),
    true,
  );
  assert.equal(
    sameAttachmentSnapshot(
      { filename: "a.bin", mime: "text/plain", data: "aGk=" },
      { filename: "renamed.bin", mime: "text/plain", size: 2, chunks: 1, blobs: [blobId] },
    ),
    false,
  );
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm run build && node --test test/sync.test.mjs`
Expected: FAIL — `parseAttachmentSnapshot` is not exported, so the import destructuring yields `undefined` and the first call throws `TypeError`.

- [ ] **Step 3: Implement the format layer**

In `src/sync.ts`, replace the `AttachmentSyncSnapshot` interface (currently at `src/sync.ts:265-269`) with:

```ts
export interface InlineAttachmentSyncSnapshot {
  filename: string;
  mime: string;
  data: string;
}

export interface BlobAttachmentSyncSnapshot {
  filename: string;
  mime: string;
  size: number;
  chunks: number;
  blobs: string[];
}

export type AttachmentSyncSnapshot = InlineAttachmentSyncSnapshot | BlobAttachmentSyncSnapshot;

export const MAX_ATTACHMENT_BLOBS = 256;
const BLOB_ID_PATTERN = /^[0-9a-f]{64}$/u;
```

Add the guard and rewrite the parser (replacing `src/sync.ts:1861-1876`):

```ts
export function isBlobAttachmentSnapshot(
  snapshot: AttachmentSyncSnapshot,
): snapshot is BlobAttachmentSyncSnapshot {
  return "blobs" in snapshot;
}

export function parseAttachmentSnapshot(value: SyncJson): AttachmentSyncSnapshot {
  const raw = recordValue(value, "Attachment");
  const filename = requiredString(raw.filename, "Attachment sync filename");
  const mime = requiredString(raw.mime, "Attachment sync MIME type");
  const hasInline = raw.data !== undefined;
  const hasBlobs = raw.blobs !== undefined || raw.chunks !== undefined || raw.size !== undefined;
  if (hasInline === hasBlobs) {
    throw new Error("An attachment sync snapshot must carry exactly one of inline data or blob references.");
  }

  if (hasInline) {
    const data = requiredString(raw.data, "Attachment sync data");
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(data)) {
      throw new Error("Attachment sync data must be canonical base64.");
    }
    if (Buffer.from(data, "base64").toString("base64") !== data) {
      throw new Error("Attachment sync data must be canonical base64.");
    }
    return { filename, mime, data };
  }

  const { size, chunks, blobs } = raw as { size: unknown; chunks: unknown; blobs: unknown };
  if (!Number.isSafeInteger(size) || (size as number) < 1 || (size as number) > MAX_ATTACHMENT_SIZE) {
    throw new Error("Attachment sync size must be between 1 byte and 250 MiB.");
  }
  if (!Array.isArray(blobs)) throw new Error("Attachment sync blobs must be an array.");
  if (blobs.length > MAX_ATTACHMENT_BLOBS) {
    throw new Error(`An attachment sync snapshot may reference at most ${MAX_ATTACHMENT_BLOBS} blobs.`);
  }
  for (const blob of blobs) {
    if (typeof blob !== "string" || !BLOB_ID_PATTERN.test(blob)) {
      throw new Error("An attachment sync blob id must be 64 lowercase hexadecimal characters.");
    }
  }
  if (
    !Number.isSafeInteger(chunks) ||
    chunks !== blobs.length ||
    chunks !== Math.ceil((size as number) / ATTACHMENT_CHUNK_SIZE)
  ) {
    throw new Error("Attachment sync chunk count must match both its blob list and its size.");
  }
  return { filename, mime, size: size as number, chunks: chunks as number, blobs: blobs as string[] };
}

export function sameAttachmentSnapshot(a: SyncJson, b: SyncJson): boolean {
  const left = parseAttachmentSnapshot(a);
  const right = parseAttachmentSnapshot(b);
  return left.filename === right.filename && left.mime === right.mime;
}
```

`ATTACHMENT_CHUNK_SIZE` and `MAX_ATTACHMENT_SIZE` are module-private in `src/documents.ts`. Export both from there (`export const ATTACHMENT_CHUNK_SIZE = 1024 * 1024;`, `export const MAX_ATTACHMENT_SIZE = 250 * 1024 * 1024;`) and import them in `src/sync.ts`.

Leave `attachmentSnapshot` (`src/sync.ts:1792`) producing the inline form for now; Task 4 changes what the writer emits.

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm run build && node --test test/sync.test.mjs`
Expected: PASS, and every pre-existing test in the file still passes.

- [ ] **Step 5: Commit**

```bash
git add src/sync.ts src/documents.ts test/sync.test.mjs
git commit -m "feat(sync): parse attachment snapshots in inline and blob form"
```

---

### Task 2: Change body version 3

**Files:**
- Modify: `src/sync.ts:90-95` (`SyncChangeBody.version`)
- Modify: `src/sync.ts:420` (body shape validation) and `src/sync.ts:461-476` (version-specific authorization rules)
- Modify: `src/format-version.ts:33` (`syncChangeEnvelope` compatibility entry)
- Test: `test/sync-protocol.test.mjs`

**Interfaces:**
- Consumes: Task 1's snapshot parser.
- Produces: `SyncChangeBody["version"]` widened to `1 | 2 | 3`; a version 3 body is authorized exactly like a version 2 body (`authorization` required, same `changeAuthorizationPayload` signing input).

- [ ] **Step 1: Write the failing test**

Append to `test/sync-protocol.test.mjs`:

```js
test("a version 3 change body is accepted and authorized like version 2", async () => {
  const { FORMAT_COMPATIBILITY } = await import("../dist/format-version.js");
  assert.deepEqual(FORMAT_COMPATIBILITY.syncChangeEnvelope.reads, [1, 2, 3]);
  assert.deepEqual(FORMAT_COMPATIBILITY.syncChangeEnvelope.writes, [1, 2, 3]);
});

test("a version 3 change body without authorization is refused", async () => {
  const { parseChangeBody } = await import("../dist/sync.js");
  assert.throws(
    () =>
      parseChangeBody({
        version: 3,
        deviceId: "11111111-1111-4111-8111-111111111111",
        sequence: 1,
        previousDeviceChange: null,
        parents: [],
        createdAt: "2026-09-04T00:00:00.000Z",
        mutation: {
          objectType: "attachment",
          objectId: "b".repeat(64),
          operation: "put",
          baseRevision: null,
          revision: 1,
          value: { filename: "a.bin", mime: "text/plain", size: 2, chunks: 1, blobs: ["a".repeat(64)] },
        },
      }),
    /authorization/i,
  );
});
```

If `parseChangeBody` is not exported from `src/sync.ts`, export it — the tests need to reach the validator directly rather than through a sealed envelope.

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm run build && node --test test/sync-protocol.test.mjs`
Expected: FAIL — `reads` is `[1, 2]`, and `parseChangeBody` rejects `version: 3` outright with the shape error rather than the authorization error.

- [ ] **Step 3: Implement version 3**

In `src/sync.ts`, widen the body type:

```ts
export interface SyncChangeBody {
  version: 1 | 2 | 3;
  // ...unchanged fields
}
```

At `src/sync.ts:420`, accept the new version:

```ts
if (
  !body ||
  typeof body !== "object" ||
  Array.isArray(body) ||
  (body.version !== 1 && body.version !== 2 && body.version !== 3)
) {
```

At `src/sync.ts:474`, authorization becomes required for every version above 1:

```ts
if (body.version === 1 || !body.authorization) {
```

Leave `src/sync.ts:461` (`if (body.version === 1)`, which rejects a version 1 body that carries `authorization`) untouched.

In `src/format-version.ts:33`:

```ts
syncChangeEnvelope: { path: "documents/sync/changes/*.change.enc", reads: [1, 2, 3], writes: [1, 2, 3] },
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm run build && node --test test/sync-protocol.test.mjs test/sync.test.mjs test/format-conformance.test.mjs`
Expected: PASS. The conformance suite must stay green — no committed fixture changes shape in this task.

- [ ] **Step 5: Commit**

```bash
git add src/sync.ts src/format-version.ts test/sync-protocol.test.mjs
git commit -m "feat(sync): accept version 3 change bodies"
```

---

### Task 3: The local blob store

A small module with one responsibility: seal attachment chunks for transport, and hold sealed blobs on disk under `documents/sync/blobs/<blobId>`. It knows nothing about the relay or about change bodies.

**Files:**
- Create: `src/sync-blobs.ts`
- Create: `test/sync-blobs.test.mjs`
- Modify: `package.json` (add the new test file to the `test` script)

**Interfaces:**
- Consumes: `encryptDocumentBytes` / `decryptDocumentBytes` (`src/document-crypto.ts`), `attachmentChunkAad` (`src/format-version.ts`), `ATTACHMENT_CHUNK_SIZE` (exported in Task 1).
- Produces:
  - `const MAX_BLOB_BYTES = 2 * 1024 * 1024`
  - `function sealAttachmentBlobs(data: Buffer, attachmentId: string, key: Buffer): { blobs: string[]; payloads: Buffer[] }`
  - `class SyncBlobStore { constructor(vaultDir: string); has(id: string): boolean; put(id: string, body: Buffer): void; read(id: string): Buffer; missing(ids: string[]): string[]; remove(id: string): void }`

`put` verifies `SHA-256(body) === id` before writing and throws otherwise, so a corrupted download can never be stored under a good name. Writes are atomic and symlink-checked, reusing the helpers `src/documents.ts` already imports (`resolveInside`, `assertNotSymlink`, `writeFileAtomic`).

- [ ] **Step 1: Write the failing test**

Create `test/sync-blobs.test.mjs`:

```js
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { SyncBlobStore, sealAttachmentBlobs } from "../dist/sync-blobs.js";
import { decryptDocumentBytes } from "../dist/document-crypto.js";
import { attachmentChunkAad } from "../dist/format-version.js";

const KEY = crypto.randomBytes(32);
const ATTACHMENT_ID = "c".repeat(64);

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "vault-brain-blobs-"));
}

test("sealed blobs are chunk-bound, hash-named and decrypt back to the original bytes", () => {
  const data = crypto.randomBytes(2 * 1024 * 1024 + 7);
  const { blobs, payloads } = sealAttachmentBlobs(data, ATTACHMENT_ID, KEY);

  assert.equal(blobs.length, 3);
  assert.equal(payloads.length, 3);
  for (const [index, payload] of payloads.entries()) {
    assert.equal(crypto.createHash("sha256").update(payload).digest("hex"), blobs[index]);
  }

  const parts = payloads.map((payload, index) =>
    decryptDocumentBytes(JSON.parse(payload.toString("utf8")), KEY, attachmentChunkAad(ATTACHMENT_ID, index)),
  );
  assert.deepEqual(Buffer.concat(parts), data);

  // The AAD binds the chunk to its index: reading chunk 1 as chunk 0 fails.
  assert.throws(() =>
    decryptDocumentBytes(JSON.parse(payloads[1].toString("utf8")), KEY, attachmentChunkAad(ATTACHMENT_ID, 0)),
  );
});

test("the blob store refuses a body that does not hash to its id", () => {
  const dir = tempDir();
  const store = new SyncBlobStore(dir);
  const body = Buffer.from("hello");
  const id = crypto.createHash("sha256").update(body).digest("hex");

  assert.equal(store.has(id), false);
  assert.throws(() => store.put("d".repeat(64), body), /does not match/i);

  store.put(id, body);
  assert.equal(store.has(id), true);
  assert.deepEqual(store.read(id), body);
  store.put(id, body); // idempotent
  assert.deepEqual(store.missing([id, "e".repeat(64)]), ["e".repeat(64)]);

  store.remove(id);
  assert.equal(store.has(id), false);
});

test("the blob store rejects an oversize body and a malformed id", () => {
  const store = new SyncBlobStore(tempDir());
  const big = Buffer.alloc(2 * 1024 * 1024 + 1);
  const id = crypto.createHash("sha256").update(big).digest("hex");
  assert.throws(() => store.put(id, big), /2 MiB/i);
  assert.throws(() => store.read("../escape"), /blob id/i);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm run build && node --test test/sync-blobs.test.mjs`
Expected: FAIL — `Cannot find module '../dist/sync-blobs.js'`.

- [ ] **Step 3: Implement the store**

Create `src/sync-blobs.ts`:

```ts
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { decryptDocumentBytes, encryptDocumentBytes } from "./document-crypto.js";
import { ATTACHMENT_CHUNK_SIZE } from "./documents.js";
import { attachmentChunkAad } from "./format-version.js";

export const MAX_BLOB_BYTES = 2 * 1024 * 1024;
const BLOB_ID_PATTERN = /^[0-9a-f]{64}$/u;

function assertBlobId(id: string): void {
  if (!BLOB_ID_PATTERN.test(id)) {
    throw new Error("A blob id must be 64 lowercase hexadecimal characters.");
  }
}

export function sealAttachmentBlobs(
  data: Buffer,
  attachmentId: string,
  key: Buffer,
): { blobs: string[]; payloads: Buffer[] } {
  const chunks = Math.ceil(data.length / ATTACHMENT_CHUNK_SIZE);
  const blobs: string[] = [];
  const payloads: Buffer[] = [];
  for (let index = 0; index < chunks; index += 1) {
    const chunk = data.subarray(index * ATTACHMENT_CHUNK_SIZE, (index + 1) * ATTACHMENT_CHUNK_SIZE);
    const payload = Buffer.from(
      JSON.stringify(encryptDocumentBytes(chunk, key, attachmentChunkAad(attachmentId, index))),
      "utf8",
    );
    if (payload.length > MAX_BLOB_BYTES) throw new Error("A sealed attachment chunk exceeds 2 MiB.");
    payloads.push(payload);
    blobs.push(crypto.createHash("sha256").update(payload).digest("hex"));
  }
  return { blobs, payloads };
}

export function openAttachmentBlob(payload: Buffer, attachmentId: string, index: number, key: Buffer): Buffer {
  return decryptDocumentBytes(
    JSON.parse(payload.toString("utf8")) as never,
    key,
    attachmentChunkAad(attachmentId, index),
  );
}

export class SyncBlobStore {
  private readonly dir: string;

  constructor(vaultDir: string) {
    this.dir = path.join(vaultDir, "documents", "sync", "blobs");
  }

  private pathFor(id: string): string {
    assertBlobId(id);
    return path.join(this.dir, id);
  }

  has(id: string): boolean {
    return fs.existsSync(this.pathFor(id));
  }

  put(id: string, body: Buffer): void {
    const target = this.pathFor(id);
    if (body.length > MAX_BLOB_BYTES) throw new Error("A blob may not exceed 2 MiB.");
    if (crypto.createHash("sha256").update(body).digest("hex") !== id) {
      throw new Error("Blob content does not match its id.");
    }
    if (fs.existsSync(target)) return;
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    const temporary = `${target}.${crypto.randomUUID()}.tmp`;
    fs.writeFileSync(temporary, body, { mode: 0o600 });
    fs.renameSync(temporary, target);
  }

  read(id: string): Buffer {
    const target = this.pathFor(id);
    const stat = fs.lstatSync(target);
    if (stat.isSymbolicLink()) throw new Error("A blob path may not be a symlink.");
    if (stat.size > MAX_BLOB_BYTES) throw new Error("A blob may not exceed 2 MiB.");
    return fs.readFileSync(target);
  }

  missing(ids: string[]): string[] {
    return ids.filter((id) => !this.has(id));
  }

  remove(id: string): void {
    fs.rmSync(this.pathFor(id), { force: true });
  }
}
```

- [ ] **Step 4: Register and run the tests**

Add `test/sync-blobs.test.mjs` to the `test` script's file list in `package.json`, immediately after `test/sync-relay.test.mjs`.

Run: `npm run build && node --test test/sync-blobs.test.mjs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/sync-blobs.ts test/sync-blobs.test.mjs package.json
git commit -m "feat(sync): add the local attachment blob store"
```

---

### Task 4: The writer emits blob-form snapshots

**Files:**
- Modify: `src/sync.ts:62-76` (delete `MAX_SYNC_ATTACHMENT_BYTES`)
- Modify: `src/sync.ts:1792-1794` (`attachmentSnapshot`)
- Modify: `src/sync.ts:2812-2846` (`putAttachment` override), `src/sync.ts:2846-2868` (`removeAttachment` override), `src/sync.ts:2715-2730` and `src/sync.ts:3026-3035` (the two snapshot comparison sites)
- Test: `test/sync.test.mjs`

**Interfaces:**
- Consumes: `sealAttachmentBlobs`, `SyncBlobStore` (Task 3); `sameAttachmentSnapshot` (Task 1).
- Produces: a `SyncedDocumentVault` whose attachment changes carry `{ filename, mime, size, chunks, blobs }`, with the sealed payloads staged in the vault's blob store.

- [ ] **Step 1: Write the failing test**

Append to `test/sync.test.mjs`:

```js
test("an attachment larger than the old 6 MiB ceiling is captured as blob references", async () => {
  const { SyncedDocumentVault, SyncDeviceManager, parseAttachmentSnapshot, isBlobAttachmentSnapshot } = await import(
    "../dist/sync.js"
  );
  const { SyncBlobStore } = await import("../dist/sync-blobs.js");
  const dir = tempVault("blob-writer");
  new SyncDeviceManager(dir, PASSPHRASE).initializeOwner("device-a", DEVICE_A);
  const vault = new SyncedDocumentVault(dir, PASSPHRASE, DEVICE_A);

  const data = crypto.randomBytes(9 * 1024 * 1024); // above MAX_SYNC_ATTACHMENT_BYTES
  const info = vault.putAttachment(data, "big.bin", "application/octet-stream");
  assert.equal(info.size, data.length);

  const changes = vault.changeLog.list().filter((change) => change.mutation.objectType === "attachment");
  const snapshot = parseAttachmentSnapshot(changes.at(-1).mutation.value);
  assert.equal(isBlobAttachmentSnapshot(snapshot), true);
  assert.equal(snapshot.size, data.length);
  assert.equal(snapshot.chunks, 9);
  assert.equal(snapshot.blobs.length, 9);

  const store = new SyncBlobStore(dir);
  assert.deepEqual(store.missing(snapshot.blobs), []);
  assert.deepEqual(vault.getAttachment(info.id).data, data);
  vault.close();
});
```

If `changeLog` is not reachable from `SyncedDocumentVault` in the test, read the changes with `new SyncChangeLog(dir, PASSPHRASE).list()` instead — that class is already imported by this file.

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm run build && node --test test/sync.test.mjs`
Expected: FAIL with `A synchronized attachment cannot exceed 6242304 bytes until blob transport is available.`

- [ ] **Step 3: Implement the writer**

Delete `MAX_SYNC_ATTACHMENT_BYTES` (`src/sync.ts:75`) and the guard that uses it at the top of the `putAttachment` override (`src/sync.ts:2814-2819`). Leave `MAX_CHANGE_BYTES` alone.

Replace `attachmentSnapshot` (`src/sync.ts:1792`) with a blob-form producer that also stages the payloads:

```ts
function attachmentSnapshot(
  data: Buffer,
  info: AttachmentInfo,
  key: Buffer,
  store: SyncBlobStore,
): BlobAttachmentSyncSnapshot {
  const { blobs, payloads } = sealAttachmentBlobs(data, info.id, key);
  for (const [index, payload] of payloads.entries()) store.put(blobs[index], payload);
  return { filename: info.filename, mime: info.mime, size: info.size, chunks: info.chunks, blobs };
}
```

Add a `private readonly blobStore = new SyncBlobStore(this.syncVaultDir);` field to `SyncedDocumentVault`, and pass `this.session.key, this.blobStore` at each of the four `attachmentSnapshot(...)` call sites (`src/sync.ts:2722`, `:2824`, `:2839`, `:2853`, `:3032`).

At the two comparison sites, swap the generic comparison for the attachment-aware one:

- `src/sync.ts:2729` — `if (existing && sameSyncValue(currentValue, operation.targetValue)) continue;` becomes `if (existing && currentValue !== null && sameAttachmentSnapshot(currentValue, operation.targetValue)) continue;`
- `src/sync.ts:2485-2487` — the `operation.objectType === "attachment"` branch's `sameSyncValue(operation.beforeValue, operation.targetValue)` becomes `sameAttachmentSnapshot(operation.beforeValue, operation.targetValue)`, guarded by both values being non-null.
- `src/sync.ts:3032` — `sameSyncValue(asSyncJson(attachmentSnapshot(...)), value)` becomes `sameAttachmentSnapshot(asSyncJson(attachmentSnapshot(attachment.data, attachment.info, this.session.key, this.blobStore)), value)`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm run build && node --test test/sync.test.mjs test/sync-apply.test.mjs test/sync-transaction.test.mjs`
Expected: PASS. Existing tests that assert on inline attachment snapshots will need their expectations updated to the blob form — update them; do not reintroduce inline writing.

- [ ] **Step 5: Commit**

```bash
git add src/sync.ts test/sync.test.mjs test/sync-apply.test.mjs test/sync-transaction.test.mjs
git commit -m "feat(sync): capture attachments as blob references and lift the 6 MiB ceiling"
```

---

### Task 5: Apply reassembles from blobs and fails closed

**Files:**
- Modify: `src/sync.ts:3072-3082` (the attachment branch of `applyStorageChange`)
- Test: `test/sync-apply.test.mjs`

**Interfaces:**
- Consumes: `SyncBlobStore`, `openAttachmentBlob` (Task 3); `parseAttachmentSnapshot`, `isBlobAttachmentSnapshot` (Task 1).
- Produces: `applyStorageChange` handling both snapshot forms; a missing chunk throws `"<n> of <m> attachment chunks are missing."` and writes nothing.

- [ ] **Step 1: Write the failing test**

Append to `test/sync-apply.test.mjs`:

```js
test("applying an attachment change fails closed while its blobs are missing", async () => {
  const { SyncedDocumentVault, SyncDeviceManager, SyncChangeLog, parseAttachmentSnapshot } = await import(
    "../dist/sync.js"
  );
  const { SyncBlobStore } = await import("../dist/sync-blobs.js");

  const source = tempVault("blob-apply-source");
  const target = tempVault("blob-apply-target");
  const manager = new SyncDeviceManager(source, PASSPHRASE);
  manager.initializeOwner("device-a", DEVICE_A);

  const sourceVault = new SyncedDocumentVault(source, PASSPHRASE, DEVICE_A);
  const data = crypto.randomBytes(3 * 1024 * 1024 + 11);
  const info = sourceVault.putAttachment(data, "clip.bin", "application/octet-stream");
  const envelopes = new SyncChangeLog(source, PASSPHRASE).envelopes();
  sourceVault.close();

  // The target device receives the envelopes but not yet the blobs.
  fs.cpSync(path.join(source, "documents", "sync", "devices.enc"), path.join(target, "documents", "sync", "devices.enc"), {
    recursive: false,
  });
  const targetVault = new SyncedDocumentVault(target, PASSPHRASE, DEVICE_A);
  new SyncChangeLog(target, PASSPHRASE).import(envelopes);
  assert.throws(() => targetVault.applySyncChange("attachment", info.id), /of 4 attachment chunks are missing/i);
  assert.equal(targetVault.listAttachments().length, 0);

  // Once every blob is staged, the same apply succeeds and the bytes verify.
  const snapshot = parseAttachmentSnapshot(
    new SyncChangeLog(target, PASSPHRASE).list().at(-1).mutation.value,
  );
  const from = new SyncBlobStore(source);
  const to = new SyncBlobStore(target);
  for (const id of snapshot.blobs) to.put(id, from.read(id));

  targetVault.applySyncChange("attachment", info.id);
  assert.deepEqual(targetVault.getAttachment(info.id).data, data);
  targetVault.close();
});
```

Use whatever the file's existing helper for applying a resolved change is named — this file already exercises `resolve`/`apply`; match its call, and keep the two assertions (fail-closed first, success after staging).

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm run build && node --test test/sync-apply.test.mjs`
Expected: FAIL — the current branch calls `Buffer.from(snapshot.data, "base64")` on a snapshot that has no `data`, so it throws a type error rather than the chunk-count message.

- [ ] **Step 3: Implement reassembly**

Replace the attachment `put` branch of `applyStorageChange` (`src/sync.ts:3072-3082`):

```ts
if (objectType === "attachment") {
  if (operation === "delete") {
    if (super.listAttachments().some((item) => item.id === objectId)) super.removeAttachment(objectId);
    return;
  }
  const snapshot = parseAttachmentSnapshot(value);
  let data: Buffer;
  if (isBlobAttachmentSnapshot(snapshot)) {
    const missing = this.blobStore.missing(snapshot.blobs);
    if (missing.length > 0) {
      throw new Error(`${missing.length} of ${snapshot.blobs.length} attachment chunks are missing.`);
    }
    data = Buffer.concat(
      snapshot.blobs.map((id, index) =>
        openAttachmentBlob(this.blobStore.read(id), objectId, index, this.session.key),
      ),
    );
    if (data.length !== snapshot.size) throw new Error("Attachment sync size does not match its blobs.");
  } else {
    data = Buffer.from(snapshot.data, "base64");
  }
  const info = super.putAttachment(data, snapshot.filename, snapshot.mime);
  if (info.id !== objectId) throw new Error("Attachment sync snapshot does not match its content ID.");
  return;
}
```

The `openAttachmentBlob` call passes `objectId` as the attachment id, so a relay that reorders chunks or substitutes one from a different attachment fails the AEAD's AAD check before the content-address check is even reached.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm run build && node --test test/sync-apply.test.mjs test/sync.test.mjs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/sync.ts test/sync-apply.test.mjs
git commit -m "feat(sync): reassemble attachments from blobs and refuse partial applies"
```

---

### Task 6: The relay serves a blobs collection

**Files:**
- Modify: `src/sync-relay.ts:135-260` (route parsing and the request handler)
- Test: `test/sync-relay.test.mjs`

**Interfaces:**
- Consumes: `MAX_BLOB_BYTES` (Task 3).
- Produces: `PUT /blobs/<id>` and `GET /blobs/<id>` on the relay; no list route for blobs.

- [ ] **Step 1: Write the failing test**

Append to `test/sync-relay.test.mjs`:

```js
test("the relay stores blobs only under their own SHA-256 and never lists them", async () => {
  const storage = tempDir("blob-relay");
  const relay = await startSyncRelay({ storage, token: TOKEN, port: 0 });
  const base = `http://127.0.0.1:${relay.port}`;
  const headers = { authorization: `Bearer ${TOKEN}`, "content-type": "application/octet-stream" };
  const body = crypto.randomBytes(1024);
  const id = crypto.createHash("sha256").update(body).digest("hex");

  const wrong = await fetch(`${base}/blobs/${"f".repeat(64)}`, { method: "PUT", headers, body });
  assert.equal(wrong.status, 400);

  const first = await fetch(`${base}/blobs/${id}`, { method: "PUT", headers, body });
  assert.equal(first.status, 201);
  const again = await fetch(`${base}/blobs/${id}`, { method: "PUT", headers, body });
  assert.equal(again.status, 200);

  const fetched = await fetch(`${base}/blobs/${id}`, { headers: { authorization: `Bearer ${TOKEN}` } });
  assert.equal(fetched.status, 200);
  assert.deepEqual(Buffer.from(await fetched.arrayBuffer()), body);

  const missing = await fetch(`${base}/blobs/${"a".repeat(64)}`, { headers: { authorization: `Bearer ${TOKEN}` } });
  assert.equal(missing.status, 404);

  const listed = await fetch(`${base}/blobs`, { headers: { authorization: `Bearer ${TOKEN}` } });
  assert.equal(listed.status, 404);

  const oversize = Buffer.alloc(2 * 1024 * 1024 + 1);
  const oversizeId = crypto.createHash("sha256").update(oversize).digest("hex");
  const rejected = await fetch(`${base}/blobs/${oversizeId}`, { method: "PUT", headers, body: oversize });
  assert.equal(rejected.status, 413);

  const unauthorized = await fetch(`${base}/blobs/${id}`);
  assert.equal(unauthorized.status, 401);

  await relay.close();
});
```

Match the existing tests in this file for how the relay is started and closed, and for the exact status codes the handler already uses for a fresh write versus an idempotent one; adjust the two `assert.equal(..., 201/200)` lines to the codes that file already asserts for change writes.

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm run build && node --test test/sync-relay.test.mjs`
Expected: FAIL — `/blobs/<id>` is not a known collection, so the handler returns 404 for the PUT.

- [ ] **Step 3: Implement the collection**

In `src/sync-relay.ts`, add `blobs` to the set of accepted collections in `parseRoute`, and in the request handler branch on it before the JSON-envelope path:

```ts
if (route.collection === "blobs") {
  if (!route.id || !/^[0-9a-f]{64}$/u.test(route.id)) throw new HttpError(400, "Invalid blob id.");
  if (request.method === "PUT") {
    const body = await requestBody(request, MAX_BLOB_BYTES);
    if (crypto.createHash("sha256").update(body).digest("hex") !== route.id) {
      throw new HttpError(400, "Blob content does not match its id.");
    }
    assertQuota(storage, body.length);
    const created = immutableWrite(blobPath(storage, route.id), body);
    response.writeHead(created ? 201 : 200, { "Content-Length": 0 });
    response.end();
    return;
  }
  if (request.method === "GET") {
    const target = blobPath(storage, route.id);
    if (!fs.existsSync(target)) throw new HttpError(404, "Not found.");
    const body = fs.readFileSync(target);
    response.writeHead(200, { "Content-Type": "application/octet-stream", "Content-Length": body.length });
    response.end(body);
    return;
  }
  throw new HttpError(405, "Method not allowed.");
}
```

Use the file's own error-reporting mechanism rather than inventing `HttpError` if one already exists, and its own quota helper rather than `assertQuota` — the names above are placeholders for whatever `src/sync-relay.ts` already calls when a change write exceeds a quota. Store blobs under `<storage>/blobs/<id>` via a `blobPath` helper alongside the existing per-collection path helper. `requestBody` already enforces the byte limit and must be given `MAX_BLOB_BYTES`; make the over-limit path answer 413.

Blobs count toward the existing storage and object-count quotas exactly as changes do.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm run build && node --test test/sync-relay.test.mjs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/sync-relay.ts test/sync-relay.test.mjs
git commit -m "feat(relay): serve an opaque content-verified blobs collection"
```

---

### Task 7: Push and pull move blobs, resumably

**Files:**
- Modify: `src/sync-relay.ts:370-418` (`SyncRelayClient` push and pull)
- Test: `test/sync-relay.test.mjs`

**Interfaces:**
- Consumes: `SyncBlobStore` (Task 3), `parseAttachmentSnapshot` / `isBlobAttachmentSnapshot` (Task 1), the relay routes (Task 6).
- Produces:
  - `SyncRelayClient.pushBlobs(ids: string[]): Promise<{ uploaded: number; skipped: number }>`
  - `SyncRelayClient.pullBlobs(ids: string[]): Promise<{ fetched: number; skipped: number }>`
  - `push` uploads every blob a change references **before** the change envelope; `pull` fetches blobs for the changes it admits.

- [ ] **Step 1: Write the failing test**

Append to `test/sync-relay.test.mjs`:

```js
test("a push uploads blobs before the change, and an interrupted pull resumes", async () => {
  const storage = tempDir("blob-transport");
  const relay = await startSyncRelay({ storage, token: TOKEN, port: 0 });
  const url = `http://127.0.0.1:${relay.port}`;

  const source = tempDir("blob-source");
  const target = tempDir("blob-target");
  const { SyncedDocumentVault, SyncDeviceManager, SyncChangeLog } = await import("../dist/sync.js");
  const { SyncBlobStore } = await import("../dist/sync-blobs.js");
  new SyncDeviceManager(source, PASSPHRASE).initializeOwner("device-a", DEVICE_ID);
  const vault = new SyncedDocumentVault(source, PASSPHRASE, DEVICE_ID);
  const data = crypto.randomBytes(3 * 1024 * 1024 + 5);
  const info = vault.putAttachment(data, "clip.bin", "application/octet-stream");
  vault.close();

  await new SyncRelayClient(url, TOKEN, source, PASSPHRASE).push();

  // Every blob is on the relay, and so is the change.
  const store = new SyncBlobStore(source);
  const changes = new SyncChangeLog(source, PASSPHRASE).list();
  const snapshot = changes.at(-1).mutation.value;
  for (const id of snapshot.blobs) {
    const head = await fetch(`${url}/blobs/${id}`, { headers: { authorization: `Bearer ${TOKEN}` } });
    assert.equal(head.status, 200);
  }

  // Simulate an interrupted pull: stage all but the last blob, then resume.
  const targetStore = new SyncBlobStore(target);
  for (const id of snapshot.blobs.slice(0, -1)) targetStore.put(id, store.read(id));
  const client = new SyncRelayClient(url, TOKEN, target, PASSPHRASE);
  const result = await client.pullBlobs(snapshot.blobs);
  assert.equal(result.fetched, 1);
  assert.equal(result.skipped, snapshot.blobs.length - 1);
  assert.deepEqual(targetStore.missing(snapshot.blobs), []);
  assert.equal(info.size, data.length);

  await relay.close();
});
```

Match the file's existing `SyncRelayClient` constructor signature; the four arguments above are illustrative of what the class needs (endpoint, token, vault directory, passphrase) and must be replaced with the real one.

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm run build && node --test test/sync-relay.test.mjs`
Expected: FAIL — `client.pullBlobs is not a function`.

- [ ] **Step 3: Implement blob transport**

In `SyncRelayClient`:

```ts
private blobIdsFor(change: SyncChange): string[] {
  if (change.mutation.objectType !== "attachment" || change.mutation.operation !== "put") return [];
  const snapshot = parseAttachmentSnapshot(change.mutation.value);
  return isBlobAttachmentSnapshot(snapshot) ? snapshot.blobs : [];
}

async pushBlobs(ids: string[]): Promise<{ uploaded: number; skipped: number }> {
  let uploaded = 0;
  let skipped = 0;
  for (const id of ids) {
    const existing = await this.request("GET", `/blobs/${id}`, undefined, [200, 404]);
    if (existing.status === 200) {
      skipped += 1;
      continue;
    }
    await this.request("PUT", `/blobs/${id}`, this.blobStore.read(id), [200, 201]);
    uploaded += 1;
  }
  return { uploaded, skipped };
}

async pullBlobs(ids: string[]): Promise<{ fetched: number; skipped: number }> {
  let fetched = 0;
  let skipped = 0;
  for (const id of ids) {
    if (this.blobStore.has(id)) {
      skipped += 1;
      continue;
    }
    const response = await this.request("GET", `/blobs/${id}`, undefined, [200]);
    this.blobStore.put(id, response.body); // put re-verifies SHA-256(body) === id
    fetched += 1;
  }
  return { fetched, skipped };
}
```

Then, in `push`, for each change about to be sent: `await this.pushBlobs(this.blobIdsFor(change));` **before** the envelope PUT. In `pull`, after admitting a batch of envelopes, collect `blobIdsFor` over the admitted changes and `await this.pullBlobs(...)`.

`this.request(...)` stands in for the file's existing HTTP helper; use it, and add the accepted-status argument only if the helper does not already expose one. `this.blobStore` is a `SyncBlobStore` constructed from the client's vault directory.

Resumability needs no extra state: `pushBlobs` skips what the relay already has, `pullBlobs` skips what the store already has, and both are safe to re-run.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm run build && node --test test/sync-relay.test.mjs test/sync.test.mjs test/sync-apply.test.mjs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/sync-relay.ts test/sync-relay.test.mjs
git commit -m "feat(relay): transfer attachment blobs before their changes and resume partial transfers"
```

---

### Task 8: CLI — blob status, fetch, prune, and bundle transport

**Files:**
- Modify: `src/cli.ts:1180-1210` (`sync export`, `sync import`) and the `sync` command group around `src/cli.ts:1131`
- Test: `test/cli.test.mjs`

**Interfaces:**
- Consumes: `SyncBlobStore` (Task 3), `SyncRelayClient.pullBlobs` (Task 7).
- Produces:
  - `sbrain sync blobs status` — per pending attachment change, how many chunks are present and missing
  - `sbrain sync blobs fetch <url>` — fetch only the missing blobs for already-admitted changes
  - `sbrain sync blobs prune <url>` — delete staged blobs the relay confirms it holds
  - `sbrain sync export --bundle <dir>` — `changes.json` plus `blobs/<id>`
  - `sbrain sync import <source>` — accepts a JSON file (unchanged) or a bundle directory

- [ ] **Step 1: Write the failing test**

Append to `test/cli.test.mjs`, following the file's existing helper for invoking the CLI:

```js
test("sync export --bundle carries attachment blobs to another vault without a relay", async () => {
  const source = tempVault("bundle-source");
  const target = tempVault("bundle-target");
  const bundle = path.join(os.tmpdir(), `vault-brain-bundle-${crypto.randomUUID()}`);

  runCli(source, ["sync", "devices", "init", "device-a"]);
  const file = path.join(os.tmpdir(), `big-${crypto.randomUUID()}.bin`);
  fs.writeFileSync(file, crypto.randomBytes(3 * 1024 * 1024 + 3));
  runCli(source, ["docs", "attach", file]); // use this repo's actual attach command

  runCli(source, ["sync", "export", "--bundle", bundle]);
  assert.ok(fs.existsSync(path.join(bundle, "changes.json")));
  assert.ok(fs.readdirSync(path.join(bundle, "blobs")).length >= 4);

  runCli(target, ["sync", "import", bundle]);
  const status = runCli(target, ["sync", "blobs", "status"]);
  assert.match(status, /0 missing/);
});
```

Replace `runCli` and the attach command with this file's real equivalents. Every `sync` invocation needs the `--experimental-trusted-sync` flag the group's `preAction` hook demands.

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm run build && node --test test/cli.test.mjs`
Expected: FAIL — `error: unknown option '--bundle'`.

- [ ] **Step 3: Implement the commands**

Add to the `sync` group in `src/cli.ts`:

```ts
const syncBlobs = sync.command("blobs").description("staged encrypted attachment chunks");

syncBlobs
  .command("status")
  .description("report present and missing chunks for pending attachment changes")
  .action(async () => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const log = new SyncChangeLog(dir, passphrase);
    const store = new SyncBlobStore(dir);
    try {
      for (const change of log.list()) {
        if (change.mutation.objectType !== "attachment" || change.mutation.operation !== "put") continue;
        const snapshot = parseAttachmentSnapshot(change.mutation.value);
        if (!isBlobAttachmentSnapshot(snapshot)) continue;
        const missing = store.missing(snapshot.blobs).length;
        console.log(`${change.mutation.objectId} ${snapshot.blobs.length - missing} present, ${missing} missing`);
      }
    } finally {
      log.close();
    }
  });
```

`fetch <url>` builds the same missing list and calls `client.pullBlobs(missing)`. `prune <url>` walks the staged blob ids, `GET /blobs/<id>` each, and calls `store.remove(id)` only on a 200 — a blob the relay does not hold is never dropped locally.

For `export --bundle <dir>`: write `changes.json` with the same JSON the stdout path produces, create `blobs/`, and copy every blob referenced by an exported attachment change out of the store. For `import <source>`: if `fs.statSync(source).isDirectory()`, read `changes.json` from it and `store.put(id, body)` each file in `blobs/` (which re-verifies each hash) before importing the envelopes; otherwise keep today's behavior exactly.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm run build && node --test test/cli.test.mjs test/sync-blobs.test.mjs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cli.ts test/cli.test.mjs
git commit -m "feat(cli): add blob status, fetch, prune and bundle transport"
```

---

### Task 9: Fixtures, the Rust pin, and the documentation

**Files:**
- Modify: `scripts/make-fixtures.mjs`
- Create: `test/fixtures/sync-attachment-blobs-v3/` (generated, then committed)
- Modify: `test/format-conformance.test.mjs`
- Modify: `src-tauri/src/lib.rs` (a test only)
- Modify: `docs/FORMAT-1.0.md`, `docs/SYNC-RELAY.md`, `docs/AUDIT-SCOPE.md`, `docs/ROADMAP.md`, `README.md`

**Interfaces:**
- Consumes: everything above.
- Produces: a committed conformance fixture holding a version 3 attachment change, read by both implementations.

- [ ] **Step 1: Write the failing conformance test**

In `test/format-conformance.test.mjs`, add a case that opens `test/fixtures/sync-attachment-blobs-v3/`, reads its change log, asserts the last attachment change body is `version: 3` with a `blobs` array of the expected length, stages the fixture's blobs, applies the change, and compares the recovered bytes against the fixture's recorded SHA-256.

In `src-tauri/src/lib.rs`, add a `#[test]` next to `sync_status_counts_changes_without_decrypting_them` that points `sync_status` at the same fixture directory and asserts the change count, proving the Rust core is unaffected by version 3 bodies.

- [ ] **Step 2: Run both suites to verify they fail**

Run: `npm run build && node --test test/format-conformance.test.mjs`
Expected: FAIL — the fixture directory does not exist.

Run: `cargo test --manifest-path src-tauri/Cargo.toml --lib`
Expected: FAIL — same reason.

- [ ] **Step 3: Generate the fixture and update the docs**

Extend `scripts/make-fixtures.mjs` with a generator that creates a vault, enrolls one device, adds a ~3.5 MiB attachment (four chunks) with deterministic bytes, and copies the vault plus its staged blobs into `test/fixtures/sync-attachment-blobs-v3/`. Then run `npm run fixtures` and commit the output.

Documentation, each edit stated in the spec's final section:

- `docs/FORMAT-1.0.md` — `version: 3` in the `SyncChangeBody` listing; both snapshot forms; the blob id derivation (`SHA-256` of the sealed chunk bytes) and why it is not keyed; the `chunks`/`blobs.length`/`size` agreement rule and the 256 cap; `syncChangeEnvelope` now `reads: [1, 2, 3], writes: [1, 2, 3]`.
- `docs/SYNC-RELAY.md` — the `blobs` collection, its 2 MiB per-object limit, that it has no list route, and the retention non-goal (blobs of a deleted attachment are not collected).
- `docs/AUDIT-SCOPE.md` — replace the accepted-risk bullet about the 6,242,304-byte ceiling with a description of the blob path as review surface, and add it to the §9 allocation table.
- `docs/ROADMAP.md` — check off "Resumable chunked transport for large attachment blobs" and drop its explanatory sub-bullet.
- `README.md` — the sync paragraph currently stating the 8 MiB ceiling.

- [ ] **Step 4: Run the full quality gate**

Run: `npm run quality`
Expected: PASS — lint, format check, typecheck, the full Node suite, the desktop suite, and the desktop build.

Run: `npm run quality:rust`
Expected: PASS — clippy with `-D warnings` and the Rust test suite.

Run: `npm run recovery:drill`
Expected: PASS — the backup-plus-relay-catch-up drill still completes; if it exercises attachments it now exercises blob transport too.

- [ ] **Step 5: Commit**

```bash
git add scripts/make-fixtures.mjs test/fixtures/sync-attachment-blobs-v3 test/format-conformance.test.mjs \
  src-tauri/src/lib.rs docs/FORMAT-1.0.md docs/SYNC-RELAY.md docs/AUDIT-SCOPE.md docs/ROADMAP.md README.md
git commit -m "feat(sync): pin version 3 attachment fixtures and document blob transport"
```

---

### Task 10: End-to-end — integrity, ordering, and a 12 MiB round trip

The spec's testing section asks for three properties no earlier task proves: that a substituted blob is caught, that the relay never advertises a change ahead of its bytes, and that an attachment well above the old ceiling survives a real device-to-device trip.

**Files:**
- Create: `test/sync-blob-transport.test.mjs`
- Modify: `package.json` (add the new test file to the `test` script)

**Interfaces:**
- Consumes: everything from Tasks 1-8. Adds no production code — if a test here fails, the fix belongs in the task that owns the behavior.

- [ ] **Step 1: Write the failing tests**

Create `test/sync-blob-transport.test.mjs`:

```js
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { startSyncRelay, SyncRelayClient } from "../dist/sync-relay.js";
import { SyncBlobStore } from "../dist/sync-blobs.js";
import { SyncChangeLog, SyncDeviceManager, SyncedDocumentVault, parseAttachmentSnapshot } from "../dist/sync.js";

const PASSPHRASE = "blob-transport-passphrase";
const DEVICE_A = "11111111-1111-4111-8111-111111111111";
const TOKEN = "relay-test-token-that-is-at-least-thirty-two-bytes";

function tempDir(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `vault-brain-${label}-`));
}

test("a 12 MiB attachment survives a device-to-device round trip through the relay", async () => {
  const storage = tempDir("roundtrip-relay");
  const relay = await startSyncRelay({ storage, token: TOKEN, port: 0 });
  const url = `http://127.0.0.1:${relay.port}`;
  const source = tempDir("roundtrip-source");
  const target = tempDir("roundtrip-target");

  new SyncDeviceManager(source, PASSPHRASE).initializeOwner("device-a", DEVICE_A);
  const sourceVault = new SyncedDocumentVault(source, PASSPHRASE, DEVICE_A);
  const data = crypto.randomBytes(12 * 1024 * 1024);
  const digest = crypto.createHash("sha256").update(data).digest("hex");
  const info = sourceVault.putAttachment(data, "video.bin", "application/octet-stream");
  sourceVault.close();

  await new SyncRelayClient(url, TOKEN, source, PASSPHRASE).push();
  await new SyncRelayClient(url, TOKEN, target, PASSPHRASE).pull();

  const targetVault = new SyncedDocumentVault(target, PASSPHRASE, DEVICE_A);
  targetVault.applySyncChange("attachment", info.id);
  const recovered = targetVault.getAttachment(info.id);
  assert.equal(crypto.createHash("sha256").update(recovered.data).digest("hex"), digest);
  assert.equal(recovered.info.size, 12 * 1024 * 1024);
  targetVault.close();
  await relay.close();
});

test("the relay never advertises an attachment change before it holds every blob", async () => {
  const storage = tempDir("ordering-relay");
  const relay = await startSyncRelay({ storage, token: TOKEN, port: 0 });
  const url = `http://127.0.0.1:${relay.port}`;
  const source = tempDir("ordering-source");

  new SyncDeviceManager(source, PASSPHRASE).initializeOwner("device-a", DEVICE_A);
  const vault = new SyncedDocumentVault(source, PASSPHRASE, DEVICE_A);
  const info = vault.putAttachment(crypto.randomBytes(3 * 1024 * 1024 + 9), "clip.bin", "application/octet-stream");
  vault.close();

  const seen = [];
  const client = new SyncRelayClient(url, TOKEN, source, PASSPHRASE);
  const original = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    if ((init?.method ?? "GET") === "PUT") seen.push(new URL(String(input)).pathname.split("/")[1]);
    return original(input, init);
  };
  try {
    await client.push();
  } finally {
    globalThis.fetch = original;
  }

  const firstChange = seen.indexOf("changes");
  const lastBlob = seen.lastIndexOf("blobs");
  assert.ok(lastBlob >= 0, "the push uploaded at least one blob");
  assert.ok(firstChange > lastBlob, "every blob PUT precedes the first change PUT");
  assert.ok(info.id.length === 64);
  await relay.close();
});

test("a substituted blob is refused rather than written into the vault", async () => {
  const source = tempDir("tamper-source");
  const target = tempDir("tamper-target");
  new SyncDeviceManager(source, PASSPHRASE).initializeOwner("device-a", DEVICE_A);
  const vault = new SyncedDocumentVault(source, PASSPHRASE, DEVICE_A);
  const info = vault.putAttachment(crypto.randomBytes(2 * 1024 * 1024 + 3), "doc.bin", "application/octet-stream");
  const envelopes = new SyncChangeLog(source, PASSPHRASE).envelopes();
  vault.close();

  const targetLog = new SyncChangeLog(target, PASSPHRASE);
  targetLog.import(envelopes);
  const snapshot = parseAttachmentSnapshot(targetLog.list().at(-1).mutation.value);
  targetLog.close();

  // Stage every blob, but swap chunk 0's payload for chunk 1's under chunk 0's id.
  const from = new SyncBlobStore(source);
  const to = new SyncBlobStore(target);
  for (const id of snapshot.blobs) to.put(id, from.read(id));
  const decoy = from.read(snapshot.blobs[1]);
  fs.writeFileSync(path.join(target, "documents", "sync", "blobs", snapshot.blobs[0]), decoy);

  const targetVault = new SyncedDocumentVault(target, PASSPHRASE, DEVICE_A);
  assert.throws(() => targetVault.applySyncChange("attachment", info.id));
  assert.equal(targetVault.listAttachments().length, 0);
  targetVault.close();
});
```

The substitution is written past `SyncBlobStore.put` on purpose — `put` would reject it, so the test writes the file directly to prove the *apply* path also refuses. The AAD binds each chunk to its index, so decryption fails before the content-address check is reached; either failure is an acceptable pass, which is why the assertion does not pin a message.

Replace `applySyncChange`, `SyncRelayClient`'s constructor, and `startSyncRelay`'s options with this repo's real signatures — Tasks 5, 6 and 7 establish them.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npm run build && node --test test/sync-blob-transport.test.mjs`
Expected: FAIL — the file is new and, before Tasks 1-8 are complete, the imports do not resolve.

- [ ] **Step 3: Register the test file**

Add `test/sync-blob-transport.test.mjs` to the `test` script's file list in `package.json`, after `test/sync-blobs.test.mjs`. No production code changes belong in this task; if a test fails, fix the owning task's code.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm run build && node --test test/sync-blob-transport.test.mjs`
Expected: PASS, all three.

- [ ] **Step 5: Commit**

```bash
git add test/sync-blob-transport.test.mjs package.json
git commit -m "test(sync): cover blob integrity, push ordering and a 12 MiB round trip"
```

---

## Notes for the executor

- **The `SyncRelayClient` and CLI signatures in Tasks 7 and 8 are illustrative.** Both files have established shapes; read them first and match what is there rather than introducing a second style.
- **Do not reintroduce inline writing.** After Task 4 the writer emits only the blob form. The inline branch exists solely to read history and committed fixtures.
- **Staged blobs are retained.** A device that adds an attachment keeps a sealed transport copy of it (roughly 1.37× the attachment size) until `sync blobs prune <url>` confirms the relay holds it. This is deliberate: blob ids cannot be recomputed from local storage, because each seal draws a fresh nonce.
- **Relay-side retention is out of scope** by the spec's Non-goals, and so is byte-range resume within a chunk.
