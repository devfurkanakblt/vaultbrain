# Phase 7.4 Full Re-key Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `vbrain rekey`, which generates a new vault keyset and re-encrypts every object under it, so a leaked passphrase stops opening the vault.

**Architecture:** A new `src/keyring-rekey.ts` enumerates every encrypted artifact and maps each to the AAD identity it was written with, re-encrypts each into a `.rekey/new/` staging tree under the vault, verifies the staged tree opens under the new keyset, then commits by writing a journal, writing the new `keyring.json`, and renaming each staged file over its live counterpart. A crash before the keyring write rolls back; a crash after it is finished by the next run from the journal.

**Tech Stack:** TypeScript (ESM, `tsc -p .` to `dist/`), Node built-in `crypto`, `node:test` with `node:assert/strict`, commander for the CLI.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-09-04-phase-7-4-full-rekey-design.md`. Read it before Task 1.
- Rotated keys: `documents`, `kv`, `syncEnvelope`. Pinned keys, carried into the new keyset byte for byte: `attachmentId`, `syncChange`, `audit`.
- **Every AAD is reproduced byte for byte.** A re-key changes keys, never identities. No file is renamed, no directory moves.
- All tests are `.mjs` under `test/`, import from `../dist/*.js`, and run under `node --test`. `npm test` builds first.
- New test files must be added to the `test` script in `package.json:34` — the file list is explicit.
- Every mutating operation runs inside `withVaultLock(vaultDir, fn)` from `src/vault-lock.ts`. It is re-entrant and **synchronous only** — the callback must not be `async`.
- Key material is zeroized with `.fill(0)` / `zeroKeySet()` on every exit path, including `finally` blocks. Follow the existing style in `src/keyring.ts` and `src/keyring-passphrase.ts`.
- Commit messages: lowercase `type: subject`, body explains why. Every commit ends with:
  ```
  Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_0117aYpsscAmKUx8LtubpHyi
  ```
- Work on branch `phase-7-4-full-rekey` (already created, already holds the spec commit).

---

### Task 1: The artifact walk

Enumerating every encrypted file and recovering the exact AAD each was written with is the correctness core of the whole feature. It gets its own task, and it **fails closed**: a file under `documents/` that the walk does not recognize aborts the run rather than being silently left under the dead key.

The AAD builders currently live as module-private functions in `src/documents.ts`. Export them rather than re-declaring the strings in a second file — a drifted copy would produce files that decrypt nowhere.

**Files:**
- Create: `src/keyring-rekey.ts`
- Modify: `src/documents.ts` (export the AAD helpers at lines 344-345 and 350-391)
- Modify: `src/sync/protocol.ts:207` (export `changeEncryptionKey`)
- Test: `test/keyring-rekey.test.mjs`
- Modify: `package.json:34`

**Interfaces:**
- Consumes: `resolveInside` from `src/safety.js`; `normalizeVaultName` from `src/safety.js`; `APPLIED_AAD`, `CHANGE_AAD_PREFIX` from `src/sync/protocol.js`; `LOCAL_TRANSACTION_AAD`, `APPLY_RECEIPT_AAD` from `src/sync/transaction.js`.
- Produces: `RekeyItemKind`, `RekeyItem`, `planRekey(vaultDir: string): RekeyItem[]`. Also the newly exported `noteAad`, `historyAad`, `canvasAad`, `pluginAad`, `pluginStoreAad`, `canvasHistoryAad`, `attachmentManifestAad`, `attachmentChunkAad`, `INDEX_AAD`, `PLUGIN_POLICY_AAD` from `src/documents.js`, and `changeEncryptionKey(key: Buffer, id: string): Buffer` from `src/sync/protocol.js`.

- [ ] **Step 1: Export the AAD helpers from `src/documents.ts`**

Add `export` to these eight functions and two constants, changing nothing else about them:

```ts
export const INDEX_AAD = "secondbrain-vault:document-index:v1";
export const PLUGIN_POLICY_AAD = "secondbrain-vault:plugin-policy:v1";

export function noteAad(id: string): string { … }
export function historyAad(id: string, revision: number): string { … }
export function canvasAad(id: string): string { … }
export function pluginAad(id: string): string { … }
export function pluginStoreAad(id: string): string { … }
export function canvasHistoryAad(id: string, revision: number): string { … }
export function attachmentManifestAad(id: string): string { … }
export function attachmentChunkAad(id: string, index: number): string { … }
```

Add `export` to `changeEncryptionKey` in `src/sync/protocol.ts:207`:

```ts
/**
 * The per-change body key. Exported for the re-key, which must derive the
 * same subkey under the old and the new `syncEnvelope` key for one change ID.
 */
export function changeEncryptionKey(key: Buffer, id: string): Buffer {
  return crypto.createHmac("sha256", key).update(CHANGE_KEY_CONTEXT).update("\0").update(id).digest();
}
```

- [ ] **Step 2: Write the failing test**

Create `test/keyring-rekey.test.mjs`:

```js
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { appendAudit } from "../dist/audit.js";
import { DocumentVault } from "../dist/documents.js";
import { planRekey } from "../dist/keyring-rekey.js";
import { upsertEntry } from "../dist/store.js";
import { saveGrants, emptyGrantFile } from "../dist/grants.js";

const PASSPHRASE = "phase-74-current-passphrase";

function tempDir(label = "rekey") {
  return fs.mkdtempSync(path.join(os.tmpdir(), `vault-brain-${label}-`));
}

/**
 * A keyring-native vault holding a note with history, a canvas, an
 * attachment, a key-value file, a grant file and an audit chain — one of
 * every artifact class the walk has to classify.
 */
function seedVault(passphrase = PASSPHRASE) {
  const dir = tempDir();
  const vault = new DocumentVault(dir, passphrase);
  const note = vault.put({ path: "Atlas/First.md", title: "First", body: "# First\n\nbody" });
  vault.put({ id: note.id, path: "Atlas/First.md", title: "First", body: "# First\n\nsecond revision" });
  const canvas = vault.putCanvas({ path: "Atlas/Board.canvas", title: "Board", nodes: [], edges: [] });
  const attachment = vault.putAttachment(Buffer.from("phase 7.4 attachment"), "note.bin");
  vault.lock();
  upsertEntry(dir, "health", "BLOOD_TYPE", "0 Rh+", "blood group", passphrase);
  saveGrants(dir, emptyGrantFile(), passphrase);
  appendAudit(dir, { actor: "cli-direct-write", file: "health", key: "BLOOD_TYPE" }, passphrase);
  return { dir, noteId: note.id, canvasId: canvas.id, attachmentId: attachment.id };
}

test("the walk classifies every encrypted artifact with the AAD that wrote it", () => {
  const { dir, noteId, canvasId, attachmentId } = seedVault();

  const items = planRekey(dir);
  const byPath = new Map(items.map((item) => [item.path, item]));

  assert.deepEqual(byPath.get("health.kv.enc"), {
    path: "health.kv.enc",
    kind: "kv",
    identity: "health",
  });
  assert.deepEqual(byPath.get("grants.enc"), {
    path: "grants.enc",
    kind: "kv",
    identity: "grants",
  });
  assert.deepEqual(byPath.get("documents/index.enc"), {
    path: "documents/index.enc",
    kind: "document",
    identity: "secondbrain-vault:document-index:v1",
  });
  assert.deepEqual(byPath.get(`documents/objects/${noteId}.note.enc`), {
    path: `documents/objects/${noteId}.note.enc`,
    kind: "document",
    identity: `secondbrain-vault:note:v1:${noteId}`,
  });
  assert.deepEqual(byPath.get(`documents/objects/${canvasId}.canvas.enc`), {
    path: `documents/objects/${canvasId}.canvas.enc`,
    kind: "document",
    identity: `secondbrain-vault:canvas:v1:${canvasId}`,
  });
  assert.deepEqual(byPath.get(`documents/history/${noteId}/1.note.enc`), {
    path: `documents/history/${noteId}/1.note.enc`,
    kind: "document",
    identity: `secondbrain-vault:note-history:v1:${noteId}:1`,
  });
  assert.deepEqual(byPath.get(`documents/attachments/${attachmentId}/manifest.enc`), {
    path: `documents/attachments/${attachmentId}/manifest.enc`,
    kind: "document",
    identity: `secondbrain-vault:attachment-manifest:v1:${attachmentId}`,
  });
  assert.deepEqual(byPath.get(`documents/attachments/${attachmentId}/0.chunk.enc`), {
    path: `documents/attachments/${attachmentId}/0.chunk.enc`,
    kind: "document",
    identity: `secondbrain-vault:attachment-chunk:v1:${attachmentId}:0`,
  });

  fs.rmSync(dir, { recursive: true, force: true });
});

test("plaintext bookkeeping files are not scheduled for re-encryption", () => {
  const { dir } = seedVault();
  const scheduled = new Set(planRekey(dir).map((item) => item.path));

  for (const untouched of ["keyring.json", "audit.log", "documents/manifest.json"]) {
    assert.equal(scheduled.has(untouched), false, `${untouched} must not be re-encrypted`);
  }

  fs.rmSync(dir, { recursive: true, force: true });
});

test("an unrecognized file under documents/ fails the walk closed", () => {
  const { dir } = seedVault();
  fs.writeFileSync(path.join(dir, "documents", "objects", "surprise.enc"), "{}");

  assert.throws(() => planRekey(dir), /cannot classify/iu);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("an unrecognized encrypted file at the vault root fails the walk closed", () => {
  const { dir } = seedVault();
  fs.writeFileSync(path.join(dir, "mystery.enc"), "{}");

  assert.throws(() => planRekey(dir), /cannot classify/iu);

  fs.rmSync(dir, { recursive: true, force: true });
});
```

Add the file to `package.json:34`, appending ` test/keyring-rekey.test.mjs` to the end of the `test` script's file list.

- [ ] **Step 3: Run the test to verify it fails**

Run: `npm test 2>&1 | tail -40`
Expected: FAIL — `Cannot find module '.../dist/keyring-rekey.js'`.

- [ ] **Step 4: Write `src/keyring-rekey.ts`**

```ts
import fs from "node:fs";
import path from "node:path";

import {
  INDEX_AAD,
  PLUGIN_POLICY_AAD,
  attachmentChunkAad,
  attachmentManifestAad,
  canvasAad,
  canvasHistoryAad,
  historyAad,
  noteAad,
  pluginAad,
  pluginStoreAad,
} from "./documents.js";
import { normalizeVaultName, resolveInside } from "./safety.js";
import { APPLIED_AAD } from "./sync/protocol.js";
import { APPLY_RECEIPT_AAD, LOCAL_TRANSACTION_AAD } from "./sync/transaction.js";

export const STAGING_DIRNAME = ".rekey";

export type RekeyItemKind = "document" | "kv" | "sync-change";

export interface RekeyItem {
  /** Path relative to the vault directory, POSIX separators. */
  path: string;
  kind: RekeyItemKind;
  /**
   * What the envelope authenticates, and therefore what must survive the
   * re-key byte for byte. For `document` it is the GCM AAD; for `kv` the
   * logical file identity `encryptWithKey` binds; for `sync-change` the
   * change ID, from which both the body subkey and the AAD derive.
   */
  identity: string;
}

/** Plaintext bookkeeping under `documents/`. Neither is encrypted. */
const DOCUMENT_PLAINTEXT = new Set(["manifest.json", "journal.json"]);

/** Plaintext or separately-managed files at the vault root. */
const ROOT_PLAINTEXT = new Set([
  "keyring.json",
  "audit.log",
  "audit.meta.json",
  "schema.json",
  ".sbrain.lock",
]);

const OBJECT_FILE = /^([a-f0-9-]{36})\.(note|canvas|plugin|pluginstore)\.enc$/u;
const HISTORY_FILE = /^(\d+)\.(note|canvas)\.enc$/u;
const CHUNK_FILE = /^(\d+)\.chunk\.enc$/u;
const CHANGE_FILE = /^([a-f0-9]{64})\.change\.enc$/u;
const DOCUMENT_ID = /^[a-f0-9-]{36}$/u;
const CONTENT_ID = /^[a-f0-9]{64}$/u;

const SYNC_STATE_AAD: Record<string, string> = {
  "applied.enc": APPLIED_AAD,
  "pending-local.enc": LOCAL_TRANSACTION_AAD,
  "apply-receipt.enc": APPLY_RECEIPT_AAD,
};

/**
 * Every AAD is a pure function of the file's own path, which is what makes a
 * re-key possible at all: the identity an envelope authenticates can be
 * recovered without opening it. Anything this cannot classify throws, so a
 * file the walk does not know about aborts the run instead of surviving under
 * a key nothing keeps.
 */
function classifyDocument(relative: string): RekeyItem | null {
  const segments = relative.split("/");
  const item = (kind: RekeyItemKind, identity: string): RekeyItem => ({
    path: `documents/${relative}`,
    kind,
    identity,
  });

  if (segments.length === 1) {
    if (DOCUMENT_PLAINTEXT.has(segments[0])) return null;
    if (segments[0] === "index.enc") return item("document", INDEX_AAD);
    if (segments[0] === "plugin-policy.enc") return item("document", PLUGIN_POLICY_AAD);
  }

  if (segments.length === 2 && segments[0] === "objects") {
    const match = OBJECT_FILE.exec(segments[1]);
    if (match) {
      const [, id, type] = match;
      if (type === "note") return item("document", noteAad(id));
      if (type === "canvas") return item("document", canvasAad(id));
      if (type === "plugin") return item("document", pluginAad(id));
      return item("document", pluginStoreAad(id));
    }
  }

  if (segments.length === 3 && segments[0] === "history" && DOCUMENT_ID.test(segments[1])) {
    const match = HISTORY_FILE.exec(segments[2]);
    if (match) {
      const revision = Number(match[1]);
      return item(
        "document",
        match[2] === "note" ? historyAad(segments[1], revision) : canvasHistoryAad(segments[1], revision),
      );
    }
  }

  if (segments.length === 3 && segments[0] === "attachments" && CONTENT_ID.test(segments[1])) {
    if (segments[2] === "manifest.enc") return item("document", attachmentManifestAad(segments[1]));
    const match = CHUNK_FILE.exec(segments[2]);
    if (match) return item("document", attachmentChunkAad(segments[1], Number(match[1])));
  }

  if (segments.length === 2 && segments[0] === "sync") {
    const aad = SYNC_STATE_AAD[segments[1]];
    if (aad) return item("document", aad);
  }

  if (segments.length === 3 && segments[0] === "sync" && segments[1] === "changes") {
    const match = CHANGE_FILE.exec(segments[2]);
    if (match) return item("sync-change", match[1]);
  }

  throw new Error(`Refusing to re-key: cannot classify documents/${relative}.`);
}

function walkDocuments(rootDir: string, current: string, prefix: string, items: RekeyItem[]): void {
  for (const entry of fs.readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    const full = path.join(current, entry.name);
    if (entry.isDirectory()) {
      walkDocuments(rootDir, full, relative, items);
      continue;
    }
    if (!entry.isFile()) continue;
    const item = classifyDocument(relative);
    if (item) items.push(item);
  }
}

/**
 * Every artifact a re-key must rewrite, in a deterministic order. The vault
 * root is scanned shallowly — only the vault's own encrypted files live there
 * — and `documents/` is walked in full.
 */
export function planRekey(vaultDir: string): RekeyItem[] {
  const items: RekeyItem[] = [];

  for (const entry of fs.readdirSync(vaultDir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    if (entry.isDirectory()) continue;
    if (!entry.isFile()) continue;
    if (ROOT_PLAINTEXT.has(entry.name)) continue;
    if (entry.name.endsWith(".kv.enc")) {
      const base = entry.name.slice(0, -".kv.enc".length);
      items.push({ path: entry.name, kind: "kv", identity: normalizeVaultName(base) });
      continue;
    }
    if (entry.name === "grants.enc") {
      items.push({ path: entry.name, kind: "kv", identity: "grants" });
      continue;
    }
    if (entry.name.endsWith(".enc")) {
      throw new Error(`Refusing to re-key: cannot classify ${entry.name}.`);
    }
  }

  const documentsDir = resolveInside(vaultDir, "documents");
  if (fs.existsSync(documentsDir)) walkDocuments(documentsDir, documentsDir, "", items);

  return items;
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `npm test 2>&1 | tail -20`
Expected: PASS, all four new tests green and no existing test broken.

- [ ] **Step 6: Commit**

```bash
git add src/keyring-rekey.ts src/documents.ts src/sync/protocol.ts test/keyring-rekey.test.mjs package.json
git commit -m "feat: enumerate every artifact a re-key must rewrite

Every AAD in the vault is a pure function of the file's own path, so the
identity an envelope authenticates can be recovered without opening it. That
is what makes a re-key possible: the key changes, the identity does not.

The walk fails closed. A file under documents/ it cannot classify aborts the
run, because the alternative is leaving that file encrypted under a key
nothing keeps.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0117aYpsscAmKUx8LtubpHyi"
```

---

### Task 2: Decrypt and re-encrypt one artifact

Each kind has its own envelope shape and its own serialization. Splitting this into `decryptItem` / `encryptItem` rather than one `reencryptItem` is what lets the staging phase verify by comparing plaintexts.

**Files:**
- Modify: `src/keyring-rekey.ts`
- Test: `test/keyring-rekey.test.mjs`

**Interfaces:**
- Consumes: `planRekey`, `RekeyItem` from Task 1; `KeySet` from `src/keyring.js`; `decryptDocumentBytes`, `encryptDocumentBytes`, `decryptDocument`, `encryptDocument`, `DocumentPayload` from `src/document-crypto.js`; `decryptWithKey`, `encryptWithKey`, `KeyedEncryptedPayload` from `src/crypto.js`; `changeEncryptionKey`, `validateEncryptedSyncChange`, `CHANGE_AAD_PREFIX` from `src/sync/protocol.js`.
- Produces: `decryptItem(item: RekeyItem, keys: KeySet, raw: Buffer): Buffer` and `encryptItem(item: RekeyItem, keys: KeySet, plaintext: Buffer): Buffer`.

- [ ] **Step 1: Write the failing test**

Append to `test/keyring-rekey.test.mjs`:

```js
import { decryptItem, encryptItem } from "../dist/keyring-rekey.js";
import { openVaultKeys, randomKeySet } from "../dist/keyring.js";

test("an artifact re-encrypted under a new keyset carries the same plaintext", () => {
  const { dir } = seedVault();
  const oldKeys = openVaultKeys(dir, PASSPHRASE);
  const newKeys = randomKeySet();
  // The identity keys are pinned, so a re-key never touches them.
  newKeys.attachmentId = Buffer.from(oldKeys.attachmentId);
  newKeys.syncChange = Buffer.from(oldKeys.syncChange);
  newKeys.audit = Buffer.from(oldKeys.audit);

  for (const item of planRekey(dir)) {
    const raw = fs.readFileSync(path.join(dir, ...item.path.split("/")));
    const plaintext = decryptItem(item, oldKeys, raw);
    const rewritten = encryptItem(item, newKeys, plaintext);

    assert.notDeepEqual(rewritten, raw, `${item.path} must not keep its ciphertext`);
    assert.deepEqual(decryptItem(item, newKeys, rewritten), plaintext, `${item.path} must round trip`);
    assert.throws(() => decryptItem(item, oldKeys, rewritten), /.*/u, `${item.path} must not open under the old keyset`);
  }

  fs.rmSync(dir, { recursive: true, force: true });
});

test("a sync change keeps its ID and its envelope shape across a re-encryption", () => {
  const { dir } = seedVault();
  const oldKeys = openVaultKeys(dir, PASSPHRASE);
  const newKeys = randomKeySet();
  newKeys.syncChange = Buffer.from(oldKeys.syncChange);

  const changesDir = path.join(dir, "documents", "sync", "changes");
  if (!fs.existsSync(changesDir)) {
    fs.rmSync(dir, { recursive: true, force: true });
    return;
  }
  for (const item of planRekey(dir).filter((candidate) => candidate.kind === "sync-change")) {
    const raw = fs.readFileSync(path.join(dir, ...item.path.split("/")));
    const rewritten = encryptItem(item, newKeys, decryptItem(item, oldKeys, raw));
    const before = JSON.parse(raw.toString("utf8"));
    const after = JSON.parse(rewritten.toString("utf8"));

    assert.equal(after.id, before.id);
    assert.equal(after.version, 1);
    assert.notEqual(after.payload.ciphertext, before.payload.ciphertext);
  }

  fs.rmSync(dir, { recursive: true, force: true });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test 2>&1 | tail -30`
Expected: FAIL — `decryptItem is not a function`.

- [ ] **Step 3: Implement both functions in `src/keyring-rekey.ts`**

Add these imports and functions:

```ts
import { decryptWithKey, encryptWithKey, type KeyedEncryptedPayload } from "./crypto.js";
import {
  decryptDocument,
  decryptDocumentBytes,
  encryptDocument,
  encryptDocumentBytes,
  type DocumentPayload,
} from "./document-crypto.js";
import type { KeySet } from "./keyring.js";
import {
  CHANGE_AAD_PREFIX,
  changeEncryptionKey,
  validateEncryptedSyncChange,
} from "./sync/protocol.js";
```

```ts
/**
 * The bytes an artifact protects, whatever envelope it wears. The `kv`
 * envelope is UTF-8 text and the other two are byte payloads, so everything
 * is normalized to a Buffer: the staging phase compares plaintexts to prove a
 * re-encryption preserved content, and that comparison must not care which
 * envelope produced it.
 */
export function decryptItem(item: RekeyItem, keys: KeySet, raw: Buffer): Buffer {
  const parsed = JSON.parse(raw.toString("utf8")) as unknown;

  if (item.kind === "document") {
    return decryptDocumentBytes(parsed as DocumentPayload, keys.documents, item.identity);
  }

  if (item.kind === "kv") {
    return Buffer.from(decryptWithKey(parsed as KeyedEncryptedPayload, keys.kv, item.identity), "utf8");
  }

  const envelope = validateEncryptedSyncChange(parsed);
  if (envelope.id !== item.identity) throw new Error(`Sync change filename does not match its envelope: ${item.identity}`);
  const envelopeKey = changeEncryptionKey(keys.syncEnvelope, envelope.id);
  try {
    return Buffer.from(
      decryptDocument(envelope.payload, envelopeKey, `${CHANGE_AAD_PREFIX}${envelope.id}`),
      "utf8",
    );
  } finally {
    envelopeKey.fill(0);
  }
}

/**
 * The inverse, serialized exactly the way the module that owns each artifact
 * writes it: two-space JSON for the key-value envelopes `saveVaultFile` and
 * `saveGrants` produce, compact JSON for everything else. A re-key must not
 * be visible as a formatting change.
 */
export function encryptItem(item: RekeyItem, keys: KeySet, plaintext: Buffer): Buffer {
  if (item.kind === "document") {
    const payload = encryptDocumentBytes(plaintext, keys.documents, item.identity);
    return Buffer.from(JSON.stringify(payload), "utf8");
  }

  if (item.kind === "kv") {
    const payload = encryptWithKey(plaintext.toString("utf8"), keys.kv, item.identity);
    return Buffer.from(JSON.stringify(payload, null, 2), "utf8");
  }

  const envelopeKey = changeEncryptionKey(keys.syncEnvelope, item.identity);
  try {
    const payload = encryptDocument(
      plaintext.toString("utf8"),
      envelopeKey,
      `${CHANGE_AAD_PREFIX}${item.identity}`,
    );
    return Buffer.from(JSON.stringify({ version: 1, id: item.identity, payload }), "utf8");
  } finally {
    envelopeKey.fill(0);
  }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm test 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/keyring-rekey.ts test/keyring-rekey.test.mjs
git commit -m "feat: re-encrypt one artifact under a new keyset

Three envelope shapes, one contract: the key changes and the authenticated
identity does not. Splitting decrypt from encrypt is what lets the staging
phase verify by comparing plaintexts rather than trusting the round trip.

Each artifact is re-serialized the way the module that owns it writes it, so
a re-key is not also a whitespace change.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0117aYpsscAmKUx8LtubpHyi"
```

---

### Task 3: Stage and verify

Everything is written to `<vault>/.rekey/new/` and proved to open under the new keyset before one live byte moves. The staging tree lives inside the vault so the later renames stay on one filesystem.

**Files:**
- Modify: `src/keyring-rekey.ts`
- Test: `test/keyring-rekey.test.mjs`

**Interfaces:**
- Consumes: Tasks 1-2; `writeFileAtomic` from `src/fs-safe.js`; `resolveInside` from `src/safety.js`.
- Produces: `stagingRoot(vaultDir: string): string`, `stagedTree(vaultDir: string): string`, `stageRekey(vaultDir: string, oldKeys: KeySet, newKeys: KeySet, items: RekeyItem[]): void`.

- [ ] **Step 1: Write the failing test**

Append to `test/keyring-rekey.test.mjs`:

```js
import { stageRekey, stagedTree, stagingRoot } from "../dist/keyring-rekey.js";

/** SHA-256 of every file in the vault, keyed by POSIX-relative path. */
function hashVault(dir) {
  const hashes = {};
  const walk = (current, prefix) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) walk(full, relative);
      else if (entry.isFile()) hashes[relative] = crypto.createHash("sha256").update(fs.readFileSync(full)).digest("hex");
    }
  };
  walk(dir, "");
  return hashes;
}

function pinnedKeySet(oldKeys) {
  const keys = randomKeySet();
  keys.attachmentId = Buffer.from(oldKeys.attachmentId);
  keys.syncChange = Buffer.from(oldKeys.syncChange);
  keys.audit = Buffer.from(oldKeys.audit);
  return keys;
}

test("staging writes a full shadow tree and touches nothing live", () => {
  const { dir } = seedVault();
  const oldKeys = openVaultKeys(dir, PASSPHRASE);
  const newKeys = pinnedKeySet(oldKeys);
  const items = planRekey(dir);
  const before = hashVault(dir);

  stageRekey(dir, oldKeys, newKeys, items);

  for (const item of items) {
    const staged = path.join(stagedTree(dir), ...item.path.split("/"));
    assert.ok(fs.existsSync(staged), `${item.path} must be staged`);
    assert.deepEqual(
      decryptItem(item, newKeys, fs.readFileSync(staged)),
      decryptItem(item, oldKeys, fs.readFileSync(path.join(dir, ...item.path.split("/")))),
      `${item.path} must stage the same plaintext`,
    );
  }

  const after = hashVault(dir);
  for (const [relative, hash] of Object.entries(before)) {
    assert.equal(after[relative], hash, `${relative} must not have changed`);
  }

  fs.rmSync(dir, { recursive: true, force: true });
});

test("staging refuses when an artifact does not open under the current keyset", () => {
  const { dir } = seedVault();
  const oldKeys = openVaultKeys(dir, PASSPHRASE);
  const newKeys = pinnedKeySet(oldKeys);
  const items = planRekey(dir);
  const wrongKeys = randomKeySet();
  const before = hashVault(dir);

  assert.throws(() => stageRekey(dir, wrongKeys, newKeys, items), /.*/u);

  const after = hashVault(dir);
  for (const [relative, hash] of Object.entries(before)) {
    assert.equal(after[relative], hash, `${relative} must not have changed`);
  }

  fs.rmSync(dir, { recursive: true, force: true });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test 2>&1 | tail -30`
Expected: FAIL — `stageRekey is not a function`.

- [ ] **Step 3: Implement staging**

Add to `src/keyring-rekey.ts`:

```ts
import { writeFileAtomic } from "./fs-safe.js";

/** `<vault>/.rekey`, holding the journal and the shadow tree. */
export function stagingRoot(vaultDir: string): string {
  return resolveInside(vaultDir, STAGING_DIRNAME);
}

/** `<vault>/.rekey/new`, mirroring the vault's own layout. */
export function stagedTree(vaultDir: string): string {
  return resolveInside(stagingRoot(vaultDir), "new");
}

/**
 * Re-encrypts every item into the shadow tree and proves each staged file
 * opens under the new keyset to the same plaintext the live file holds under
 * the old one. Nothing live is touched, so any failure here — a wrong
 * passphrase, a damaged object, a full disk — leaves the vault byte-identical.
 */
export function stageRekey(vaultDir: string, oldKeys: KeySet, newKeys: KeySet, items: RekeyItem[]): void {
  const tree = stagedTree(vaultDir);
  fs.rmSync(stagingRoot(vaultDir), { recursive: true, force: true });
  fs.mkdirSync(tree, { recursive: true, mode: 0o700 });

  for (const item of items) {
    const live = resolveInside(vaultDir, item.path);
    const staged = resolveInside(tree, item.path);
    let plaintext: Buffer | undefined;
    let verified: Buffer | undefined;
    try {
      plaintext = decryptItem(item, oldKeys, fs.readFileSync(live));
      const rewritten = encryptItem(item, newKeys, plaintext);
      fs.mkdirSync(path.dirname(staged), { recursive: true, mode: 0o700 });
      writeFileAtomic(staged, rewritten, { mode: 0o600 });

      // Read back from disk rather than trusting the buffer: this is what
      // catches a truncated or partially flushed write before the commit.
      verified = decryptItem(item, newKeys, fs.readFileSync(staged));
      if (!verified.equals(plaintext)) {
        throw new Error(`The re-keyed copy of ${item.path} does not carry its plaintext.`);
      }
    } catch (error) {
      fs.rmSync(stagingRoot(vaultDir), { recursive: true, force: true });
      throw error;
    } finally {
      plaintext?.fill(0);
      verified?.fill(0);
    }
  }
}
```

`writeFileAtomic` accepts `string | Buffer` through `fs.writeFileSync`; if its signature is narrower, widen the `data` parameter to `string | Buffer` in `src/fs-safe.ts:36` rather than converting to a string here.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm test 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/keyring-rekey.ts src/fs-safe.ts test/keyring-rekey.test.mjs
git commit -m "feat: stage a re-keyed vault beside the live one

Every object is re-encrypted into .rekey/new and read back from disk under
the new keyset before one live byte moves, so a wrong passphrase, a damaged
object or a full disk leaves the vault byte-identical.

The shadow tree lives inside the vault so the renames that install it later
stay on one filesystem.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0117aYpsscAmKUx8LtubpHyi"
```

---

### Task 4: Journal, commit and recovery

The only genuinely atomic operation available is a single-file replace, so `keyring.json` is the commit point and a journal written before it makes the swap deterministic in both directions.

**Files:**
- Modify: `src/keyring-rekey.ts`
- Test: `test/keyring-rekey.test.mjs`

**Interfaces:**
- Consumes: Tasks 1-3; `readKeyring`, `writeKeyring`, `KeyringFile` from `src/keyring.js`.
- Produces: `RekeyJournal`, `journalPath(vaultDir: string): string`, `commitRekey(vaultDir: string, journal: RekeyJournal, keyring: KeyringFile): void`, `installStaged(vaultDir: string, journal: RekeyJournal): void`, `recoverRekey(vaultDir: string): "none" | "rolled-back" | "finished"`.

- [ ] **Step 1: Write the failing test**

Append to `test/keyring-rekey.test.mjs`:

```js
import { commitRekey, installStaged, journalPath, recoverRekey } from "../dist/keyring-rekey.js";
import { KEYRING_VERSION, forgetVaultKeys, readKeyring, wrapKeySet, writeKeyring } from "../dist/keyring.js";

const NEW_PASSPHRASE = "phase-74-replacement-passphrase";

/** Stage a re-key and return everything the commit needs, without committing. */
function preparedRekey(dir) {
  const oldKeys = openVaultKeys(dir, PASSPHRASE);
  const newKeys = pinnedKeySet(oldKeys);
  const items = planRekey(dir);
  stageRekey(dir, oldKeys, newKeys, items);
  const slot = wrapKeySet(newKeys, NEW_PASSPHRASE);
  return {
    oldKeys,
    newKeys,
    journal: { version: 1, slotId: slot.id, files: items.map((item) => item.path) },
    keyring: { version: KEYRING_VERSION, slots: [slot] },
  };
}

test("a committed re-key installs every staged file and clears the staging tree", () => {
  const { dir } = seedVault();
  const { newKeys, journal, keyring } = preparedRekey(dir);

  commitRekey(dir, journal, keyring);

  assert.equal(fs.existsSync(stagingRoot(dir)), false);
  for (const item of planRekey(dir)) {
    const raw = fs.readFileSync(path.join(dir, ...item.path.split("/")));
    assert.ok(decryptItem(item, newKeys, raw).length >= 0);
  }

  fs.rmSync(dir, { recursive: true, force: true });
});

test("a crash before the new keyring rolls the re-key back", () => {
  const { dir } = seedVault();
  const { journal } = preparedRekey(dir);
  const before = hashVault(dir);
  // Simulate a crash between the journal write and the keyring write.
  fs.writeFileSync(journalPath(dir), `${JSON.stringify(journal)}\n`);

  assert.equal(recoverRekey(dir), "rolled-back");
  assert.equal(fs.existsSync(stagingRoot(dir)), false);

  forgetVaultKeys();
  assert.ok(openVaultKeys(dir, PASSPHRASE), "the old passphrase must still open the vault");
  const after = hashVault(dir);
  for (const [relative, hash] of Object.entries(before)) {
    assert.equal(after[relative], hash, `${relative} must not have changed`);
  }

  fs.rmSync(dir, { recursive: true, force: true });
});

test("a crash partway through the installs is finished by the next run", () => {
  const { dir } = seedVault();
  const { newKeys, journal, keyring } = preparedRekey(dir);

  // Simulate a crash after the keyring write with only the first file installed.
  fs.writeFileSync(journalPath(dir), `${JSON.stringify(journal)}\n`);
  writeKeyring(dir, keyring);
  installStaged(dir, { ...journal, files: journal.files.slice(0, 1) });

  assert.equal(recoverRekey(dir), "finished");
  assert.equal(fs.existsSync(stagingRoot(dir)), false);
  for (const item of planRekey(dir)) {
    const raw = fs.readFileSync(path.join(dir, ...item.path.split("/")));
    assert.ok(decryptItem(item, newKeys, raw).length >= 0, `${item.path} must open under the new keyset`);
  }

  fs.rmSync(dir, { recursive: true, force: true });
});

test("recovery is a no-op on a vault with no journal, and clears an aborted stage", () => {
  const { dir } = seedVault();
  assert.equal(recoverRekey(dir), "none");

  preparedRekey(dir);
  assert.equal(fs.existsSync(stagedTree(dir)), true);
  assert.equal(recoverRekey(dir), "none");
  assert.equal(fs.existsSync(stagingRoot(dir)), false);

  fs.rmSync(dir, { recursive: true, force: true });
});
```

Note: `installStaged` is deliberately called with a truncated file list in the third test. It only installs the files it is given, which is exactly the partial state a crash produces.

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test 2>&1 | tail -30`
Expected: FAIL — `commitRekey is not a function`.

- [ ] **Step 3: Implement the journal, commit and recovery**

Add to `src/keyring-rekey.ts`:

```ts
import { readKeyring, writeKeyring, type KeyringFile } from "./keyring.js";

export interface RekeyJournal {
  version: 1;
  /** The ID of the slot the new keyring carries. */
  slotId: string;
  /** Vault-relative POSIX paths still to install. */
  files: string[];
}

export function journalPath(vaultDir: string): string {
  return resolveInside(stagingRoot(vaultDir), "journal.json");
}

function readJournal(vaultDir: string): RekeyJournal | null {
  const filePath = journalPath(vaultDir);
  if (!fs.existsSync(filePath)) return null;
  const parsed = JSON.parse(fs.readFileSync(filePath, "utf8")) as RekeyJournal;
  if (
    parsed?.version !== 1 ||
    typeof parsed.slotId !== "string" ||
    !/^[0-9a-f-]{36}$/u.test(parsed.slotId) ||
    !Array.isArray(parsed.files) ||
    parsed.files.some((entry) => typeof entry !== "string")
  ) {
    throw new Error("The re-key journal is malformed; refusing to touch the vault.");
  }
  return { version: 1, slotId: parsed.slotId, files: parsed.files };
}

/**
 * Moves the staged tree over the live vault. Every rename is atomic and a
 * file already installed is simply absent from the staging tree, so replaying
 * this from the top of the list is safe — which is what makes recovery after
 * a crash mid-install a plain re-run.
 */
export function installStaged(vaultDir: string, journal: RekeyJournal): void {
  const tree = stagedTree(vaultDir);
  for (const relative of journal.files) {
    const staged = resolveInside(tree, relative);
    if (!fs.existsSync(staged)) continue;
    const live = resolveInside(vaultDir, relative);
    fs.mkdirSync(path.dirname(live), { recursive: true, mode: 0o700 });
    fs.renameSync(staged, live);
  }
}

/**
 * The commit, in the only order that is recoverable in both directions:
 * journal, then the keyring, then the installs. Writing `keyring.json` is a
 * single-file replace and therefore the point of no return; the journal
 * written before it is what lets a later run tell which side of that point a
 * crash landed on.
 */
export function commitRekey(vaultDir: string, journal: RekeyJournal, keyring: KeyringFile): void {
  fs.mkdirSync(stagingRoot(vaultDir), { recursive: true, mode: 0o700 });
  writeFileAtomic(journalPath(vaultDir), `${JSON.stringify(journal)}\n`, { mode: 0o600 });
  writeKeyring(vaultDir, keyring);
  installStaged(vaultDir, journal);
  fs.rmSync(stagingRoot(vaultDir), { recursive: true, force: true });
}

/**
 * Finishes or discards an interrupted re-key. The journal names the slot the
 * new keyring carries, so its presence in `keyring.json` is what says whether
 * the commit point was passed.
 */
export function recoverRekey(vaultDir: string): "none" | "rolled-back" | "finished" {
  const journal = readJournal(vaultDir);
  if (!journal) {
    // A staging tree with no journal is an abandoned stage: nothing live was
    // ever touched, so it is safe to drop.
    fs.rmSync(stagingRoot(vaultDir), { recursive: true, force: true });
    return "none";
  }

  const committed = readKeyring(vaultDir)?.slots.some((slot) => slot.id === journal.slotId) ?? false;
  if (!committed) {
    fs.rmSync(stagingRoot(vaultDir), { recursive: true, force: true });
    return "rolled-back";
  }

  installStaged(vaultDir, journal);
  fs.rmSync(stagingRoot(vaultDir), { recursive: true, force: true });
  return "finished";
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm test 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/keyring-rekey.ts test/keyring-rekey.test.mjs
git commit -m "feat: commit a re-key through a journal

The only atomic operation available is a single-file replace, so keyring.json
is the commit point. A journal written before it names the slot the new
keyring carries, which is how a later run tells whether a crash landed before
or after that point: absent, roll back; present, finish the installs.

Every rename is atomic and an installed file is simply gone from the staging
tree, so replaying the install list is a no-op.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0117aYpsscAmKUx8LtubpHyi"
```

---

### Task 5: `rekeyVault`

The orchestration: recovery, format check, keyset construction with the three pinned keys, staging, the new slot, the commit, and the report.

**Files:**
- Modify: `src/keyring-rekey.ts`
- Test: `test/keyring-rekey.test.mjs`

**Interfaces:**
- Consumes: Tasks 1-4; `withVaultLock` from `src/vault-lock.js`; `detectVaultFormat`, `randomKeySet`, `wrapKeySet`, `unwrapSlot`, `forgetVaultKeys`, `openVaultKeys`, `zeroKeySet`, `KEYRING_VERSION`, `KEY_NAMES`, `KeyName` from `src/keyring.js`; `MIN_PASSPHRASE_LENGTH` from `src/keyring-passphrase.js`.
- Produces: `PINNED_KEYS`, `ROTATED_KEYS`, `RekeyReport`, `rekeyVault(vaultDir: string, currentPassphrase: string, newPassphrase: string, options?: { keepPassphrase?: boolean }): RekeyReport`.

- [ ] **Step 1: Write the failing test**

Append to `test/keyring-rekey.test.mjs`:

```js
import { rekeyVault } from "../dist/keyring-rekey.js";
import { verifyAudit } from "../dist/audit.js";
import { loadVaultFile } from "../dist/store.js";
import { DEFAULT_SCRYPT_N } from "../dist/keyring.js";

test("a re-key rewrites every ciphertext and keeps every plaintext", () => {
  const { dir, noteId, attachmentId } = seedVault();
  const before = hashVault(dir);

  const report = rekeyVault(dir, PASSPHRASE, NEW_PASSPHRASE);

  assert.deepEqual(report.rotated, ["documents", "kv", "syncEnvelope"]);
  assert.deepEqual(
    report.pinned.map((entry) => entry.name),
    ["attachmentId", "syncChange", "audit"],
  );
  assert.equal(report.passphraseChanged, true);
  assert.equal(report.resumed, false);

  const after = hashVault(dir);
  for (const item of planRekey(dir)) {
    assert.notEqual(after[item.path], before[item.path], `${item.path} must have been re-encrypted`);
  }
  // Nothing moved: the same set of paths, before and after.
  assert.deepEqual(Object.keys(after).sort(), Object.keys(before).sort());

  forgetVaultKeys();
  const vault = new DocumentVault(dir, NEW_PASSPHRASE);
  assert.match(vault.get(noteId).body, /second revision/u);
  assert.equal(vault.getAttachment(attachmentId).data.toString("utf8"), "phase 7.4 attachment");
  vault.lock();

  assert.equal(loadVaultFile(dir, "health", NEW_PASSPHRASE)[0].value, "0 Rh+");
  assert.equal(verifyAudit(dir, NEW_PASSPHRASE).valid, true);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("the old passphrase no longer opens a re-keyed vault", () => {
  const { dir } = seedVault();
  rekeyVault(dir, PASSPHRASE, NEW_PASSPHRASE);

  forgetVaultKeys();
  assert.ok(openVaultKeys(dir, NEW_PASSPHRASE));
  assert.throws(() => openVaultKeys(dir, PASSPHRASE), /wrong passphrase/iu);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("attachment identities, sync change IDs and the audit chain survive a re-key", () => {
  const { dir, attachmentId } = seedVault();
  const changesDir = path.join(dir, "documents", "sync", "changes");
  const changesBefore = fs.existsSync(changesDir) ? fs.readdirSync(changesDir).sort() : [];

  rekeyVault(dir, PASSPHRASE, NEW_PASSPHRASE);

  forgetVaultKeys();
  const vault = new DocumentVault(dir, NEW_PASSPHRASE);
  // getAttachment recomputes the content address; an unchanged ID proves the
  // attachmentId key was pinned.
  assert.equal(vault.getAttachment(attachmentId).info.id, attachmentId);
  vault.lock();

  const changesAfter = fs.existsSync(changesDir) ? fs.readdirSync(changesDir).sort() : [];
  assert.deepEqual(changesAfter, changesBefore);
  assert.equal(verifyAudit(dir, NEW_PASSPHRASE).valid, true);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("a re-key writes one fresh slot at the current cost and drops slots it cannot open", () => {
  const { dir } = seedVault();
  const stranger = wrapKeySet(randomKeySet(), "an-unrelated-recovery-passphrase");
  const existing = readKeyring(dir);
  writeKeyring(dir, { version: KEYRING_VERSION, slots: [...existing.slots, stranger] });
  forgetVaultKeys();

  const report = rekeyVault(dir, PASSPHRASE, NEW_PASSPHRASE);

  assert.deepEqual(
    report.droppedSlots.map((slot) => slot.id),
    [stranger.id],
  );
  const slots = readKeyring(dir).slots;
  assert.equal(slots.length, 1);
  assert.equal(slots[0].kdf.N, DEFAULT_SCRYPT_N);
  assert.equal(slots[0].label, "primary");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("--keep-passphrase rotates the keyset under the same passphrase", () => {
  const { dir } = seedVault();
  const before = hashVault(dir);

  const report = rekeyVault(dir, PASSPHRASE, "", { keepPassphrase: true });

  assert.equal(report.passphraseChanged, false);
  forgetVaultKeys();
  assert.ok(openVaultKeys(dir, PASSPHRASE));
  for (const item of planRekey(dir)) {
    assert.notEqual(hashVault(dir)[item.path], before[item.path]);
  }

  fs.rmSync(dir, { recursive: true, force: true });
});

test("every refusal leaves the vault byte-identical and no staging behind", () => {
  const { dir } = seedVault();
  const before = hashVault(dir);

  assert.throws(() => rekeyVault(dir, "the-wrong-passphrase", NEW_PASSPHRASE), /wrong passphrase|damaged/iu);
  assert.throws(() => rekeyVault(dir, PASSPHRASE, "short"), /at least 12 characters/u);

  assert.equal(fs.existsSync(stagingRoot(dir)), false);
  assert.deepEqual(hashVault(dir), before);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("a legacy vault is refused and told to migrate", () => {
  const dir = tempDir("legacy");
  fs.writeFileSync(path.join(dir, "schema.json"), '{"version":1,"files":{}}\n');

  assert.throws(() => rekeyVault(dir, PASSPHRASE, NEW_PASSPHRASE), /vbrain migrate/u);
  assert.equal(fs.existsSync(path.join(dir, "keyring.json")), false);

  fs.rmSync(dir, { recursive: true, force: true });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test 2>&1 | tail -30`
Expected: FAIL — `rekeyVault is not a function`.

- [ ] **Step 3: Implement `rekeyVault`**

Add to `src/keyring-rekey.ts`:

```ts
import {
  DEFAULT_SCRYPT_N,
  KEYRING_VERSION,
  detectVaultFormat,
  forgetVaultKeys,
  openVaultKeys,
  randomKeySet,
  unwrapSlot,
  wrapKeySet,
  zeroKeySet,
  type KeyName,
  type KeyringSlot,
} from "./keyring.js";
import { MIN_PASSPHRASE_LENGTH } from "./keyring-passphrase.js";
import { withVaultLock } from "./vault-lock.js";

/** The three keys that protect content, and therefore rotate. */
export const ROTATED_KEYS: KeyName[] = ["documents", "kv", "syncEnvelope"];

/**
 * The three keys carried across unchanged, with the reason each one is not a
 * rotation but a migration. `vbrain rekey` prints these, because a user whose
 * passphrase leaked deserves to know exactly what a re-key did not do.
 */
export const PINNED_KEYS: { name: KeyName; reason: string }[] = [
  {
    name: "attachmentId",
    reason: "attachment content addresses name directories, AADs, canvas nodes and sync objects",
  },
  { name: "syncChange", reason: "change IDs are referenced as parents by every descendant change" },
  { name: "audit", reason: "the audit chain carries no key epoch, so rotating it invalidates it" },
];

export interface DroppedSlot {
  id: string;
  label: string;
  createdAt: string;
}

export interface RekeyReport {
  rotated: KeyName[];
  pinned: { name: KeyName; reason: string }[];
  reencrypted: { documents: number; kv: number; syncChanges: number; total: number };
  droppedSlots: DroppedSlot[];
  passphraseChanged: boolean;
  resumed: boolean;
}

function emptyReport(overrides: Partial<RekeyReport>): RekeyReport {
  return {
    rotated: [...ROTATED_KEYS],
    pinned: PINNED_KEYS.map((entry) => ({ ...entry })),
    reencrypted: { documents: 0, kv: 0, syncChanges: 0, total: 0 },
    droppedSlots: [],
    passphraseChanged: false,
    resumed: false,
    ...overrides,
  };
}

/**
 * A new keyset and every object re-encrypted under it. Unlike
 * `changeVaultPassphrase`, which re-wraps the same keyset and touches no
 * content, this is the answer to a leaked passphrase: afterwards no byte on
 * disk opens under the old passphrase or the old keys.
 *
 * `attachmentId`, `syncChange` and `audit` are pinned. They derive identities
 * and signatures rather than protecting content, and rotating any of them is
 * an identity migration that cascades into canvas objects, index references,
 * the causal DAG and every peer device.
 */
export function rekeyVault(
  vaultDir: string,
  currentPassphrase: string,
  newPassphrase: string,
  options: { keepPassphrase?: boolean } = {},
): RekeyReport {
  if (!currentPassphrase) throw new Error("A non-empty vault passphrase is required.");
  const keepPassphrase = Boolean(options.keepPassphrase);
  if (!keepPassphrase && newPassphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(`The new passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters.`);
  }
  const wrapPassphrase = keepPassphrase ? currentPassphrase : newPassphrase;

  return withVaultLock(vaultDir, () => {
    // An interrupted earlier run is finished or discarded before anything
    // else looks at the vault, so the rest of this function only ever sees a
    // consistent one.
    if (recoverRekey(vaultDir) === "finished") {
      return emptyReport({ resumed: true, passphraseChanged: false });
    }

    if (detectVaultFormat(vaultDir) !== "keyring") {
      throw new Error("This vault is not in the keyring format yet. Run 'vbrain migrate' first.");
    }
    const file = readKeyring(vaultDir);
    if (!file) throw new Error("This vault has no keyring to re-key.");

    let oldKeys: KeySet | undefined;
    let newKeys: KeySet | undefined;
    const droppedSlots: DroppedSlot[] = [];

    try {
      for (const slot of file.slots) {
        let opened: KeySet;
        try {
          opened = unwrapSlot(slot, currentPassphrase);
        } catch {
          // Wrapped around the keyset this run supersedes, so it is dropped
          // rather than preserved — the deliberate opposite of a passphrase
          // change, which keeps a recovery slot alive.
          droppedSlots.push({ id: slot.id, label: slot.label, createdAt: slot.createdAt });
          continue;
        }
        if (oldKeys) zeroKeySet(opened);
        else oldKeys = opened;
      }
      if (!oldKeys) {
        throw new Error("Unable to unlock this vault: wrong passphrase, or the keyring is damaged.");
      }

      newKeys = randomKeySet();
      for (const { name } of PINNED_KEYS) {
        newKeys[name].fill(0);
        newKeys[name] = Buffer.from(oldKeys[name]);
      }

      const items = planRekey(vaultDir);
      stageRekey(vaultDir, oldKeys, newKeys, items);

      const slot: KeyringSlot = wrapKeySet(newKeys, wrapPassphrase, DEFAULT_SCRYPT_N);
      commitRekey(
        vaultDir,
        { version: 1, slotId: slot.id, files: items.map((item) => item.path) },
        { version: KEYRING_VERSION, slots: [slot] },
      );
      forgetVaultKeys(vaultDir);

      // Prove the vault on disk opens under the passphrase the user was just
      // given before reporting success.
      const written = openVaultKeys(vaultDir, wrapPassphrase);
      if (!written) throw new Error("The re-keyed vault could not be reopened.");
      zeroKeySet(written);

      return {
        rotated: [...ROTATED_KEYS],
        pinned: PINNED_KEYS.map((entry) => ({ ...entry })),
        reencrypted: {
          documents: items.filter((item) => item.kind === "document").length,
          kv: items.filter((item) => item.kind === "kv").length,
          syncChanges: items.filter((item) => item.kind === "sync-change").length,
          total: items.length,
        },
        droppedSlots,
        passphraseChanged: !keepPassphrase,
        resumed: false,
      };
    } catch (error) {
      fs.rmSync(stagingRoot(vaultDir), { recursive: true, force: true });
      throw error;
    } finally {
      if (oldKeys) zeroKeySet(oldKeys);
      if (newKeys) zeroKeySet(newKeys);
    }
  });
}
```

Add `import type { KeySet } from "./keyring.js";` to the existing keyring import if it is not already there.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm test 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Run lint and typecheck**

Run: `npm run lint && npm run typecheck`
Expected: both clean.

- [ ] **Step 6: Commit**

```bash
git add src/keyring-rekey.ts test/keyring-rekey.test.mjs
git commit -m "feat: rotate the vault keyset and re-encrypt every object

A passphrase change re-wraps the keyset; this replaces it. Afterwards no byte
on disk opens under the old passphrase or the old keys, which is the only
thing that helps once a passphrase has leaked.

attachmentId, syncChange and audit are pinned. They derive identities and
signatures rather than protecting content, and rotating any of them cascades
into canvas objects, index references, the causal DAG and every peer.

Slots this passphrase cannot open are dropped, not preserved: they wrap the
keyset this run supersedes.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0117aYpsscAmKUx8LtubpHyi"
```

---

### Task 6: The `vbrain rekey` command

**Files:**
- Modify: `src/cli.ts` (add the command after the `passphrase` group at `1232-1292`; amend the closing lines at `1279-1280`)
- Modify: `test/keyring-passphrase.test.mjs:452` (the assertion on the "once it ships" wording)
- Test: `test/keyring-rekey.test.mjs`

**Interfaces:**
- Consumes: `rekeyVault`, `RekeyReport` from `src/keyring-rekey.js`; the existing `readSecret`, `readNewPassphrase`, `updateRememberedPassphrase` in `src/cli.ts`.
- Produces: the `rekey` command.

- [ ] **Step 1: Write the failing test**

Append to `test/keyring-rekey.test.mjs`:

```js
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const cliPath = fileURLToPath(new URL("../dist/cli.js", import.meta.url));

function runCli(args, env) {
  return spawnSync(process.execPath, [cliPath, ...args], {
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
}

test("the CLI re-keys a vault end to end", () => {
  const { dir, noteId } = seedVault();

  const result = runCli(["--vault", dir, "rekey"], {
    VBRAIN_PASSPHRASE: PASSPHRASE,
    VBRAIN_NEW_PASSPHRASE: NEW_PASSPHRASE,
  });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Re-keyed/u);
  assert.match(result.stdout, /Attachment identities, sync change IDs and the audit chain are unchanged/u);
  assert.match(result.stdout, /confirm a guessed file/u);

  forgetVaultKeys();
  assert.ok(openVaultKeys(dir, NEW_PASSPHRASE));
  assert.throws(() => openVaultKeys(dir, PASSPHRASE), /wrong passphrase/iu);
  const vault = new DocumentVault(dir, NEW_PASSPHRASE);
  assert.match(vault.get(noteId).body, /second revision/u);
  vault.lock();

  fs.rmSync(dir, { recursive: true, force: true });
});

test("the CLI refuses a short new passphrase and leaves the vault alone", () => {
  const { dir } = seedVault();
  const before = hashVault(dir);

  const result = runCli(["--vault", dir, "rekey"], {
    VBRAIN_PASSPHRASE: PASSPHRASE,
    VBRAIN_NEW_PASSPHRASE: "short",
  });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /at least 12 characters/u);
  assert.deepEqual(hashVault(dir), before);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("the CLI never takes the current passphrase from the credential store", () => {
  const { dir } = seedVault();

  const result = runCli(["--vault", dir, "rekey"], {
    VBRAIN_PASSPHRASE: "",
    VBRAIN_NEW_PASSPHRASE: NEW_PASSPHRASE,
  });

  assert.notEqual(result.status, 0);
  assert.equal(fs.existsSync(stagingRoot(dir)), false);

  fs.rmSync(dir, { recursive: true, force: true });
});
```

Also update the stale assertion in `test/keyring-passphrase.test.mjs:452`, replacing:

```js
  assert.match(result.stdout, /vbrain rekey/u);
```

with:

```js
  assert.match(result.stdout, /If the old passphrase leaked, run 'vbrain rekey'/u);
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test 2>&1 | tail -30`
Expected: FAIL — `error: unknown command 'rekey'`.

- [ ] **Step 3: Add the command to `src/cli.ts`**

Add to the imports near line 26:

```ts
import { rekeyVault } from "./keyring-rekey.js";
```

Change the last line of the `passphrase change` action (`src/cli.ts:1280`) from:

```ts
    console.log("If the old passphrase leaked, run 'vbrain rekey' once it ships.");
```

to:

```ts
    console.log("If the old passphrase leaked, run 'vbrain rekey' instead: it replaces the keys as well.");
```

Insert the new command after `readNewPassphrase` (`src/cli.ts:1292`):

```ts
program
  .command("rekey")
  .description("replace the vault keyset and re-encrypt every object under it")
  .option("--keep-passphrase", "rotate the keys but keep wrapping them under the current passphrase")
  .action(async (opts) => {
    const dir = program.opts().vault;
    const keepPassphrase = Boolean(opts.keepPassphrase);
    // Never taken from the OS credential store, for the same reason
    // `passphrase change` does not: a stale or attacker-primed credential
    // must not be able to authorize a re-key on its own.
    const current = process.env.VBRAIN_PASSPHRASE ?? (await readSecret("Current vault passphrase: "));
    if (!current) {
      console.error("A passphrase is required.");
      process.exit(1);
    }
    const next = keepPassphrase
      ? ""
      : (process.env.VBRAIN_NEW_PASSPHRASE ?? (await readNewPassphrase()));

    const report = rekeyVault(dir, current, next, { keepPassphrase });

    if (report.resumed) {
      console.log(`Finished an interrupted re-key of ${dir}.`);
      return;
    }

    console.log(`Re-keyed ${dir}.`);
    console.log(
      `Rotated ${report.rotated.join(", ")} and re-encrypted ${report.reencrypted.total} file(s): ` +
        `${report.reencrypted.documents} document object(s), ${report.reencrypted.kv} key-value file(s), ` +
        `${report.reencrypted.syncChanges} sync change(s).`,
    );
    if (report.droppedSlots.length > 0) {
      console.log(`Dropped ${report.droppedSlots.length} slot(s) this passphrase does not open:`);
      for (const slot of report.droppedSlots) {
        console.log(`  ${slot.id} (${slot.label}), created ${slot.createdAt}.`);
      }
    }

    if (report.passphraseChanged) {
      const keychainResult = updateRememberedPassphrase(dir, next);
      if (keychainResult.updated) {
        console.log(`Updated the remembered passphrase in the OS credential store (${keychainResult.backend}).`);
      } else if (keychainResult.error) {
        const credentialState = keychainResult.cleared
          ? "The remembered credential was removed. Run 'vbrain unlock --remember' to store the new passphrase."
          : "The remembered credential could not be removed either. Run 'vbrain lock' to clear it.";
        console.error(
          `Warning: the vault was re-keyed, but the OS credential store (${keychainResult.backend}) could not be updated (${keychainResult.error}). ` +
            credentialState,
        );
      }
    }

    console.log("Attachment identities, sync change IDs and the audit chain are unchanged by design:");
    for (const pinned of report.pinned) {
      console.log(`  ${pinned.name} is pinned because ${pinned.reason}.`);
    }
    console.log(
      "Someone who kept the old keyset can still confirm a guessed file is in this vault, though they cannot read it.",
    );
  });
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm test 2>&1 | tail -20`
Expected: PASS, including the amended `keyring-passphrase` assertion.

- [ ] **Step 5: Run lint, format and typecheck**

Run: `npm run lint && npm run format:check && npm run typecheck`
Expected: all clean.

- [ ] **Step 6: Commit**

```bash
git add src/cli.ts test/keyring-rekey.test.mjs test/keyring-passphrase.test.mjs
git commit -m "feat: add the vbrain rekey command

A new passphrase is required by default: re-keying while leaving the keyset
wrapped under the leaked passphrase protects a stale copy of keyring.json and
nothing else. --keep-passphrase covers the case where the keyset, not the
passphrase, is what is suspect.

The closing note says what the re-key did not do, and names the confirmation
oracle the pinned identity keys leave behind, because a user whose passphrase
leaked should not have to read the source to learn it.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0117aYpsscAmKUx8LtubpHyi"
```

---

### Task 7: Documentation

**Files:**
- Modify: `README.md:169-193`
- Modify: `docs/ARCHITECTURE.md:121-134`
- Modify: `SECURITY.md`
- Modify: `docs/ROADMAP.md:91`
- Modify: `CHANGELOG.md:6`

- [ ] **Step 1: `README.md`**

Add `rekey` to the command block near line 169, beside `migrate` and `passphrase change`:

```
vbrain --vault ./vault rekey
```

In the prose block at 180-193, after the `vbrain passphrase change` bullet, add:

```markdown
- `vbrain rekey` replaces the vault's keys and re-encrypts every object under
  them. Use it when a passphrase has leaked: a passphrase change re-wraps the
  same keys, so the leaked passphrase would still open a copy of
  `keyring.json` taken before the change. It asks for a new passphrase, and
  `--keep-passphrase` skips that when the keys, not the passphrase, are what
  is suspect. Attachment identities, sync change IDs and the audit chain are
  deliberately unchanged, so attachments keep their content addresses, peers
  keep converging and `vbrain audit verify` keeps validating the whole chain.
```

- [ ] **Step 2: `docs/ARCHITECTURE.md`**

Replace the sentence at 132-134 that says key rotation re-wraps data keys instead of rewriting every object. It is now only half true, and the half it omits is the interesting one:

```markdown
Changing the passphrase re-wraps the keyset and rewrites no object. Re-keying
(`vbrain rekey`) replaces the keyset and rewrites every object, which is what
a leaked passphrase requires.

Three of the six keys rotate: `documents`, `kv` and `syncEnvelope`. They
protect content, and every envelope they cover binds an AAD that is a pure
function of the artifact's own path, so a re-key can reproduce each identity
byte for byte while changing the key underneath it.

Three do not. `attachmentId` and `syncChange` derive identities rather than
protecting content — a content address that names a directory, an AAD, a
canvas node and a sync object; a change ID that every descendant lists as a
parent — so rotating either is an identity migration that diverges from any
peer that has not run it. `audit` signs a chain the format gives no key epoch,
so rotating it would invalidate every entry written before the rotation.

Pinning the two identity keys leaves a confirmation oracle: someone holding
the old keyset can compute a candidate file's content address and check
whether a directory of that name exists, learning that the vault holds that
exact file without decrypting anything. Closing it is an identity migration
and has not been done.
```

- [ ] **Step 3: `SECURITY.md`**

Add to the limitations section:

```markdown
- A re-key does not retract what a leaked passphrase already exposed. An
  attacker who held the passphrase and a copy of the vault has already read
  what that copy contained. `vbrain rekey` is forward-looking: afterwards no
  byte on disk opens under the old passphrase or the old keys.
- A re-key pins the two keys that derive identities, `attachmentId` and
  `syncChange`. Someone who kept the old keyset can therefore still confirm
  that a guessed file or a guessed sync change is present, from directory
  names alone, without decrypting anything. They cannot read its contents.
```

- [ ] **Step 4: `docs/ROADMAP.md`**

Check line 91 and add the follow-on item beneath it:

```markdown
- [x] Full re-key after a compromised passphrase
  - [ ] Attachment identity migration, closing the confirmation oracle a
        re-key leaves behind. Rotating `attachmentId` renames every attachment
        directory and rewrites every canvas object, canvas history revision
        and index reference that names one, and every peer must run it at the
        same time or their attachment IDs diverge.
```

- [ ] **Step 5: `CHANGELOG.md`**

Add under `## Unreleased`:

```markdown
- `vbrain rekey`: a new vault keyset with every object re-encrypted under it,
  for when a passphrase has leaked and re-wrapping the same keys is not
  enough. Staged beside the live vault, verified, then committed through a
  journal, so an interrupted run either rolls back or is finished by the next
  one. `documents`, `kv` and `syncEnvelope` rotate; `attachmentId`,
  `syncChange` and `audit` are pinned, so attachment identities, sync change
  IDs and the audit chain survive.
```

- [ ] **Step 6: Run the full quality gate**

Run: `npm run quality`
Expected: lint, format, typecheck, tests, desktop tests and desktop build all clean.

- [ ] **Step 7: Commit**

```bash
git add README.md docs/ARCHITECTURE.md SECURITY.md docs/ROADMAP.md CHANGELOG.md
git commit -m "docs: document the re-key and what it leaves behind

ARCHITECTURE said key rotation re-wraps data keys instead of rewriting every
object. That is now only half the story, and the half it omitted — which keys
cannot rotate, and why — is the half a reader needs.

SECURITY gets the two honest limits: a re-key does not retract what a leaked
passphrase already exposed, and the pinned identity keys leave a confirmation
oracle over guessed content.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0117aYpsscAmKUx8LtubpHyi"
```
