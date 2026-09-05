import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { appendAudit, verifyAudit } from "../dist/audit.js";
import { DocumentVault } from "../dist/documents.js";
import {
  commitRekey,
  decryptItem,
  encryptItem,
  installStaged,
  journalPath,
  planRekey,
  recoverRekey,
  rekeyVault,
  STAGING_DIRNAME,
  stageRekey,
  stagedTree,
  stagingRoot,
} from "../dist/keyring-rekey.js";
import {
  DEFAULT_SCRYPT_N,
  KEYRING_VERSION,
  forgetVaultKeys,
  openVaultKeys,
  randomKeySet,
  readKeyring,
  wrapKeySet,
  writeKeyring,
} from "../dist/keyring.js";
import { loadVaultFile, upsertEntry } from "../dist/store.js";
import { saveGrants, emptyGrantFile } from "../dist/grants.js";
import { SyncChangeLog } from "../dist/sync.js";

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

// Finding 1 (critical): normalizeVaultName must not run a second time on a
// filename base that saveVaultFile already normalized. A key-value file
// whose real identity ends in ".kv" is the case that exposes a double strip.
test("a kv identity that itself ends in .kv is not stripped twice", () => {
  const dir = tempDir();
  upsertEntry(dir, "backup.kv.kv", "SOME_KEY", "some value", "a note", PASSPHRASE);

  const items = planRekey(dir);
  const backup = items.find((item) => item.path === "backup.kv.kv.enc");

  assert.ok(backup, "backup.kv.kv.enc should have been scheduled");
  assert.equal(backup.kind, "kv");
  assert.equal(backup.identity, "backup.kv", "the identity is the normalized filename base, stripped once");

  fs.rmSync(dir, { recursive: true, force: true });
});

// Finding 3 (important): a leftover atomic-write temp file must be treated
// like every other reader in this codebase treats it — as a crash artifact
// no one consults, not as data to classify.
test("a leftover atomic-write temp file under documents/ is skipped, not scheduled", () => {
  const { dir } = seedVault();
  const changesDir = path.join(dir, "documents", "sync", "changes");
  fs.mkdirSync(changesDir, { recursive: true });
  const leftover = path.join(changesDir, ".something.123.11111111-1111-4111-8111-111111111111.tmp");
  fs.writeFileSync(leftover, "partial write");

  const items = planRekey(dir);

  assert.equal(
    items.some((item) => item.path.endsWith(".tmp")),
    false,
    "a .tmp leftover must never be scheduled for re-encryption",
  );

  fs.rmSync(dir, { recursive: true, force: true });
});

test("a leftover atomic-write temp file at the vault root is skipped, not scheduled", () => {
  const { dir } = seedVault();
  fs.writeFileSync(path.join(dir, ".health.kv.enc.999.22222222-2222-4222-8222-222222222222.tmp"), "partial write");

  const items = planRekey(dir);

  assert.equal(
    items.some((item) => item.path.endsWith(".tmp")),
    false,
    "a .tmp leftover at the vault root must never be scheduled for re-encryption",
  );

  fs.rmSync(dir, { recursive: true, force: true });
});

// Finding 4 (important): every classifier branch, exercised by the real
// writer that produces it where practical. The sync-change branch matters
// most — it is the only place `kind: "sync-change"` is reachable at all, and
// its identity feeds a key derivation in a later task.
test("plugin, plugin storage, plugin policy and canvas history all classify with the AAD that wrote them", () => {
  const dir = tempDir();
  const vault = new DocumentVault(dir, PASSPHRASE);

  const plugin = vault.installPlugin({
    manifest: {
      manifestVersion: 1,
      id: "word-count",
      name: "Word count",
      version: "1.0.0",
      description: "Counts words in the open note",
      author: "someone",
      capabilities: ["notes:read"],
    },
    source: "vbrain.ui.panel('Words', '12');",
  });
  vault.setPluginStorage(plugin.id, { lastCount: "12" });
  vault.setPluginRestrictedMode(true);

  const canvas = vault.putCanvas({ path: "Atlas/Board.canvas", title: "Board", nodes: [], edges: [] });
  vault.putCanvas({
    id: canvas.id,
    path: "Atlas/Board.canvas",
    title: "Board",
    nodes: [{ id: "n1", type: "text", x: 0, y: 0, width: 100, height: 50, text: "note" }],
    edges: [],
  });

  vault.lock();

  const items = planRekey(dir);
  const byPath = new Map(items.map((item) => [item.path, item]));

  assert.deepEqual(byPath.get(`documents/objects/${plugin.id}.plugin.enc`), {
    path: `documents/objects/${plugin.id}.plugin.enc`,
    kind: "document",
    identity: `secondbrain-vault:plugin:v1:${plugin.id}`,
  });
  assert.deepEqual(byPath.get(`documents/objects/${plugin.id}.pluginstore.enc`), {
    path: `documents/objects/${plugin.id}.pluginstore.enc`,
    kind: "document",
    identity: `secondbrain-vault:plugin-store:v1:${plugin.id}`,
  });
  assert.deepEqual(byPath.get("documents/plugin-policy.enc"), {
    path: "documents/plugin-policy.enc",
    kind: "document",
    identity: "secondbrain-vault:plugin-policy:v1",
  });
  assert.deepEqual(byPath.get(`documents/history/${canvas.id}/1.canvas.enc`), {
    path: `documents/history/${canvas.id}/1.canvas.enc`,
    kind: "document",
    identity: `secondbrain-vault:canvas-history:v1:${canvas.id}:1`,
  });

  fs.rmSync(dir, { recursive: true, force: true });
});

test("sync state files and a sync change all classify with the AAD or ID that wrote them", () => {
  const dir = tempDir();
  const log = new SyncChangeLog(dir, PASSPHRASE);
  const deviceId = "33333333-3333-4333-8333-333333333333";
  const change = log.append(deviceId, {
    objectType: "note",
    objectId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    operation: "put",
    baseRevision: null,
    revision: 1,
    value: { title: "Plan", body: "private body" },
  });
  log.markApplied(change);
  log.close();

  // pending-local.enc and apply-receipt.enc are written by
  // SyncLocalTransaction / SyncApplyReceiptStore, whose multi-phase APIs are
  // impractical to drive here — planted directly per the brief's fallback.
  fs.writeFileSync(path.join(dir, "documents", "sync", "pending-local.enc"), "{}");
  fs.writeFileSync(path.join(dir, "documents", "sync", "apply-receipt.enc"), "{}");

  const items = planRekey(dir);
  const byPath = new Map(items.map((item) => [item.path, item]));

  assert.deepEqual(byPath.get(`documents/sync/changes/${change.id}.change.enc`), {
    path: `documents/sync/changes/${change.id}.change.enc`,
    kind: "sync-change",
    identity: change.id,
  });
  assert.deepEqual(byPath.get("documents/sync/applied.enc"), {
    path: "documents/sync/applied.enc",
    kind: "document",
    identity: "secondbrain-vault:sync-applied:v1",
  });
  assert.deepEqual(byPath.get("documents/sync/pending-local.enc"), {
    path: "documents/sync/pending-local.enc",
    kind: "document",
    identity: "secondbrain-vault:sync-local-transaction:v1",
  });
  assert.deepEqual(byPath.get("documents/sync/apply-receipt.enc"), {
    path: "documents/sync/apply-receipt.enc",
    kind: "document",
    identity: "secondbrain-vault:sync-apply-receipt:v1",
  });

  fs.rmSync(dir, { recursive: true, force: true });
});

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
    // Minor finding: any thrown error used to satisfy this assertion,
    // including a TypeError from a broken cast. Pin the actual failure mode:
    // GCM authentication rejecting ciphertext sealed under a different key.
    assert.throws(
      () => decryptItem(item, oldKeys, rewritten),
      /Unsupported state or unable to authenticate data/u,
      `${item.path} must not open under the old keyset`,
    );
  }

  fs.rmSync(dir, { recursive: true, force: true });
});

// Kills mutation A: changing the `kv` branch's `JSON.stringify(payload, null,
// 2)` to compact (or the `document`/`sync-change` branches' compact
// `JSON.stringify(payload)` to indented) would silently reformat every
// artifact of that kind on disk. src/store.ts:133 and src/grants.ts:180 both
// write two-space JSON for kv envelopes; every document, chunk and
// sync-change writer in src/documents.ts and src/sync/protocol.ts writes
// compact JSON. Asserted directly on the bytes `encryptItem` produced, not by
// re-parsing into objects and comparing equality (which would not notice a
// formatting change at all).
test("encryptItem reproduces each owner's JSON formatting exactly", () => {
  const { dir } = seedVault();
  const oldKeys = openVaultKeys(dir, PASSPHRASE);

  const items = planRekey(dir);
  const kvItem = items.find((item) => item.path === "health.kv.enc");
  const documentItem = items.find((item) => item.path === "documents/index.enc");
  assert.ok(kvItem, "health.kv.enc should have been scheduled");
  assert.ok(documentItem, "documents/index.enc should have been scheduled");

  const kvRaw = fs.readFileSync(path.join(dir, kvItem.path));
  const kvPlaintext = decryptItem(kvItem, oldKeys, kvRaw);
  const kvRewritten = encryptItem(kvItem, oldKeys, kvPlaintext).toString("utf8");

  // src/store.ts / src/grants.ts format: JSON.stringify(payload, null, 2).
  assert.match(
    kvRewritten,
    /^\{\n {2}"version": 2,\n {2}"cipher": "aes-256-gcm",\n {2}"keyId": "kv",\n {2}"iv": "/u,
    "kv envelopes must be two-space-indented JSON, like src/store.ts and src/grants.ts write",
  );

  const documentRaw = fs.readFileSync(path.join(dir, ...documentItem.path.split("/")));
  const documentPlaintext = decryptItem(documentItem, oldKeys, documentRaw);
  const documentRewritten = encryptItem(documentItem, oldKeys, documentPlaintext).toString("utf8");

  // src/documents.ts format: compact JSON.stringify(payload), no whitespace.
  assert.match(documentRewritten, /^\{"version":1,"iv":"/u, "document envelopes must be compact JSON");
  assert.doesNotMatch(documentRewritten, /\n/u, "document envelopes must not contain any newlines");

  fs.rmSync(dir, { recursive: true, force: true });
});

// Kills mutation B: routing the `document` branch through `.toString("utf8")`
// instead of decryptDocumentBytes/encryptDocumentBytes would corrupt any
// attachment chunk holding bytes that are not valid UTF-8 — exactly the case
// for arbitrary binary attachments. One chunk is well under the 1 MiB chunk
// size (src/documents.ts ATTACHMENT_CHUNK_SIZE), so this does not exercise
// the multi-chunk path; kept small so the test stays fast.
test("an attachment with invalid UTF-8 bytes survives re-encryption byte for byte", () => {
  const dir = tempDir();
  const vault = new DocumentVault(dir, PASSPHRASE);
  const binary = Buffer.from([
    0x48, 0x65, 0x6c, 0x6c, 0x6f, // "Hello", so the payload isn't purely pathological
    0x80, 0x81, // lone continuation bytes
    0xff, 0xfe, // invalid standalone bytes
    0xe2, 0x28, 0xa1, // truncated / invalid multi-byte sequence
    0x00, // NUL
  ]);
  const attachment = vault.putAttachment(binary, "binary.bin");
  vault.lock();

  const oldKeys = openVaultKeys(dir, PASSPHRASE);
  const newKeys = randomKeySet();
  newKeys.attachmentId = Buffer.from(oldKeys.attachmentId);

  const item = planRekey(dir).find(
    (candidate) => candidate.path === `documents/attachments/${attachment.id}/0.chunk.enc`,
  );
  assert.ok(item, "the attachment chunk should have been scheduled");

  const raw = fs.readFileSync(path.join(dir, ...item.path.split("/")));
  const plaintext = decryptItem(item, oldKeys, raw);
  assert.deepEqual(plaintext, binary, "decrypted chunk must match the original bytes exactly");

  const rewritten = encryptItem(item, newKeys, plaintext);
  const roundTripped = decryptItem(item, newKeys, rewritten);
  assert.deepEqual(roundTripped, binary, "re-encrypted chunk must round trip byte for byte");

  fs.rmSync(dir, { recursive: true, force: true });
});

// Kills mutation C: disabling the `envelope.id !== item.identity` guard in
// the sync-change branch of decryptItem would let a swapped or renamed
// change file re-seal under the wrong subkey and AAD. Drives a real
// SyncChangeLog for the envelope, then hands decryptItem an item whose
// identity does not match what the file's own envelope carries.
test("decryptItem refuses a sync change whose filename does not match its envelope", () => {
  const dir = tempDir();
  const log = new SyncChangeLog(dir, PASSPHRASE);
  const deviceId = "33333333-3333-4333-8333-333333333333";
  const change = log.append(deviceId, {
    objectType: "note",
    objectId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    operation: "put",
    baseRevision: null,
    revision: 1,
    value: { title: "Plan", body: "private body" },
  });
  log.close();

  const keys = openVaultKeys(dir, PASSPHRASE);
  const item = planRekey(dir).find((candidate) => candidate.kind === "sync-change");
  assert.ok(item, "a sync change should have been scheduled");
  assert.equal(item.identity, change.id);

  const raw = fs.readFileSync(path.join(dir, ...item.path.split("/")));
  const mismatched = { ...item, identity: "0".repeat(64) };
  assert.notEqual(mismatched.identity, change.id);

  assert.throws(
    () => decryptItem(mismatched, keys, raw),
    /Sync change filename does not match its envelope/u,
  );

  fs.rmSync(dir, { recursive: true, force: true });
});

// seedVault() does not produce a sync change, so the round-trip test above
// never exercises the "sync-change" branch. This test drives a real
// SyncChangeLog so that branch — the only place kind: "sync-change" is
// reachable at all — is actually covered.
test("a sync change keeps its ID and its envelope shape across a re-encryption", () => {
  const dir = tempDir();
  const log = new SyncChangeLog(dir, PASSPHRASE);
  const deviceId = "33333333-3333-4333-8333-333333333333";
  const change = log.append(deviceId, {
    objectType: "note",
    objectId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    operation: "put",
    baseRevision: null,
    revision: 1,
    value: { title: "Plan", body: "private body" },
  });
  log.close();

  const oldKeys = openVaultKeys(dir, PASSPHRASE);
  const newKeys = randomKeySet();
  newKeys.syncChange = Buffer.from(oldKeys.syncChange);

  const item = planRekey(dir).find((candidate) => candidate.kind === "sync-change");
  assert.ok(item, "a sync change should have been scheduled");
  assert.equal(item.identity, change.id);

  const raw = fs.readFileSync(path.join(dir, ...item.path.split("/")));
  const rewritten = encryptItem(item, newKeys, decryptItem(item, oldKeys, raw));
  const before = JSON.parse(raw.toString("utf8"));
  const after = JSON.parse(rewritten.toString("utf8"));

  assert.equal(after.id, before.id);
  assert.equal(after.version, 1);
  assert.notEqual(after.payload.ciphertext, before.payload.ciphertext);

  // Minor finding: nothing pinned that the re-sealed envelope's key order
  // matches sealSyncChange (src/sync/protocol.ts) — {version, id, payload}.
  // Object.keys on a JSON.parse result reflects the order the keys appeared
  // in the source text (these are non-integer string keys, so JS does not
  // reorder them), which lets this check speak to the actual serialized
  // bytes rather than just the parsed shape.
  assert.deepEqual(Object.keys(after), ["version", "id", "payload"]);
  assert.match(rewritten.toString("utf8"), /^\{"version":1,"id":"[0-9a-f]{64}","payload":/u);

  fs.rmSync(dir, { recursive: true, force: true });
});

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

/**
 * The fail-closed contract of a refused stage: every live file byte-identical
 * to the hashes taken before the attempt, no file appearing or disappearing
 * anywhere under the vault, and no staging tree left behind. Comparing the
 * key sets and not just the values is what makes a surviving `.rekey` visible
 * — a value-only comparison cannot see a file that was not there before.
 */
function assertVaultUnchanged(dir, before) {
  const after = hashVault(dir);
  for (const [relative, hash] of Object.entries(before)) {
    assert.equal(after[relative], hash, `${relative} must not have changed`);
  }
  assert.deepEqual(
    Object.keys(after).sort(),
    Object.keys(before).sort(),
    "a refused stage must not add or remove a single file anywhere in the vault",
  );
  assert.equal(fs.existsSync(stagingRoot(dir)), false, "the staging tree must not survive a refused stage");
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

  assertVaultUnchanged(dir, before);

  fs.rmSync(dir, { recursive: true, force: true });
});

// A staging tree left in the vault root (e.g. from a previous stageRekey call
// that stageRekey itself has not yet cleaned up, or one this run is about to
// overwrite) must not be enumerated as vault content: planRekey's vault-root
// scan only classifies *files*, and .rekey is a directory, so it is skipped
// exactly like any other subdirectory. This test pins that behavior so a
// future change to the root scan cannot regress it into walking into .rekey.
test("a staging directory at the vault root does not break planRekey and is never enumerated as vault content", () => {
  const { dir } = seedVault();
  const before = planRekey(dir);

  const oldKeys = openVaultKeys(dir, PASSPHRASE);
  const newKeys = pinnedKeySet(oldKeys);
  stageRekey(dir, oldKeys, newKeys, before);
  assert.ok(fs.existsSync(stagingRoot(dir)), "staging root should exist after stageRekey");

  const after = planRekey(dir);
  assert.deepEqual(
    after.map((item) => item.path).sort(),
    before.map((item) => item.path).sort(),
    "planRekey must schedule the same live artifacts whether or not a .rekey staging tree is present",
  );
  assert.equal(
    after.some((item) => item.path.startsWith(".rekey")),
    false,
    "no item under .rekey should ever be scheduled as vault content",
  );

  fs.rmSync(dir, { recursive: true, force: true });
});

// The three tests below inject a failure PART WAY THROUGH the staging loop.
// The wrong-keyset test above fails on the very first item, so it can never
// show that a partially built shadow tree is discarded — the shape where
// "no partial staging tree survives" means anything at all.

// Kills the mutation "delete the fs.rmSync from stageRekey's catch block":
// several items stage successfully before the damaged one, so removing the
// cleanup leaves a real, partially populated .rekey tree that
// assertVaultUnchanged sees as files that appeared.
test("a damaged artifact at the end of the list leaves no partial staging tree", () => {
  const { dir } = seedVault();
  const oldKeys = openVaultKeys(dir, PASSPHRASE);
  const newKeys = pinnedKeySet(oldKeys);
  const items = planRekey(dir);
  assert.ok(items.length > 3, "the seeded vault must hold several artifacts for this to be a mid-loop failure");

  // A well-formed envelope sealed under a key this vault does not hold: what
  // a damaged or foreign object looks like on disk. Written to the LAST item
  // so everything before it stages cleanly first.
  const damaged = items[items.length - 1];
  const livePath = path.join(dir, ...damaged.path.split("/"));
  fs.writeFileSync(livePath, encryptItem(damaged, randomKeySet(), Buffer.from("not this vault's plaintext")));

  // Hashed after the damage, so the corrupted file is part of the baseline
  // the vault must still match once staging refuses.
  const before = hashVault(dir);

  assert.throws(
    () => stageRekey(dir, oldKeys, newKeys, items),
    /Unsupported state or unable to authenticate data/u,
  );

  assertVaultUnchanged(dir, before);

  fs.rmSync(dir, { recursive: true, force: true });
});

// Kills two mutations at once: replacing the disk read-back with the buffer
// already in hand (`verified = Buffer.from(plaintext)`), and neutering the
// comparison (`verified.equals(verified)`). Both make a staged file that does
// NOT carry its item's plaintext pass verification, so stageRekey returns
// instead of throwing.
//
// The staged payload substituted here is a valid envelope over a plaintext
// ten bytes short — the outcome of a write that landed but did not land in
// full. A raw byte truncation of the ciphertext would only prove the reader
// throws on garbage, which a mutated comparison would still do; a short but
// well-formed payload is what forces the byte-for-byte comparison to be the
// thing that catches it.
test("the disk read-back catches a staged file that does not carry its plaintext", () => {
  const { dir } = seedVault();
  const oldKeys = openVaultKeys(dir, PASSPHRASE);
  const newKeys = pinnedKeySet(oldKeys);
  const items = planRekey(dir);
  const plaintextOf = (item) => decryptItem(item, oldKeys, fs.readFileSync(path.join(dir, ...item.path.split("/"))));

  // Partway through the list, so items stage cleanly on either side of it.
  const targetIndex = items.findIndex((item, index) => index >= 2 && plaintextOf(item).length > 10);
  assert.ok(targetIndex > 1, "the seeded vault must hold a mid-list artifact long enough to shorten");
  const target = items[targetIndex];
  const shortPlaintext = plaintextOf(target).subarray(0, -10);
  const shortPayload = encryptItem(target, newKeys, shortPlaintext);

  const before = hashVault(dir);
  const realWriteFileSync = fs.writeFileSync;
  let writes = 0;
  try {
    // writeFileAtomic (src/fs-safe.ts) issues exactly one writeFileSync per
    // staged artifact, so the Nth call is items[N - 1].
    fs.writeFileSync = (destination, data, options) => {
      writes += 1;
      return realWriteFileSync(destination, writes === targetIndex + 1 ? shortPayload : data, options);
    };

    assert.throws(() => stageRekey(dir, oldKeys, newKeys, items), /does not carry its plaintext/u);
  } finally {
    fs.writeFileSync = realWriteFileSync;
  }

  assert.equal(writes, targetIndex + 1, "staging must stop at the damaged write, not carry on past it");
  assertVaultUnchanged(dir, before);

  fs.rmSync(dir, { recursive: true, force: true });
});

// A full disk partway through the loop: the original ENOSPC must reach the
// caller unchanged, and the two artifacts already staged must not survive.
test("a mid-list I/O failure aborts staging with the original error and no leftovers", () => {
  const { dir } = seedVault();
  const oldKeys = openVaultKeys(dir, PASSPHRASE);
  const newKeys = pinnedKeySet(oldKeys);
  const items = planRekey(dir);
  assert.ok(items.length > 3, "the seeded vault must hold several artifacts for this to be a mid-loop failure");

  const before = hashVault(dir);
  const realOpenSync = fs.openSync;
  let opens = 0;
  try {
    // writeFileAtomic opens the temporary sibling it writes; the third open
    // is the third artifact, so two are already staged when the disk fills.
    fs.openSync = (...args) => {
      opens += 1;
      if (opens === 3) {
        const full = new Error("ENOSPC: no space left on device, open");
        full.code = "ENOSPC";
        throw full;
      }
      return realOpenSync(...args);
    };

    assert.throws(() => stageRekey(dir, oldKeys, newKeys, items), (error) => {
      assert.equal(error.code, "ENOSPC", "the original I/O error must reach the caller, not a cleanup failure");
      return true;
    });
  } finally {
    fs.openSync = realOpenSync;
  }

  assert.equal(opens, 3, "staging must stop at the failed write, not carry on past it");
  assertVaultUnchanged(dir, before);

  fs.rmSync(dir, { recursive: true, force: true });
});

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

/**
 * `hashVault` covers the whole directory, staging tree included, so a
 * baseline taken while `.rekey` exists cannot be compared against a vault the
 * commit or the rollback has since cleaned up. These are the live files only
 * — the ones a re-key must either replace wholesale or leave untouched.
 */
function liveHashes(dir) {
  return Object.fromEntries(
    Object.entries(hashVault(dir)).filter(([relative]) => !relative.startsWith(`${STAGING_DIRNAME}/`)),
  );
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
  const before = liveHashes(dir);
  // Simulate a crash between the journal write and the keyring write.
  fs.writeFileSync(journalPath(dir), `${JSON.stringify(journal)}\n`);

  assert.equal(recoverRekey(dir), "rolled-back");
  assert.equal(fs.existsSync(stagingRoot(dir)), false);

  forgetVaultKeys();
  assert.ok(openVaultKeys(dir, PASSPHRASE), "the old passphrase must still open the vault");
  const after = liveHashes(dir);
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

// The three tests above hand-build the states a crash produces. The two below
// produce them the only way that also pins the commit ORDER: by failing a
// real `commitRekey` mid-flight and handing what it left on disk to
// `recoverRekey`.
//
// This one kills the mutation "write the keyring before the journal": the
// injected failure hits the keyring's atomic rename, so if the journal were
// written second it would never exist and there would be nothing to recover.
test("a real crash on the keyring write rolls back and leaves the old passphrase working", () => {
  const { dir } = seedVault();
  const { journal, keyring } = preparedRekey(dir);
  const before = liveHashes(dir);

  const realRenameSync = fs.renameSync;
  try {
    fs.renameSync = (from, to, ...rest) => {
      if (path.basename(to) === "keyring.json") {
        const failure = new Error("EIO: simulated crash during the keyring write");
        failure.code = "EIO";
        throw failure;
      }
      return realRenameSync(from, to, ...rest);
    };

    assert.throws(() => commitRekey(dir, journal, keyring), /simulated crash/u);
  } finally {
    fs.renameSync = realRenameSync;
  }

  assert.equal(fs.existsSync(journalPath(dir)), true, "the journal must land before the keyring write");
  assert.equal(
    readKeyring(dir).slots.some((slot) => slot.id === journal.slotId),
    false,
    "the keyring must not carry the new slot after a failed keyring write",
  );

  assert.equal(recoverRekey(dir), "rolled-back");
  assert.equal(fs.existsSync(stagingRoot(dir)), false);

  forgetVaultKeys();
  assert.ok(openVaultKeys(dir, PASSPHRASE), "the old passphrase must still open the vault");
  assert.deepEqual(liveHashes(dir), before, "a rolled-back re-key must leave every live file byte-identical");

  fs.rmSync(dir, { recursive: true, force: true });
});

// Kills the mutation "install the staged files before writing the keyring",
// and the mutation "clear the staging tree before the installs": the crash
// lands after two real installs, so only a run that still has both the
// journal and the staged remainder on disk can finish the job.
test("a real crash partway through the installs is finished by the next run", () => {
  const { dir } = seedVault();
  const { newKeys, journal, keyring } = preparedRekey(dir);
  assert.ok(journal.files.length > 3, "the seeded vault must hold several artifacts for a mid-install crash");

  const tree = stagedTree(dir);
  const realRenameSync = fs.renameSync;
  let installs = 0;
  try {
    fs.renameSync = (from, to, ...rest) => {
      // The journal's and the keyring's atomic writes rename too; only a
      // rename out of the staged tree is an install.
      if (String(from).startsWith(tree)) {
        installs += 1;
        if (installs === 3) {
          const failure = new Error("EIO: simulated crash partway through the installs");
          failure.code = "EIO";
          throw failure;
        }
      }
      return realRenameSync(from, to, ...rest);
    };

    assert.throws(() => commitRekey(dir, journal, keyring), /simulated crash/u);
  } finally {
    fs.renameSync = realRenameSync;
  }

  assert.equal(installs, 3, "the crash must land after two files were really installed");
  assert.equal(fs.existsSync(stagingRoot(dir)), true, "the staged remainder must survive a crash mid-install");
  assert.ok(
    readKeyring(dir).slots.some((slot) => slot.id === journal.slotId),
    "the keyring must already carry the new slot once the installs have begun",
  );

  assert.equal(recoverRekey(dir), "finished");
  assert.equal(fs.existsSync(stagingRoot(dir)), false);
  for (const item of planRekey(dir)) {
    const raw = fs.readFileSync(path.join(dir, ...item.path.split("/")));
    assert.ok(decryptItem(item, newKeys, raw).length >= 0, `${item.path} must open under the new keyset`);
  }

  forgetVaultKeys();
  assert.ok(openVaultKeys(dir, NEW_PASSPHRASE), "the new passphrase must open the finished vault");

  fs.rmSync(dir, { recursive: true, force: true });
});

// Kills the mutation "drop the journal validation": a journal whose slotId is
// not a slot ID can never be found in a keyring, so an unvalidated read would
// silently roll a committed re-key back — destroying the staged tree the
// vault now depends on.
test("a malformed journal refuses recovery instead of touching the vault", () => {
  const { dir } = seedVault();
  const { journal } = preparedRekey(dir);
  fs.writeFileSync(journalPath(dir), `${JSON.stringify({ ...journal, slotId: "not-a-slot-id" })}\n`);
  const before = liveHashes(dir);

  assert.throws(() => recoverRekey(dir), /malformed/u);

  assert.equal(fs.existsSync(stagedTree(dir)), true, "a refused recovery must not destroy the staged tree");
  assert.deepEqual(liveHashes(dir), before, "a refused recovery must not touch a single live file");

  fs.rmSync(dir, { recursive: true, force: true });
});

// Kills the mutation "delete the staged-completeness loop from commitRekey":
// `installStaged` skips a staged file it cannot find, so without the loop a
// short staged tree commits in total silence — the new keyring lands, the
// un-staged object stays sealed under the old keyset, the staging tree is
// swept, and `recoverRekey` afterwards reports "none". The vault ends readable
// by neither keyset with no signal at all. The guard turns that into a refusal
// taken BEFORE the keyring write, which is the only point at which the vault
// is still recoverable.
test("a staged tree missing a file refuses to commit instead of crossing the commit point", () => {
  const { dir } = seedVault();
  const { journal, keyring } = preparedRekey(dir);
  const keyringBefore = readKeyring(dir);
  const missing = journal.files[journal.files.length - 1];
  fs.rmSync(path.join(stagedTree(dir), ...missing.split("/")));
  const before = liveHashes(dir);

  assert.throws(() => commitRekey(dir, journal, keyring), /missing from the staged tree/u);

  assert.deepEqual(readKeyring(dir), keyringBefore, "the old keyring must still be the one on disk");
  assert.deepEqual(liveHashes(dir), before, "a refused commit must not touch a single live file");

  forgetVaultKeys();
  assert.ok(openVaultKeys(dir, PASSPHRASE), "the old passphrase must still open the vault");

  fs.rmSync(dir, { recursive: true, force: true });
});

// Kills the mutation "delete the journal check from stageRekey": the opening
// rmSync clears the whole staging root, journal included. An operator who
// retries the re-key after a crash mid-install instead of recovering would
// take the journal and the un-installed remainder with it, and the
// half-committed vault becomes unrecoverable — `recoverRekey` would find no
// journal and report "none" over files that never got installed.
test("staging refuses while an interrupted re-key is still journaled", () => {
  const { dir } = seedVault();
  const oldKeys = openVaultKeys(dir, PASSPHRASE);
  const newKeys = pinnedKeySet(oldKeys);
  const items = planRekey(dir);
  const journal = { version: 1, slotId: crypto.randomUUID(), files: items.map((item) => item.path) };
  fs.mkdirSync(stagingRoot(dir), { recursive: true });
  fs.writeFileSync(journalPath(dir), `${JSON.stringify(journal)}\n`);
  const journalBefore = fs.readFileSync(journalPath(dir));

  assert.throws(() => stageRekey(dir, oldKeys, newKeys, items), /run recovery/u);

  assert.ok(fs.existsSync(journalPath(dir)), "the journal must survive a refused stage");
  assert.deepEqual(fs.readFileSync(journalPath(dir)), journalBefore, "the journal must be byte-identical");

  fs.rmSync(dir, { recursive: true, force: true });
});

// Kills the mutation "unwrap the JSON.parse guard in readJournal": a truncated
// journal is an ordinary crash artifact, and the operator must see the same
// "refusing to touch the vault" refusal a structurally invalid journal
// produces, not a raw SyntaxError from the parser.
test("a truncated journal refuses recovery with the same message a malformed one gives", () => {
  const { dir } = seedVault();
  const { journal } = preparedRekey(dir);
  fs.writeFileSync(journalPath(dir), `${JSON.stringify(journal)}\n`.slice(0, 40));
  const before = liveHashes(dir);

  assert.throws(() => recoverRekey(dir), /malformed; refusing to touch the vault/u);

  assert.equal(fs.existsSync(stagedTree(dir)), true, "a refused recovery must not destroy the staged tree");
  assert.deepEqual(liveHashes(dir), before, "a refused recovery must not touch a single live file");

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- Task 5: the orchestration ------------------------------------------

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

  // The counts the Task 6 CLI prints. Pinned against the plan the walk
  // produces rather than against literals, so a hard-coded zero anywhere in
  // `reencrypted` goes red here.
  const items = planRekey(dir);
  assert.equal(report.reencrypted.total, items.length);
  assert.equal(report.reencrypted.documents, items.filter((item) => item.kind === "document").length);
  assert.equal(report.reencrypted.kv, items.filter((item) => item.kind === "kv").length);
  assert.equal(report.reencrypted.syncChanges, items.filter((item) => item.kind === "sync-change").length);
  assert.ok(report.reencrypted.documents > 0 && report.reencrypted.kv > 0);
  assert.equal(
    report.reencrypted.documents + report.reencrypted.kv + report.reencrypted.syncChanges,
    report.reencrypted.total,
  );

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

// Kills the mutation "drop the same-passphrase refusal": without it the run
// completes and reports `passphraseChanged: true` while the passphrase the
// user is re-keying away from still opens the vault.
test("a re-key to the passphrase already in use is refused unless it is asked for", () => {
  const { dir } = seedVault();
  const before = hashVault(dir);

  assert.throws(
    () => rekeyVault(dir, PASSPHRASE, PASSPHRASE),
    /same as the current one/u,
  );
  assertVaultUnchanged(dir, before);

  // The escape hatch still performs the full rotation.
  const report = rekeyVault(dir, PASSPHRASE, PASSPHRASE, { allowSamePassphrase: true });
  assert.equal(report.passphraseChanged, true);
  const after = hashVault(dir);
  for (const item of planRekey(dir)) {
    assert.notEqual(after[item.path], before[item.path], `${item.path} must have been re-encrypted`);
  }
  forgetVaultKeys();
  assert.ok(openVaultKeys(dir, PASSPHRASE));

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
  const after = hashVault(dir);
  for (const item of planRekey(dir)) {
    assert.notEqual(after[item.path], before[item.path]);
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

// The report names the split, but only the bytes on disk prove it. Reading
// both keysets and comparing them key by key is what goes red if the pinning
// loop is deleted (the three identity keys would rotate) or if it is widened
// to every key (the three content keys would not). Neither mutation is
// visible to a ciphertext-changed assertion, because a fresh IV changes every
// ciphertext even when the key behind it does not change at all.
test("a re-key rotates exactly the three content keys and pins exactly the three identity keys", () => {
  const { dir } = seedVault();
  const oldKeys = openVaultKeys(dir, PASSPHRASE);

  rekeyVault(dir, PASSPHRASE, NEW_PASSPHRASE);

  forgetVaultKeys();
  const newKeys = openVaultKeys(dir, NEW_PASSPHRASE);
  for (const name of ["documents", "kv", "syncEnvelope"]) {
    assert.equal(newKeys[name].equals(oldKeys[name]), false, `${name} must have been rotated`);
  }
  for (const name of ["attachmentId", "syncChange", "audit"]) {
    assert.equal(newKeys[name].equals(oldKeys[name]), true, `${name} must have been pinned`);
  }

  fs.rmSync(dir, { recursive: true, force: true });
});

// seedVault() produces no sync change, so the orchestration's sync-change
// branch — and the syncEnvelope rotation that only shows up there — is
// otherwise never driven end to end.
test("a re-key re-seals a sync change under the new envelope key without moving it", () => {
  const dir = tempDir();
  const log = new SyncChangeLog(dir, PASSPHRASE);
  const change = log.append("33333333-3333-4333-8333-333333333333", {
    objectType: "note",
    objectId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
    operation: "put",
    baseRevision: null,
    revision: 1,
    value: { title: "Plan", body: "private body" },
  });
  log.close();
  const before = hashVault(dir);
  const changeFile = `documents/sync/changes/${change.id}.change.enc`;

  const report = rekeyVault(dir, PASSPHRASE, NEW_PASSPHRASE);

  assert.equal(report.reencrypted.syncChanges, 1);
  assert.notEqual(hashVault(dir)[changeFile], before[changeFile]);

  forgetVaultKeys();
  const reopened = new SyncChangeLog(dir, NEW_PASSPHRASE);
  assert.equal(reopened.change(change.id).mutation.value.body, "private body");
  assert.deepEqual(reopened.verify().heads, [change.id]);
  reopened.close();

  fs.rmSync(dir, { recursive: true, force: true });
});

// Kills the mutation "skip recovery and go straight to staging": an
// interrupted re-key whose keyring was already replaced must be finished, not
// restaged, and the run that finishes it must say so rather than claim a
// fresh rotation it did not perform.
test("a re-key finishes an interrupted one instead of starting over", () => {
  const { dir } = seedVault();
  const { journal, keyring } = preparedRekey(dir);
  // Simulate a crash after the commit point: the journal and the new keyring
  // are both on disk, but nothing has been installed yet.
  fs.writeFileSync(journalPath(dir), `${JSON.stringify(journal)}\n`);
  writeKeyring(dir, keyring);
  const staged = journal.files.map((relative) => path.join(stagedTree(dir), ...relative.split("/")));
  assert.ok(staged.every((file) => fs.existsSync(file)));

  const report = rekeyVault(dir, NEW_PASSPHRASE, "another-replacement-passphrase");

  assert.equal(report.resumed, true);
  assert.equal(report.passphraseChanged, false);
  assert.equal(fs.existsSync(stagingRoot(dir)), false);
  forgetVaultKeys();
  assert.ok(openVaultKeys(dir, NEW_PASSPHRASE), "the interrupted re-key's passphrase must open the vault");

  fs.rmSync(dir, { recursive: true, force: true });
});

// A failure past the commit point is the one case where the fail-closed
// cleanup must not run: `keyring.json` already names the new keyset, so the
// staged remainder is the only copy of the files the vault now depends on.
// Kills the mutation "clear the staging tree on any error": with the journal
// check removed, this run leaves a vault whose keyring and whose objects
// disagree, with nothing left on disk to reconcile them.
test("a failure partway through the installs leaves the journal for recovery", () => {
  const { dir, noteId } = seedVault();
  const tree = stagedTree(dir);
  const realRenameSync = fs.renameSync;
  let installs = 0;
  try {
    // An install is the only rename that moves a file out of the staged tree;
    // staging's own atomic writes rename within it, and the keyring's rename
    // does not start there at all.
    fs.renameSync = (from, to, ...rest) => {
      if (String(from).startsWith(tree) && !String(to).startsWith(tree)) {
        installs += 1;
        if (installs > 2) {
          const failure = new Error("EIO: simulated crash during the installs");
          failure.code = "EIO";
          throw failure;
        }
      }
      return realRenameSync(from, to, ...rest);
    };

    assert.throws(() => rekeyVault(dir, PASSPHRASE, NEW_PASSPHRASE), /simulated crash/u);
  } finally {
    fs.renameSync = realRenameSync;
  }

  assert.equal(fs.existsSync(journalPath(dir)), true, "the journal must survive a failure past the commit point");
  assert.equal(recoverRekey(dir), "finished");

  forgetVaultKeys();
  const vault = new DocumentVault(dir, NEW_PASSPHRASE);
  assert.match(vault.get(noteId).body, /second revision/u);
  vault.lock();

  fs.rmSync(dir, { recursive: true, force: true });
});
