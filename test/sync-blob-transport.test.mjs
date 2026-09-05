import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { SyncBlobStore } from "../dist/sync-blobs.js";
import { attachmentBlobIds, startSyncRelay, SyncRelayClient } from "../dist/sync-relay.js";
import { parseAttachmentSnapshot, SyncDeviceManager, SyncedDocumentVault } from "../dist/sync.js";

const PASSPHRASE = "blob-transport-test-passphrase";
const TOKEN = "relay-test-token-that-is-at-least-thirty-two-bytes";
const DEVICE_A = "11111111-1111-4111-8111-111111111111";
const MIB = 1024 * 1024;

function tempDir(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `vault-brain-blob-transport-${label}-`));
}

function removeAll(...dirs) {
  for (const dir of dirs) fs.rmSync(dir, { recursive: true, force: true });
}

/**
 * A vault whose enrollment and key material exist but which holds no content
 * yet, plus a byte-identical clone of it. Vault keys are per-vault, so a peer
 * that must open this vault's envelopes has to start from a copy of it — the
 * same shape `test/sync-apply.test.mjs` uses.
 */
function enrolledPair(label) {
  const sourceDir = tempDir(`${label}-source`);
  const manager = new SyncDeviceManager(sourceDir, PASSPHRASE);
  manager.initializeOwner("Owner", DEVICE_A, "2026-09-04T10:00:00.000Z");
  const vaultId = manager.fingerprint();
  manager.close();

  const vault = new SyncedDocumentVault(sourceDir, PASSPHRASE, DEVICE_A);
  vault.lock();

  const targetDir = tempDir(`${label}-target`);
  fs.rmSync(targetDir, { recursive: true, force: true });
  fs.cpSync(sourceDir, targetDir, { recursive: true });
  return { sourceDir, targetDir, vaultId };
}

/** Every blob id the given changes reference, de-duplicated, in change order. */
function referencedBlobIds(changes) {
  return [...new Set(changes.flatMap((change) => attachmentBlobIds(change)))];
}

function blobSnapshot(log, attachmentId) {
  return parseAttachmentSnapshot(log.resolve("attachment", attachmentId).winner.mutation.value);
}

test("a 12 MiB attachment survives a device-to-device round trip through the relay", async () => {
  const storageDir = tempDir("roundtrip-storage");
  const { sourceDir, targetDir, vaultId } = enrolledPair("roundtrip");
  const relay = await startSyncRelay({ storageDir, token: TOKEN });
  let source;
  let target;
  try {
    const data = crypto.randomBytes(12 * MIB);
    const digest = crypto.createHash("sha256").update(data).digest("hex");

    source = new SyncedDocumentVault(sourceDir, PASSPHRASE, DEVICE_A);
    const info = source.putAttachment(data, "video.bin", "application/octet-stream");
    assert.equal(info.size, 12 * MIB);

    // The manifest replaced the bytes: 12 blob ids, no inline payload.
    const snapshot = blobSnapshot(source.changeLog, info.id);
    assert.deepEqual(
      {
        filename: snapshot.filename,
        mime: snapshot.mime,
        size: snapshot.size,
        chunks: snapshot.chunks,
        blobCount: snapshot.blobs.length,
        inline: "data" in snapshot,
      },
      {
        filename: "video.bin",
        mime: "application/octet-stream",
        size: 12 * MIB,
        chunks: 12,
        blobCount: 12,
        inline: false,
      },
    );
    assert.ok(snapshot.blobs.every((id) => /^[0-9a-f]{64}$/u.test(id)));

    // Push: the envelopes plus the sealed chunks they reference.
    const pusher = new SyncRelayClient(relay.url, TOKEN, vaultId, sourceDir);
    const uploaded = await pusher.uploadChanges(source.changeLog.envelopes(), source.changeLog.changes());
    assert.equal(uploaded.stored, source.changeLog.envelopes().length);
    // A second push is a no-op on both collections.
    assert.deepEqual(await pusher.pushBlobs(snapshot.blobs), { uploaded: 0, skipped: 12 });
    source.lock();
    source = undefined;

    // Pull onto the second device, which starts with neither change nor bytes.
    const puller = new SyncRelayClient(relay.url, TOKEN, vaultId, targetDir);
    target = new SyncedDocumentVault(targetDir, PASSPHRASE);
    target.changeLog.import(await puller.downloadChanges());
    const ids = referencedBlobIds(target.changeLog.changes());
    assert.equal(ids.length, 12);
    assert.deepEqual(await puller.pullBlobs(ids), { fetched: 12, skipped: 0 });

    target.applyResolved("attachment", info.id);
    const recovered = target.getAttachment(info.id);
    assert.equal(crypto.createHash("sha256").update(recovered.data).digest("hex"), digest);
    assert.equal(recovered.data.length, 12 * MIB);
    assert.equal(recovered.info.id, info.id);
    assert.equal(recovered.info.size, 12 * MIB);
    assert.equal(recovered.info.filename, "video.bin");
    assert.equal(recovered.info.mime, "application/octet-stream");
  } finally {
    source?.lock();
    target?.lock();
    await relay.close();
    removeAll(storageDir, sourceDir, targetDir);
  }
});

test("every blob PUT precedes the first change PUT of a push", async () => {
  const storageDir = tempDir("ordering-storage");
  const { sourceDir, targetDir, vaultId } = enrolledPair("ordering");
  const relay = await startSyncRelay({ storageDir, token: TOKEN });
  let source;
  try {
    source = new SyncedDocumentVault(sourceDir, PASSPHRASE, DEVICE_A);
    const info = source.putAttachment(crypto.randomBytes(3 * MIB + 9), "clip.bin", "application/octet-stream");
    const snapshot = blobSnapshot(source.changeLog, info.id);
    assert.equal(snapshot.blobs.length, 4);

    const client = new SyncRelayClient(relay.url, TOKEN, vaultId, sourceDir);
    const seen = [];
    const original = globalThis.fetch;
    globalThis.fetch = async (input, init) => {
      seen.push(`${init?.method ?? "GET"} ${new URL(String(input)).pathname}`);
      return original(input, init);
    };
    try {
      await client.uploadChanges(source.changeLog.envelopes(), source.changeLog.changes());
    } finally {
      globalThis.fetch = original;
    }

    const isBlobPut = (record) => record.startsWith(`PUT /v1/vaults/${vaultId}/blobs/`);
    const isChangePut = (record) => record.startsWith(`PUT /v1/vaults/${vaultId}/changes/`);
    const firstChangePut = seen.findIndex(isChangePut);
    const blobPuts = seen.flatMap((record, index) => (isBlobPut(record) ? [index] : []));

    assert.equal(blobPuts.length, 4, "the push uploaded every sealed chunk");
    assert.ok(firstChangePut >= 0, "the push uploaded at least one change");
    assert.ok(
      blobPuts.every((index) => index < firstChangePut),
      `every blob PUT must precede the first change PUT: ${JSON.stringify(seen)}`,
    );
    assert.ok(seen.at(-1) !== undefined && isChangePut(seen.at(-1)));
    // The uploaded blob ids are exactly the manifest's, none invented.
    assert.deepEqual(
      blobPuts.map((index) => seen[index].slice(`PUT /v1/vaults/${vaultId}/blobs/`.length)).sort(),
      [...snapshot.blobs].sort(),
    );
  } finally {
    source?.lock();
    await relay.close();
    removeAll(storageDir, sourceDir, targetDir);
  }
});

/**
 * A target device holding an attachment change and every one of its blobs,
 * except that chunk 0's file has been overwritten with chunk 1's sealed bytes.
 * `SyncBlobStore.put` rejects that substitution, so it is written straight to
 * disk to prove the apply path refuses it independently.
 */
function stagedWithSubstitutedChunk(label) {
  const { sourceDir, targetDir } = enrolledPair(label);
  const source = new SyncedDocumentVault(sourceDir, PASSPHRASE, DEVICE_A);
  const data = crypto.randomBytes(2 * MIB + 3);
  const info = source.putAttachment(data, "doc.bin", "application/octet-stream");
  const envelopes = source.changeLog.envelopes();
  const snapshot = blobSnapshot(source.changeLog, info.id);
  source.lock();

  const target = new SyncedDocumentVault(targetDir, PASSPHRASE);
  target.changeLog.import(envelopes);

  const from = new SyncBlobStore(sourceDir);
  const to = new SyncBlobStore(targetDir);
  for (const id of snapshot.blobs) to.put(id, from.read(id));
  const decoy = from.read(snapshot.blobs[1]);
  fs.writeFileSync(path.join(targetDir, "documents", "sync", "blobs", snapshot.blobs[0]), decoy);

  return { sourceDir, targetDir, target, from, to, data, info, snapshot, decoy };
}

test("a substituted blob is refused rather than written into the vault", () => {
  const staged = stagedWithSubstitutedChunk("tamper");
  let target = staged.target;
  try {
    assert.equal(staged.snapshot.blobs.length, 3);
    // The store's own content-address check rejects the substitution; the
    // fixture wrote past it, and the bytes on disk really are the decoy.
    assert.throws(() => staged.to.put(staged.snapshot.blobs[0], staged.decoy), /does not match its id/iu);
    assert.deepEqual(staged.to.read(staged.snapshot.blobs[0]), staged.decoy);

    // The AAD binds a chunk to its index, so this fails before the
    // content-address check; either refusal is a pass, so no message is pinned.
    assert.throws(() => target.applyResolved("attachment", staged.info.id));
    assert.equal(target.listAttachments().length, 0);
    assert.throws(() => target.getAttachment(staged.info.id));
    // The positive control is the round-trip test above: the identical apply
    // over genuine blobs reproduces the bytes exactly.
  } finally {
    target?.lock();
    removeAll(staged.sourceDir, staged.targetDir);
  }
});

// The mirror of `test/sync-apply.test.mjs`'s missing-chunk case: a refused
// attachment apply must leave no receipt behind, because a receipt is rolled
// forward on every later unlock and would fail there too. `src/sync.ts` says so
// itself, above `assertRemoteChangeIsStaged`.
test("a refused substituted blob leaves no receipt that follows the vault to its next unlock", () => {
  const staged = stagedWithSubstitutedChunk("tamper-receipt");
  let target = staged.target;
  try {
    assert.throws(() => target.applyResolved("attachment", staged.info.id));
    assert.equal(target.listAttachments().length, 0);
    target.lock();

    target = new SyncedDocumentVault(staged.targetDir, PASSPHRASE);
    assert.equal(target.listAttachments().length, 0);
  } finally {
    target?.lock();
    removeAll(staged.sourceDir, staged.targetDir);
  }
});
