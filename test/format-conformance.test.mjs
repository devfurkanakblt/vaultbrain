import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { AAD, FORMAT_COMPATIBILITY, VAULT_FORMAT_VERSION, canonicalBase64 } from "../dist/format-version.js";
import { SyncBlobStore } from "../dist/sync-blobs.js";
import {
  SyncChangeLog,
  SyncDeviceManager,
  SyncedDocumentVault,
  canonicalSyncJson,
  parseAttachmentSnapshot,
} from "../dist/sync.js";

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures");
const FIXTURE_PASSPHRASE = "fixture-only-passphrase";
const OWNER = "11111111-1111-4111-8111-111111111111";
const REVOKED = "22222222-2222-4222-8222-222222222222";

test("the format version surface is frozen and complete", () => {
  assert.equal(VAULT_FORMAT_VERSION, "1.0");

  // Every AAD string is domain-separated under one prefix and is unique.
  const values = Object.values(AAD);
  assert.ok(values.length >= 20, "the inventory must cover every domain string in the codebase");
  for (const value of values) {
    assert.match(value, /^secondbrain-vault:/u, `AAD ${value} must carry the project prefix`);
  }
  assert.equal(new Set(values).size, values.length, "AAD strings must be unique");

  // The compatibility record names every artifact and the versions this build handles.
  for (const [artifact, entry] of Object.entries(FORMAT_COMPATIBILITY)) {
    assert.ok(entry.reads.length > 0, `${artifact} must declare readable versions`);
    assert.ok(entry.writes.length > 0, `${artifact} must declare written versions`);
    for (const written of entry.writes) {
      assert.ok(entry.reads.includes(written), `${artifact} must read every version it writes`);
    }
  }
  assert.deepEqual(FORMAT_COMPATIBILITY.encryptedEnvelope.reads, [0, 1]);
  assert.deepEqual(FORMAT_COMPATIBILITY.encryptedEnvelope.writes, [1]);

  // Blob transport added change body version 3 to the sync change entry.
  assert.deepEqual(FORMAT_COMPATIBILITY.syncChangeEnvelope.reads, [1, 2, 3]);
  assert.deepEqual(FORMAT_COMPATIBILITY.syncChangeEnvelope.writes, [1, 2, 3]);
});

test("canonical base64 rejects non-canonical and wrong-length encodings", () => {
  const key = Buffer.alloc(44, 7).toString("base64");
  assert.equal(canonicalBase64(key, 44, "test key"), key);
  assert.throws(() => canonicalBase64(key, 32, "test key"), /invalid test key length/u);
  assert.throws(() => canonicalBase64("not base64!", undefined, "test key"), /malformed test key/u);
  // "QQ==" is canonical; "QQ" is the same bytes without padding and must be refused.
  assert.equal(canonicalBase64("QQ==", 1, "test key"), "QQ==");
  assert.throws(() => canonicalBase64("QQ", 1, "test key"), /malformed test key/u);
});

test("the committed rotated vault still opens both envelope versions", () => {
  const dir = path.join(FIXTURES, "sync-epoch-v2");
  const log = new SyncChangeLog(dir, FIXTURE_PASSPHRASE);
  try {
    const envelopes = log.envelopes().sort((left, right) => left.version - right.version);
    assert.equal(envelopes.length, 2);
    assert.equal(envelopes[0].version, 1);
    assert.equal(envelopes[0].epoch, undefined);
    assert.equal(envelopes[1].version, 2);
    assert.equal(envelopes[1].epoch, 2);

    // Both open on the device that holds the epoch key, and the plaintext is frozen.
    const bodies = log.changes().map((change) => change.mutation.value.body);
    assert.deepEqual(bodies.sort(), ["after rotation", "before rotation"]);
  } finally {
    log.close();
  }
});

test("the committed registry pins the post-rotation shape", () => {
  const dir = path.join(FIXTURES, "sync-epoch-v2");
  const manager = new SyncDeviceManager(dir, FIXTURE_PASSPHRASE);
  try {
    const registry = manager.state();
    assert.equal(registry.body.version, 2);
    assert.equal(registry.body.epoch, 2);

    // The epoch key reaches the owner and nobody else.
    assert.deepEqual(
      registry.body.epochKeys.map((wrap) => wrap.deviceId),
      [OWNER],
    );

    const owner = registry.body.devices.find((record) => record.certificate.deviceId === OWNER);
    const revoked = registry.body.devices.find((record) => record.certificate.deviceId === REVOKED);
    assert.equal(owner.certificate.version, 2);
    assert.equal(owner.certificate.epoch, 2);
    assert.equal(Buffer.from(owner.certificate.keyAgreementKey, "base64").length, 44);
    assert.equal(revoked.certificate.epoch, 1, "the revoked device stays at the old epoch");
    assert.equal(revoked.revokedAfterSequence, 1);
  } finally {
    manager.close();
  }
});

test("the fixture vault caches no epoch key the revoked device could use", () => {
  const epochs = path.join(FIXTURES, "sync-epoch-v2", "documents", "sync", "identity", "epochs");
  assert.deepEqual(fs.readdirSync(epochs), ["2.key.enc"], "only the current epoch key is cached");
});

const BLOBS_FIXTURE = path.join(FIXTURES, "sync-attachment-blobs-v3");
const blobsManifest = JSON.parse(fs.readFileSync(path.join(BLOBS_FIXTURE, "manifest.json"), "utf8"));

test("the committed attachment blob fixture pins the version 3 manifest body", () => {
  const log = new SyncChangeLog(path.join(BLOBS_FIXTURE, "source"), FIXTURE_PASSPHRASE);
  try {
    const changes = log.changes();
    assert.equal(changes.length, blobsManifest.changeCount);
    const attachment = changes.find((change) => change.mutation.objectType === "attachment");

    // A version 3 body is authorized exactly like a version 2 body, and this
    // build must keep reading it.
    assert.equal(attachment.version, 3);
    assert.equal(attachment.authorization.certificateSerial, 1);
    assert.equal(attachment.mutation.objectId, blobsManifest.attachmentId);

    // The bytes are not in the change: the snapshot is a manifest.
    const snapshot = parseAttachmentSnapshot(attachment.mutation.value);
    assert.equal(snapshot.data, undefined);
    assert.equal(snapshot.filename, blobsManifest.filename);
    assert.equal(snapshot.mime, blobsManifest.mime);
    assert.equal(snapshot.size, blobsManifest.size);
    assert.equal(snapshot.chunks, 2);
    assert.equal(snapshot.chunks, snapshot.blobs.length);
    assert.deepEqual(snapshot.blobs, blobsManifest.blobs);

    // A blob id is the SHA-256 of the sealed chunk itself, which is what lets
    // the relay verify an upload while holding no key.
    const store = new SyncBlobStore(path.join(BLOBS_FIXTURE, "source"));
    for (const id of snapshot.blobs) {
      assert.match(id, /^[0-9a-f]{64}$/u);
      assert.equal(crypto.createHash("sha256").update(store.read(id)).digest("hex"), id);
    }
  } finally {
    log.close();
  }
});

test("a second device reassembles the committed attachment from its staged blobs", () => {
  const targetDir = fs.mkdtempSync(path.join(os.tmpdir(), "vault-brain-blob-fixture-"));
  fs.rmSync(targetDir, { recursive: true, force: true });
  fs.cpSync(path.join(BLOBS_FIXTURE, "target"), targetDir, { recursive: true });
  const sourceDir = path.join(BLOBS_FIXTURE, "source");

  const source = new SyncChangeLog(sourceDir, FIXTURE_PASSPHRASE);
  const target = new SyncedDocumentVault(targetDir, FIXTURE_PASSPHRASE);
  try {
    target.changeLog.import(source.envelopes());

    // Without the bytes the apply fails closed and writes nothing.
    assert.throws(
      () => target.applyResolved("attachment", blobsManifest.attachmentId),
      /2 of 2 attachment chunks are missing\./u,
    );
    assert.equal(target.listAttachments().length, 0);

    const from = new SyncBlobStore(sourceDir);
    const to = new SyncBlobStore(targetDir);
    for (const id of blobsManifest.blobs) to.put(id, from.read(id));

    target.applyResolved("attachment", blobsManifest.attachmentId);
    const recovered = target.getAttachment(blobsManifest.attachmentId);
    assert.equal(recovered.info.filename, blobsManifest.filename);
    assert.equal(recovered.data.length, blobsManifest.size);
    assert.equal(crypto.createHash("sha256").update(recovered.data).digest("hex"), blobsManifest.sha256);
  } finally {
    source.close();
    target.lock();
    fs.rmSync(targetDir, { recursive: true, force: true });
  }
});

test("a device signature covers the change body version, not a pinned literal", () => {
  const dir = path.join(BLOBS_FIXTURE, "source");
  const log = new SyncChangeLog(dir, FIXTURE_PASSPHRASE);
  const manager = new SyncDeviceManager(dir, FIXTURE_PASSPHRASE);
  try {
    const attachment = log.changes().find((change) => change.mutation.objectType === "attachment");
    assert.equal(attachment.version, 3);

    const record = manager
      .state()
      .body.devices.find((device) => device.certificate.deviceId === attachment.deviceId);
    const publicKey = crypto.createPublicKey({
      key: Buffer.from(record.certificate.publicKey, "base64"),
      format: "der",
      type: "spki",
    });
    const signature = Buffer.from(attachment.authorization.signature, "base64");
    const payloadAt = (version) =>
      Buffer.from(
        canonicalSyncJson({
          version,
          deviceId: attachment.deviceId,
          sequence: attachment.sequence,
          previousDeviceChange: attachment.previousDeviceChange,
          parents: attachment.parents,
          createdAt: attachment.createdAt,
          mutation: attachment.mutation,
          authorization: { certificateSerial: attachment.authorization.certificateSerial },
        }),
        "utf8",
      );

    assert.equal(crypto.verify(null, payloadAt(3), publicKey, signature), true);

    // Relabelling the body as version 2 must break the signature. While the
    // payload pinned a literal 2, this verified, and the body version rested on
    // the change id alone -- which only a holder of syncChangeKey can check.
    assert.equal(crypto.verify(null, payloadAt(2), publicKey, signature), false);
  } finally {
    manager.close();
    log.close();
  }
});
