import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { AAD, FORMAT_COMPATIBILITY, VAULT_FORMAT_VERSION, canonicalBase64 } from "../dist/format-version.js";
import { SyncChangeLog, SyncDeviceManager } from "../dist/sync.js";

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
