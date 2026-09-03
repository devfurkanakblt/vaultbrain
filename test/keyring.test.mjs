import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  DEFAULT_SCRYPT_N,
  KEY_NAMES,
  detectVaultFormat,
  forgetVaultKeys,
  openVaultKeys,
  randomKeySet,
  unwrapSlot,
  wrapKeySet,
  writeKeyring,
} from "../dist/keyring.js";

import { decrypt, decryptWithKey, encrypt, encryptWithKey, envelopeVersion } from "../dist/crypto.js";
import { loadVaultFile, saveVaultFile, vaultFileEnvelopeVersion } from "../dist/store.js";
import { addGrant, emptyGrantFile, loadGrants, saveGrants } from "../dist/grants.js";
import { appendAudit, verifyAudit } from "../dist/audit.js";
import { openDocumentKey } from "../dist/document-crypto.js";
import { DocumentVault } from "../dist/documents.js";
import { SyncChangeLog } from "../dist/sync/change-log.js";
import { openSyncChange, sealSyncChange } from "../dist/sync/protocol.js";
import { SyncLocalTransaction, SyncApplyReceiptStore } from "../dist/sync/transaction.js";

const PASSPHRASE = "keyring-test-passphrase";

test("a wrapped keyset round-trips and records its own cost", () => {
  const keys = randomKeySet();
  const slot = wrapKeySet(keys, PASSPHRASE);

  assert.equal(slot.type, "passphrase");
  assert.equal(slot.kdf.name, "scrypt");
  assert.equal(slot.kdf.N, DEFAULT_SCRYPT_N);
  assert.equal(slot.kdf.r, 8);
  assert.equal(slot.kdf.p, 1);
  assert.match(slot.id, /^[0-9a-f-]{36}$/u);

  const opened = unwrapSlot(slot, PASSPHRASE);
  for (const name of KEY_NAMES) {
    assert.equal(opened[name].length, 32);
    assert.equal(opened[name].toString("base64"), keys[name].toString("base64"));
  }
});

test("a fresh keyset uses six independent keys", () => {
  const keys = randomKeySet();
  const seen = new Set(KEY_NAMES.map((name) => keys[name].toString("base64")));
  assert.equal(seen.size, KEY_NAMES.length);
});

test("a wrapped keyset rejects a wrong passphrase and a rewritten header", () => {
  const slot = wrapKeySet(randomKeySet(), PASSPHRASE);

  assert.throws(() => unwrapSlot(slot, "wrong passphrase"));

  // The recorded cost is authenticated, so it cannot be weakened for the next derivation.
  assert.throws(() => unwrapSlot({ ...slot, kdf: { ...slot.kdf, N: 2 ** 14 } }, PASSPHRASE));
  // Nor can a slot's ciphertext be transplanted onto another slot's identity.
  assert.throws(() => unwrapSlot({ ...slot, id: "00000000-0000-4000-8000-000000000000" }, PASSPHRASE));
  assert.throws(
    () => unwrapSlot({ ...slot, wrapped: { ...slot.wrapped, ciphertext: `${slot.wrapped.ciphertext.slice(0, -2)}AA` } }, PASSPHRASE),
  );
});

test("a hostile slot cannot dictate an unacceptable derivation", () => {
  const slot = wrapKeySet(randomKeySet(), PASSPHRASE);

  assert.throws(() => unwrapSlot({ ...slot, kdf: { ...slot.kdf, N: 2 ** 24 } }, PASSPHRASE), /unacceptable scrypt cost/u);
  assert.throws(() => unwrapSlot({ ...slot, kdf: { ...slot.kdf, N: 100000 } }, PASSPHRASE), /unacceptable scrypt cost/u);
  assert.throws(() => unwrapSlot({ ...slot, kdf: { ...slot.kdf, r: 0 } }, PASSPHRASE), /unacceptable scrypt block size/u);
  assert.throws(() => unwrapSlot({ ...slot, kdf: { ...slot.kdf, p: 99 } }, PASSPHRASE), /unacceptable scrypt parallelism/u);
  assert.throws(() => unwrapSlot({ ...slot, kdf: { ...slot.kdf, name: "pbkdf2" } }, PASSPHRASE), /Unsupported key-derivation/u);
  assert.throws(() => unwrapSlot({ ...slot, kdf: { ...slot.kdf, salt: "AAAA" } }, PASSPHRASE), /out-of-range salt/u);
});

test("a slot whose in-range N and r together imply a multi-gigabyte allocation is refused, quickly", () => {
  const slot = wrapKeySet(randomKeySet(), PASSPHRASE);
  // N = 2**20 and r = 32 are each individually within validateKdf's accepted
  // bounds, but together they would demand roughly 256 * 2**20 * 32 bytes
  // (~8 GiB) of scrypt memory if the ceiling scaled with what the file
  // declares. The fixed 256MB ceiling must make this fail fast instead.
  const hostile = { ...slot, kdf: { ...slot.kdf, N: 2 ** 20, r: 32 } };
  const start = Date.now();
  assert.throws(() => unwrapSlot(hostile, PASSPHRASE), /memory limit exceeded/iu);
  const elapsedMs = Date.now() - start;
  assert.ok(elapsedMs < 5000, `expected the hostile derivation to fail fast, took ${elapsedMs}ms`);
});

test("wrapping refuses an empty passphrase", () => {
  assert.throws(() => wrapKeySet(randomKeySet(), ""), /non-empty vault passphrase/u);
});

function tempVault() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "vault-brain-keyring-"));
}

function seedKeyring(vaultDir, passphrase) {
  const keys = randomKeySet();
  writeKeyring(vaultDir, { version: 2, slots: [wrapKeySet(keys, passphrase, 2 ** 14)] });
  forgetVaultKeys(vaultDir);
  return keys;
}

/**
 * What a pre-keyring release left in a vault directory. Writing it is what
 * makes this a legacy vault: since phase 7.2 the ordinary write paths create a
 * keyring on a directory holding no legacy material, so a test that needs the
 * pre-keyring format has to say so. `schema.json` is the inert marker — no
 * code path reads its contents, so seeding it changes the vault's format and
 * nothing else.
 */
function seedLegacyVault(vaultDir) {
  fs.mkdirSync(vaultDir, { recursive: true });
  fs.writeFileSync(path.join(vaultDir, "schema.json"), '{"version":1,"files":{}}\n');
}

test("an empty directory is an empty vault and gets no keyring implicitly", () => {
  const vault = tempVault();
  assert.equal(detectVaultFormat(vault), "empty");
  assert.equal(openVaultKeys(vault, PASSPHRASE), null);
  assert.equal(fs.existsSync(path.join(vault, "keyring.json")), false);
});

test("a vault holding legacy material is a legacy vault", () => {
  const vault = tempVault();
  fs.mkdirSync(path.join(vault, "documents"), { recursive: true });
  fs.writeFileSync(path.join(vault, "documents", "manifest.json"), "{}");
  assert.equal(detectVaultFormat(vault), "legacy");
  assert.equal(openVaultKeys(vault, PASSPHRASE), null);

  const kvOnly = tempVault();
  fs.writeFileSync(path.join(kvOnly, "health.kv.enc"), "{}");
  assert.equal(detectVaultFormat(kvOnly), "legacy");
});

test("a keyring vault resolves all six keys and rejects a wrong passphrase", () => {
  const vault = tempVault();
  const keys = seedKeyring(vault, PASSPHRASE);

  assert.equal(detectVaultFormat(vault), "keyring");
  const opened = openVaultKeys(vault, PASSPHRASE);
  assert.ok(opened);
  for (const name of KEY_NAMES) {
    assert.equal(opened[name].toString("base64"), keys[name].toString("base64"));
  }
  assert.throws(() => openVaultKeys(vault, "wrong passphrase"), /wrong passphrase/u);
});

test("each caller gets its own buffers, so zeroizing one session cannot blind another", () => {
  const vault = tempVault();
  const keys = seedKeyring(vault, PASSPHRASE);

  const first = openVaultKeys(vault, PASSPHRASE);
  first.documents.fill(0);

  const second = openVaultKeys(vault, PASSPHRASE);
  assert.equal(second.documents.toString("base64"), keys.documents.toString("base64"));
});

test("forgetVaultKeys drops the cached keyset", () => {
  const vault = tempVault();
  seedKeyring(vault, PASSPHRASE);
  assert.ok(openVaultKeys(vault, PASSPHRASE));

  fs.rmSync(path.join(vault, "keyring.json"));
  forgetVaultKeys(vault);
  assert.equal(openVaultKeys(vault, PASSPHRASE), null);
});

test("the keyed envelope binds its ciphertext to one file identity", () => {
  const key = crypto.randomBytes(32);
  const payload = encryptWithKey("BLOOD_TYPE=0 Rh+", key, "health");

  assert.equal(payload.version, 2);
  assert.equal(payload.cipher, "aes-256-gcm");
  assert.equal(payload.keyId, "kv");
  assert.equal(envelopeVersion(payload), 2);
  assert.equal(decryptWithKey(payload, key, "health"), "BLOOD_TYPE=0 Rh+");

  // Moving health.kv.enc onto finance.kv.enc must not decrypt.
  assert.throws(() => decryptWithKey(payload, key, "finance"));
  assert.throws(() => decryptWithKey(payload, crypto.randomBytes(32), "health"));
  assert.throws(() =>
    decryptWithKey({ ...payload, ciphertext: `${payload.ciphertext.slice(0, -2)}AA` }, key, "health"),
  );
});

test("the passphrase envelope refuses a keyed payload with a usable message", () => {
  const payload = encryptWithKey("secret", crypto.randomBytes(32), "health");
  assert.throws(() => decrypt(payload, PASSPHRASE), /keyring/u);
});

test("key-value files use the keyed envelope once a vault has a keyring", () => {
  const vault = tempVault();
  seedLegacyVault(vault);
  saveVaultFile(vault, "health", [{ key: "BLOOD_TYPE", value: "0 Rh+", desc: "blood group" }], PASSPHRASE);
  assert.equal(vaultFileEnvelopeVersion(vault, "health"), 1);

  seedKeyring(vault, PASSPHRASE);

  // A v1 file written before the keyring existed still opens.
  assert.deepEqual(loadVaultFile(vault, "health", PASSPHRASE), [
    { key: "BLOOD_TYPE", value: "0 Rh+", desc: "blood group" },
  ]);

  // The next write uses the keyset.
  saveVaultFile(vault, "health", [{ key: "BLOOD_TYPE", value: "A Rh-", desc: "blood group" }], PASSPHRASE);
  assert.equal(vaultFileEnvelopeVersion(vault, "health"), 2);
  assert.deepEqual(loadVaultFile(vault, "health", PASSPHRASE), [
    { key: "BLOOD_TYPE", value: "A Rh-", desc: "blood group" },
  ]);
});

test("a keyed key-value file cannot be renamed into another category", () => {
  const vault = tempVault();
  seedKeyring(vault, PASSPHRASE);
  saveVaultFile(vault, "health", [{ key: "BLOOD_TYPE", value: "0 Rh+", desc: "blood group" }], PASSPHRASE);

  fs.copyFileSync(path.join(vault, "health.kv.enc"), path.join(vault, "finance.kv.enc"));
  assert.throws(() => loadVaultFile(vault, "finance", PASSPHRASE));
});

test("grant files use the keyed envelope once a vault has a keyring", () => {
  const vault = tempVault();
  seedLegacyVault(vault);
  saveGrants(vault, emptyGrantFile(), PASSPHRASE);
  const payload = JSON.parse(fs.readFileSync(path.join(vault, "grants.enc"), "utf8"));
  assert.equal(envelopeVersion(payload), 1);

  seedKeyring(vault, PASSPHRASE);

  // A v1 file written before the keyring existed still opens.
  assert.deepEqual(loadGrants(vault, PASSPHRASE), emptyGrantFile());

  // The next write uses the keyset.
  const grant = addGrant(
    vault,
    {
      agent: "test-agent",
      scopes: [{ file: "health", keys: ["*"], actions: ["discover", "resolve", "store"], redact: "none" }],
    },
    PASSPHRASE,
  );
  const updatedPayload = JSON.parse(fs.readFileSync(path.join(vault, "grants.enc"), "utf8"));
  assert.equal(updatedPayload.version, 2);
  const loaded = loadGrants(vault, PASSPHRASE);
  assert.ok(loaded);
  assert.equal(loaded.grants.length, 1);
  assert.equal(loaded.grants[0].id, grant.id);
});

test("a v1 grant file written before keyring exists still opens in a vault with a keyring", () => {
  const vault = tempVault();
  // Write a v1 envelope grant file before the keyring exists
  const grantFile = emptyGrantFile();
  const v1Payload = encrypt(JSON.stringify(grantFile), PASSPHRASE);
  fs.writeFileSync(path.join(vault, "grants.enc"), JSON.stringify(v1Payload, null, 2));
  assert.equal(envelopeVersion(v1Payload), 1);

  seedKeyring(vault, PASSPHRASE);

  // The v1 file can still be loaded after the keyring is added.
  const loaded = loadGrants(vault, PASSPHRASE);
  assert.deepEqual(loaded, grantFile);
});

test("a keyed grant file throws a clear error when the keyring is missing", () => {
  const vault = tempVault();
  seedKeyring(vault, PASSPHRASE);

  // Save a grant, which uses the keyed envelope.
  addGrant(
    vault,
    {
      agent: "test-agent",
      scopes: [{ file: "health", keys: ["*"], actions: ["discover"], redact: "none" }],
    },
    PASSPHRASE,
  );

  // Delete the keyring and forget the cached keys.
  fs.rmSync(path.join(vault, "keyring.json"));
  forgetVaultKeys(vault);

  // Loading the keyed grant file without a keyring must throw with a clear message.
  assert.throws(() => loadGrants(vault, PASSPHRASE), /keyring-encrypted but the vault has no readable keyring/u);
});

test("a keyed key-value file throws a clear error when the keyring is missing", () => {
  const vault = tempVault();
  seedKeyring(vault, PASSPHRASE);

  // Save a key-value file, which uses the keyed envelope.
  saveVaultFile(vault, "health", [{ key: "BLOOD_TYPE", value: "0 Rh+", desc: "blood group" }], PASSPHRASE);
  assert.equal(vaultFileEnvelopeVersion(vault, "health"), 2);

  // Delete the keyring and forget the cached keys.
  fs.rmSync(path.join(vault, "keyring.json"));
  forgetVaultKeys(vault);

  // Loading the keyed key-value file without a keyring must throw with a clear message.
  assert.throws(() => loadVaultFile(vault, "health", PASSPHRASE), /keyring-encrypted but the vault has no readable keyring/u);
});

test("the audit chain keeps verifying after a keyring appears", () => {
  const vault = tempVault();
  appendAudit(vault, { actor: "cli-direct", file: "health", key: "BLOOD_TYPE" }, PASSPHRASE);
  assert.equal(verifyAudit(vault, PASSPHRASE).valid, true);

  seedKeyring(vault, PASSPHRASE);

  // The keyring's audit key is new material, so entries signed with the old
  // one no longer verify. Migration adopts the old key precisely to avoid
  // this; here we prove the two keys are genuinely distinct.
  assert.equal(verifyAudit(vault, PASSPHRASE).valid, false);

  const fresh = tempVault();
  seedKeyring(fresh, PASSPHRASE);
  appendAudit(fresh, { actor: "cli-direct", file: "health", key: "BLOOD_TYPE" }, PASSPHRASE);
  const verified = verifyAudit(fresh, PASSPHRASE);
  assert.equal(verified.valid, true);
  assert.equal(verified.signedEntries, 1);
  assert.equal(fs.existsSync(path.join(fresh, "audit.meta.json")), false);
});

test("a legacy session uses one key for content and identity, a keyring session does not", () => {
  const legacy = tempVault();
  seedLegacyVault(legacy);
  const legacySession = openDocumentKey(legacy, PASSPHRASE);
  assert.equal(legacySession.attachmentIdKey.toString("base64"), legacySession.key.toString("base64"));
  assert.equal(legacySession.syncChangeKey.toString("base64"), legacySession.key.toString("base64"));
  assert.equal(legacySession.syncEnvelopeKey.toString("base64"), legacySession.key.toString("base64"));

  const keyed = tempVault();
  const keys = seedKeyring(keyed, PASSPHRASE);
  const session = openDocumentKey(keyed, PASSPHRASE);
  assert.equal(session.key.toString("base64"), keys.documents.toString("base64"));
  assert.equal(session.attachmentIdKey.toString("base64"), keys.attachmentId.toString("base64"));
  assert.equal(session.syncChangeKey.toString("base64"), keys.syncChange.toString("base64"));
  assert.equal(session.syncEnvelopeKey.toString("base64"), keys.syncEnvelope.toString("base64"));
  assert.equal(session.manifest, null);
});

test("syncChange and syncEnvelope are independent: a change sealed with one pair does not open with a mismatched pair", () => {
  const vault = tempVault();
  const keys = seedKeyring(vault, PASSPHRASE);
  assert.notEqual(keys.syncChange.toString("base64"), keys.syncEnvelope.toString("base64"));

  const session = openDocumentKey(vault, PASSPHRASE);
  const correctKeys = { syncChangeKey: session.syncChangeKey, syncEnvelopeKey: session.syncEnvelopeKey };
  const body = {
    version: 1,
    deviceId: "11111111-1111-4111-8111-111111111111",
    sequence: 1,
    previousDeviceChange: null,
    parents: [],
    createdAt: "2026-09-03T00:00:00.000Z",
    mutation: {
      objectType: "note",
      objectId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      operation: "put",
      baseRevision: null,
      revision: 1,
      value: { title: "Plan", body: "keyring split" },
    },
  };
  const sealed = sealSyncChange(body, correctKeys);
  assert.deepEqual(openSyncChange(sealed, correctKeys).mutation.value, body.mutation.value);

  // Rotating only syncEnvelope, exactly what a future re-key does, must not
  // change the change's identity: the ID depends only on syncChangeKey.
  const rotatedEnvelope = { syncChangeKey: session.syncChangeKey, syncEnvelopeKey: crypto.randomBytes(32) };
  const resealed = sealSyncChange(body, rotatedEnvelope);
  assert.equal(resealed.id, sealed.id, "rotating syncEnvelope alone must not change the change ID");
  assert.notEqual(resealed.payload.ciphertext, sealed.payload.ciphertext);

  // A change sealed under one (syncChangeKey, syncEnvelopeKey) pair must not
  // open under a mismatched pair, in either direction.
  assert.throws(() => openSyncChange(sealed, rotatedEnvelope));
  const rotatedIdentity = { syncChangeKey: crypto.randomBytes(32), syncEnvelopeKey: session.syncEnvelopeKey };
  assert.throws(() => openSyncChange(sealed, rotatedIdentity), /does not match its content/u);

  session.key.fill(0);
  session.attachmentIdKey.fill(0);
  session.syncChangeKey.fill(0);
  session.syncEnvelopeKey.fill(0);
});

test("a keyring vault stores and reads attachments end to end", () => {
  const vault = tempVault();
  seedKeyring(vault, PASSPHRASE);
  const documents = new DocumentVault(vault, PASSPHRASE);
  const info = documents.putAttachment(Buffer.from("attachment bytes"), "note.txt", "text/plain");
  assert.equal(documents.getAttachment(info.id).data.toString("utf8"), "attachment bytes");
  documents.lock();
});

test("locking zeroizes every key the session was handed", () => {
  const vault = tempVault();
  seedKeyring(vault, PASSPHRASE);
  const documents = new DocumentVault(vault, PASSPHRASE);
  documents.lock();
  // A second vault opened afterwards must still work: the cache handed out copies.
  const second = new DocumentVault(vault, PASSPHRASE);
  assert.deepEqual(second.list(), []);
  second.lock();
  // Verify that all four keys were zeroized
  assert.ok(documents.session.key.every((byte) => byte === 0), "key should be zeroed");
  assert.ok(documents.session.attachmentIdKey.every((byte) => byte === 0), "attachmentIdKey should be zeroed");
  assert.ok(documents.session.syncChangeKey.every((byte) => byte === 0), "syncChangeKey should be zeroed");
  assert.ok(documents.session.syncEnvelopeKey.every((byte) => byte === 0), "syncEnvelopeKey should be zeroed");
});

test("SyncChangeLog.close() zeroizes all keys", () => {
  const vault = tempVault();
  seedKeyring(vault, PASSPHRASE);
  const log = new SyncChangeLog(vault, PASSPHRASE);
  log.close();
  // Verify that all four keys were zeroized
  assert.ok(log.session.key.every((byte) => byte === 0), "key should be zeroed");
  assert.ok(log.session.attachmentIdKey.every((byte) => byte === 0), "attachmentIdKey should be zeroed");
  assert.ok(log.session.syncChangeKey.every((byte) => byte === 0), "syncChangeKey should be zeroed");
  assert.ok(log.session.syncEnvelopeKey.every((byte) => byte === 0), "syncEnvelopeKey should be zeroed");
});

test("SyncLocalTransaction.close() zeroizes all keys", () => {
  const vault = tempVault();
  seedKeyring(vault, PASSPHRASE);
  const transaction = new SyncLocalTransaction(vault, PASSPHRASE);
  transaction.close();
  // Verify that all four keys were zeroized
  assert.ok(transaction.session.key.every((byte) => byte === 0), "key should be zeroed");
  assert.ok(transaction.session.attachmentIdKey.every((byte) => byte === 0), "attachmentIdKey should be zeroed");
  assert.ok(transaction.session.syncChangeKey.every((byte) => byte === 0), "syncChangeKey should be zeroed");
  assert.ok(transaction.session.syncEnvelopeKey.every((byte) => byte === 0), "syncEnvelopeKey should be zeroed");
});

test("DocumentVault.lock() drops the module-level keyset cache, not just its own copies", () => {
  const vault = tempVault();
  seedKeyring(vault, PASSPHRASE);
  const documents = new DocumentVault(vault, PASSPHRASE);
  // Prime the module-level cache independently, the way any other caller
  // (store.ts, grants.ts, audit.ts) would.
  assert.ok(openVaultKeys(vault, PASSPHRASE));

  documents.lock();

  // The observable proxy for "the cache no longer holds this vault's keys":
  // delete keyring.json, then openVaultKeys must re-read the file (and so
  // return null) instead of serving a cached keyset.
  fs.rmSync(path.join(vault, "keyring.json"));
  assert.equal(openVaultKeys(vault, PASSPHRASE), null);
});

test("SyncApplyReceiptStore.close() zeroizes all keys", () => {
  const vault = tempVault();
  seedKeyring(vault, PASSPHRASE);
  const store = new SyncApplyReceiptStore(vault, PASSPHRASE);
  store.close();
  // Verify that all four keys were zeroized
  assert.ok(store.session.key.every((byte) => byte === 0), "key should be zeroed");
  assert.ok(store.session.attachmentIdKey.every((byte) => byte === 0), "attachmentIdKey should be zeroed");
  assert.ok(store.session.syncChangeKey.every((byte) => byte === 0), "syncChangeKey should be zeroed");
  assert.ok(store.session.syncEnvelopeKey.every((byte) => byte === 0), "syncEnvelopeKey should be zeroed");
});

test("a version 2 manifest without a keyring fails closed", () => {
  const vault = tempVault();
  fs.mkdirSync(path.join(vault, "documents"), { recursive: true });
  fs.writeFileSync(path.join(vault, "documents", "manifest.json"), JSON.stringify({ version: 2, keyring: true }));
  assert.throws(() => openDocumentKey(vault, PASSPHRASE), /keyring/u);
});
