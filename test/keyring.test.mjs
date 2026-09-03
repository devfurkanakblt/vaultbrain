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

test("a fresh keyset uses five independent keys", () => {
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

test("a keyring vault resolves all five keys and rejects a wrong passphrase", () => {
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
