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

import { decrypt, decryptWithKey, encryptWithKey, envelopeVersion } from "../dist/crypto.js";

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
