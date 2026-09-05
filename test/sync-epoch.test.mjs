import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { openDocumentKey } from "../dist/document-crypto.js";
import {
  EPOCH_KEY_BYTES,
  agreementPublicKeyFromBase64,
  exportAgreementPublicKey,
  generateAgreementKeyPair,
  readEpochKey,
  saveEpochKey,
  unwrapEpochKey,
  validateEpochKeyWrap,
  wrapEpochKey,
} from "../dist/sync-epoch.js";

const DEVICE_A = "11111111-1111-4111-8111-111111111111";
const DEVICE_B = "22222222-2222-4222-8222-222222222222";

test("an epoch key round-trips to the intended device only", () => {
  const alice = generateAgreementKeyPair();
  const bob = generateAgreementKeyPair();
  const epochKey = crypto.randomBytes(EPOCH_KEY_BYTES);

  const wrap = wrapEpochKey(epochKey, 2, DEVICE_A, alice.publicKey);
  assert.equal(wrap.deviceId, DEVICE_A);
  assert.deepEqual(unwrapEpochKey(wrap, 2, DEVICE_A, alice.privateKey), epochKey);

  // A different device's private key cannot open it.
  assert.throws(() => unwrapEpochKey(wrap, 2, DEVICE_A, bob.privateKey));
});

test("a wrap is bound to its epoch and device and cannot be replayed", () => {
  const alice = generateAgreementKeyPair();
  const epochKey = crypto.randomBytes(EPOCH_KEY_BYTES);
  const wrap = wrapEpochKey(epochKey, 2, DEVICE_A, alice.publicKey);

  // Same ciphertext, claimed for a later epoch: the AAD no longer matches.
  assert.throws(() => unwrapEpochKey(wrap, 3, DEVICE_A, alice.privateKey));
  // Same ciphertext, relabelled for another device: also refused.
  assert.throws(() => unwrapEpochKey({ ...wrap, deviceId: DEVICE_B }, 2, DEVICE_B, alice.privateKey));
});

test("every wrap of the same key uses a fresh ephemeral key and nonce", () => {
  const alice = generateAgreementKeyPair();
  const epochKey = crypto.randomBytes(EPOCH_KEY_BYTES);
  const first = wrapEpochKey(epochKey, 2, DEVICE_A, alice.publicKey);
  const second = wrapEpochKey(epochKey, 2, DEVICE_A, alice.publicKey);
  assert.notEqual(first.ephemeralPublicKey, second.ephemeralPublicKey);
  assert.notEqual(first.iv, second.iv);
  assert.notEqual(first.ciphertext, second.ciphertext);
});

test("agreement keys are X25519 and structurally validated", () => {
  const pair = generateAgreementKeyPair();
  const encoded = exportAgreementPublicKey(pair.publicKey);
  assert.equal(Buffer.from(encoded, "base64").length, 44);
  assert.equal(agreementPublicKeyFromBase64(encoded, "test key").asymmetricKeyType, "x25519");

  // An Ed25519 key is the same 44-byte SPKI length and must still be rejected.
  const signing = crypto.generateKeyPairSync("ed25519");
  const ed = signing.publicKey.export({ format: "der", type: "spki" }).toString("base64");
  assert.throws(() => agreementPublicKeyFromBase64(ed, "test key"), /must be an X25519 public key/u);
});

test("malformed wraps are rejected before any cryptographic work", () => {
  const alice = generateAgreementKeyPair();
  const wrap = wrapEpochKey(crypto.randomBytes(EPOCH_KEY_BYTES), 2, DEVICE_A, alice.publicKey);
  assert.deepEqual(validateEpochKeyWrap(wrap), wrap);
  assert.throws(() => validateEpochKeyWrap({ ...wrap, deviceId: "not-a-uuid" }), /device ID/u);
  assert.throws(() => validateEpochKeyWrap({ ...wrap, iv: "AAAA" }), /nonce/u);
  assert.throws(() => validateEpochKeyWrap({ ...wrap, authTag: "AAAA" }), /authentication tag/u);
});

test("unwrapEpochKey refuses epoch 1 and below before touching key material", () => {
  const alice = generateAgreementKeyPair();
  const wrap = wrapEpochKey(crypto.randomBytes(EPOCH_KEY_BYTES), 2, DEVICE_A, alice.publicKey);

  // A malformed wrap (bad device ID) would normally fail structural validation
  // first; using a below-epoch check with an otherwise-valid wrap proves the
  // epoch guard runs before validateEpochKeyWrap or any decryption.
  assert.throws(() => unwrapEpochKey(wrap, 1, DEVICE_A, alice.privateKey), /epoch 2 and above/u);
  assert.throws(() => unwrapEpochKey(wrap, 0, DEVICE_A, alice.privateKey), /epoch 2 and above/u);
  assert.throws(() => unwrapEpochKey(wrap, -1, DEVICE_A, alice.privateKey), /epoch 2 and above/u);

  // The guard trips even when the wrap itself is structurally invalid, showing
  // it runs strictly before validateEpochKeyWrap.
  assert.throws(
    () => unwrapEpochKey({ ...wrap, deviceId: "not-a-uuid" }, 1, DEVICE_A, alice.privateKey),
    /epoch 2 and above/u,
  );
});

test("epoch keys persist under the master key and refuse epoch 1", () => {
  const vaultDir = fs.mkdtempSync(path.join(os.tmpdir(), "secondbrain-epoch-store-"));
  const session = openDocumentKey(vaultDir, "epoch-store-test-passphrase");
  const epochKey = crypto.randomBytes(EPOCH_KEY_BYTES);

  assert.equal(readEpochKey(session.rootDir, session.key, 2), undefined, "an unknown epoch reads as absent");
  saveEpochKey(session.rootDir, session.key, 2, epochKey);
  assert.deepEqual(readEpochKey(session.rootDir, session.key, 2), epochKey);

  // Epoch 1 is the master-key epoch and never has a stored key.
  assert.throws(() => saveEpochKey(session.rootDir, session.key, 1, epochKey), /epoch 2 and above/u);
  assert.throws(() => readEpochKey(session.rootDir, session.key, 1), /epoch 2 and above/u);

  // The stored file is ciphertext, not the raw key.
  const stored = fs.readFileSync(path.join(session.rootDir, "sync", "identity", "epochs", "2.key.enc"), "utf8");
  assert.doesNotMatch(stored, new RegExp(epochKey.toString("base64").slice(0, 16), "u"));
});
