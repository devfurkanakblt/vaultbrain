import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  EPOCH_KEY_BYTES,
  agreementPublicKeyFromBase64,
  exportAgreementPublicKey,
  generateAgreementKeyPair,
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
