import assert from "node:assert/strict";
import test from "node:test";

import {
  DEFAULT_SCRYPT_N,
  KEY_NAMES,
  randomKeySet,
  unwrapSlot,
  wrapKeySet,
} from "../dist/keyring.js";

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
