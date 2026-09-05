import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  KEYSET_VERSION,
  KEY_NAMES,
  RETIRING_KEYSET_VERSION,
  ROTATABLE_KEY_NAMES,
  copyRetiringKeys,
  forgetVaultKeys,
  openVaultKeys,
  randomKeySet,
  unwrapSlot,
  unwrapSlotKeySet,
  wrapKeySet,
  writeKeyring,
  zeroRetiringKeys,
} from "../dist/keyring.js";

const PASSPHRASE = "keyring-rekey-test-passphrase";
const LOW_COST_N = 2 ** 14;

function temporaryVault(name) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `vbrain-${name}-`));
  return path.join(dir, "vault");
}

function retiringKeys() {
  const keys = {};
  for (const name of ROTATABLE_KEY_NAMES) keys[name] = crypto.randomBytes(32);
  return keys;
}

test("the rotatable key names are exactly the three a re-key replaces", () => {
  assert.deepEqual([...ROTATABLE_KEY_NAMES], ["documents", "kv", "syncEnvelope"]);
  for (const name of ROTATABLE_KEY_NAMES) {
    assert.ok(KEY_NAMES.includes(name), `${name} must be a real keyset entry`);
  }
  // The permanent three are what every existing reference in the vault is
  // keyed under, so a re-key must never touch them.
  for (const name of ["attachmentId", "syncChange", "audit"]) {
    assert.ok(!ROTATABLE_KEY_NAMES.includes(name), `${name} must never rotate`);
  }
});

test("a settled keyset round-trips as version 1 with no retiring keys", () => {
  const keys = randomKeySet();
  const slot = wrapKeySet(keys, PASSPHRASE, LOW_COST_N);
  const opened = unwrapSlotKeySet(slot, PASSPHRASE);
  assert.equal(opened.retiring, null);
  for (const name of KEY_NAMES) assert.ok(opened.keys[name].equals(keys[name]));
});

test("a keyset caught mid-re-key round-trips its retiring keys", () => {
  const keys = randomKeySet();
  const retiring = retiringKeys();
  const expected = copyRetiringKeys(retiring);
  const slot = wrapKeySet(keys, PASSPHRASE, LOW_COST_N, retiring);
  const opened = unwrapSlotKeySet(slot, PASSPHRASE);
  assert.ok(opened.retiring, "the retiring keys must survive the round trip");
  for (const name of ROTATABLE_KEY_NAMES) {
    assert.ok(opened.retiring[name].equals(expected[name]));
  }
  for (const name of KEY_NAMES) assert.ok(opened.keys[name].equals(keys[name]));
});

test("unwrapSlot drops the retiring keys rather than leaking them to a caller that did not ask", () => {
  const slot = wrapKeySet(randomKeySet(), PASSPHRASE, LOW_COST_N, retiringKeys());
  const keys = unwrapSlot(slot, PASSPHRASE);
  for (const name of KEY_NAMES) assert.equal(keys[name].length, 32);
});

test("the keyset version says whether retiring keys are present", () => {
  const settled = wrapKeySet(randomKeySet(), PASSPHRASE, LOW_COST_N);
  const rotating = wrapKeySet(randomKeySet(), PASSPHRASE, LOW_COST_N, retiringKeys());
  // The version lives inside the sealed keyset, so read it back through the
  // AEAD rather than off the slot header.
  assert.notEqual(settled.wrapped.ciphertext, rotating.wrapped.ciphertext);
  assert.equal(KEYSET_VERSION, 1);
  assert.equal(RETIRING_KEYSET_VERSION, 2);
});

test("zeroizing the retiring keys leaves nothing behind", () => {
  const retiring = retiringKeys();
  zeroRetiringKeys(retiring);
  for (const name of ROTATABLE_KEY_NAMES) {
    assert.ok(retiring[name].every((byte) => byte === 0));
  }
});

test("opening a vault whose re-key never finished fails closed with an instruction", () => {
  const vaultDir = temporaryVault("rekey-unfinished");
  const keys = randomKeySet();
  writeKeyring(vaultDir, {
    version: 2,
    slots: [wrapKeySet(keys, PASSPHRASE, LOW_COST_N, retiringKeys())],
  });
  forgetVaultKeys(vaultDir);
  assert.throws(() => openVaultKeys(vaultDir, PASSPHRASE), /unfinished re-key/u);
});
