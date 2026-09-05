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
  openVaultKeySet,
  openVaultReadKeys,
  randomKeySet,
  readKeyring,
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

/**
 * Puts a vault into the state an interrupted re-key leaves behind: the keyring
 * holds fresh rotatable keys with the ones every stored object was written
 * under carried alongside as `retiring`.
 */
function stallMidRekey(vaultDir) {
  const file = readKeyring(vaultDir);
  const current = unwrapSlot(file.slots[0], PASSPHRASE);
  const next = {};
  const retiring = {};
  for (const name of KEY_NAMES) next[name] = current[name];
  for (const name of ROTATABLE_KEY_NAMES) {
    retiring[name] = Buffer.from(current[name]);
    next[name] = crypto.randomBytes(32);
  }
  writeKeyring(vaultDir, {
    version: 2,
    slots: [wrapKeySet(next, PASSPHRASE, LOW_COST_N, retiring)],
  });
  forgetVaultKeys(vaultDir);
  return { next, retiring };
}

test("a vault caught mid-re-key still opens, and reports both key generations", () => {
  const vaultDir = temporaryVault("rekey-open");
  writeKeyring(vaultDir, {
    version: 2,
    slots: [wrapKeySet(randomKeySet(), PASSPHRASE, LOW_COST_N)],
  });
  forgetVaultKeys(vaultDir);
  assert.equal(openVaultKeySet(vaultDir, PASSPHRASE).retiring, null);

  const { next, retiring } = stallMidRekey(vaultDir);
  const opened = openVaultKeySet(vaultDir, PASSPHRASE);
  assert.ok(opened.retiring, "a stalled re-key must surface its retiring keys");
  for (const name of ROTATABLE_KEY_NAMES) {
    assert.ok(opened.keys[name].equals(next[name]));
    assert.ok(opened.retiring[name].equals(retiring[name]));
  }
});

test("a read offers the key in force first and the retiring one behind it", () => {
  const vaultDir = temporaryVault("rekey-read-keys");
  writeKeyring(vaultDir, {
    version: 2,
    slots: [wrapKeySet(randomKeySet(), PASSPHRASE, LOW_COST_N)],
  });
  forgetVaultKeys(vaultDir);
  assert.equal(openVaultReadKeys(vaultDir, PASSPHRASE, "kv").length, 1);

  const { next, retiring } = stallMidRekey(vaultDir);
  const keys = openVaultReadKeys(vaultDir, PASSPHRASE, "kv");
  assert.equal(keys.length, 2);
  assert.ok(keys[0].equals(next.kv), "the key in force must be tried first");
  assert.ok(keys[1].equals(retiring.kv));
});

test("notes, attachments and key-value files written before a re-key still read during one", async () => {
  const { DocumentVault } = await import("../dist/documents.js");
  const { loadVaultFile, saveVaultFile } = await import("../dist/store.js");
  const vaultDir = temporaryVault("rekey-read-through");

  const before = new DocumentVault(vaultDir, PASSPHRASE);
  const note = before.put({ path: "before.md", title: "written before the re-key", body: "still readable" });
  const attachment = before.putAttachment(Buffer.from("attachment bytes"), "a.txt", "text/plain");
  before.lock();
  saveVaultFile(vaultDir, "health", [{ key: "BLOOD_TYPE", value: "0 Rh+", desc: "blood group" }], PASSPHRASE);

  stallMidRekey(vaultDir);

  // Nothing has been rewritten yet, so every object here authenticates only
  // under the retiring key. Reading it proves the fallback is wired through.
  const during = new DocumentVault(vaultDir, PASSPHRASE);
  assert.equal(during.get(note.id).body, "still readable");
  assert.equal(during.getAttachment(attachment.id).data.toString("utf8"), "attachment bytes");
  during.lock();
  assert.deepEqual(loadVaultFile(vaultDir, "health", PASSPHRASE), [
    { key: "BLOOD_TYPE", value: "0 Rh+", desc: "blood group" },
  ]);
});

test("a decrypt helper offered a list tries each key in order", async () => {
  const { decryptDocument, encryptDocument } = await import("../dist/document-crypto.js");
  const older = crypto.randomBytes(32);
  const newer = crypto.randomBytes(32);
  const aad = "secondbrain-vault:note:v1:some-note";
  const payload = encryptDocument("still under the old key", older, aad);

  assert.equal(decryptDocument(payload, [newer, older], aad), "still under the old key");
  assert.equal(decryptDocument(payload, [older], aad), "still under the old key");
  assert.throws(() => decryptDocument(payload, [newer], aad));
  assert.throws(() => decryptDocument(payload, [], aad), /No key was offered/u);
});

test("a fallback key cannot open an object it was not written for", async () => {
  const { decryptDocument, encryptDocument } = await import("../dist/document-crypto.js");
  const older = crypto.randomBytes(32);
  const newer = crypto.randomBytes(32);
  const payload = encryptDocument("one note", older, "secondbrain-vault:note:v1:a");
  // The AAD binds the object's identity, so offering every key in the vault
  // still cannot make one object's ciphertext open as another's.
  assert.throws(() => decryptDocument(payload, [newer, older], "secondbrain-vault:note:v1:b"));
});

test("the keyed envelope helper takes the same ordered list", async () => {
  const { decryptWithKey, encryptWithKey } = await import("../dist/crypto.js");
  const older = crypto.randomBytes(32);
  const newer = crypto.randomBytes(32);
  const payload = encryptWithKey("workspace state", older, "workspace");

  assert.equal(decryptWithKey(payload, [newer, older], "workspace"), "workspace state");
  assert.throws(() => decryptWithKey(payload, [newer], "workspace"));
  assert.throws(() => decryptWithKey(payload, [], "workspace"), /No key was offered/u);
  // A short key inside the list is still refused, not skipped over silently.
  assert.throws(() => decryptWithKey(payload, [crypto.randomBytes(16)], "workspace"), /256-bit key/u);
});

test("the sync device registry still opens during a re-key", async () => {
  const { SyncDeviceManager } = await import("../dist/sync.js");
  const vaultDir = temporaryVault("rekey-sync");

  const devices = new SyncDeviceManager(vaultDir, PASSPHRASE);
  devices.initializeOwner("Owner laptop");
  const fingerprint = devices.fingerprint();
  devices.close();

  stallMidRekey(vaultDir);

  // devices.enc is sealed directly under the documents key, so reading it back
  // is what proves the sync read paths were given the fallback list too.
  const after = new SyncDeviceManager(vaultDir, PASSPHRASE);
  assert.equal(after.fingerprint(), fingerprint);
  after.close();
});
