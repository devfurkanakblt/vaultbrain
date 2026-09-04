import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { appendAudit, verifyAudit } from "../dist/audit.js";
import { DocumentVault } from "../dist/documents.js";
import {
  DEFAULT_SCRYPT_N,
  forgetVaultKeys,
  openVaultKeys,
  randomKeySet,
  wrapKeySet,
  writeKeyring,
} from "../dist/keyring.js";
import { accountFor, setKeychainBackend, updateRememberedPassphrase } from "../dist/keychain.js";
import { changeVaultPassphrase, MIN_PASSPHRASE_LENGTH } from "../dist/keyring-passphrase.js";
import { loadVaultFile, upsertEntry } from "../dist/store.js";

const PASSPHRASE = "phase-73-current-passphrase";
const NEW_PASSPHRASE = "phase-73-replacement-passphrase";

function tempDir(label = "passphrase") {
  return fs.mkdtempSync(path.join(os.tmpdir(), `vault-brain-${label}-`));
}

/** A keyring-native vault holding one note, one attachment and one key-value entry. */
function seedVault(passphrase = PASSPHRASE) {
  const dir = tempDir();
  const vault = new DocumentVault(dir, passphrase);
  vault.put({ path: "Atlas/First.md", title: "First", body: "# First\n\nbody" });
  const attachment = vault.putAttachment(Buffer.from("phase 7.3 attachment"), "note.bin");
  vault.lock();
  upsertEntry(dir, "health", "BLOOD_TYPE", "0 Rh+", "blood group", passphrase);
  appendAudit(dir, { actor: "cli-direct-write", file: "health", key: "BLOOD_TYPE" }, passphrase);
  return { dir, attachmentId: attachment.id };
}

function readSlots(dir) {
  return JSON.parse(fs.readFileSync(path.join(dir, "keyring.json"), "utf8")).slots;
}

/**
 * SHA-256 of every file under `<dir>/documents/`, keyed by its path relative
 * to that directory (POSIX-style separators, so the map compares equal
 * regardless of platform). Used to prove no object's ciphertext moved.
 */
function hashDocuments(dir) {
  const root = path.join(dir, "documents");
  const hashes = {};
  if (!fs.existsSync(root)) return hashes;

  const walk = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile()) {
        const relative = path.relative(root, full).split(path.sep).join("/");
        hashes[relative] = crypto.createHash("sha256").update(fs.readFileSync(full)).digest("hex");
      }
    }
  };
  walk(root);
  return hashes;
}

test("the new passphrase opens the vault and the old one no longer does", () => {
  const { dir } = seedVault();

  // Warm the in-process keyset cache under the old passphrase first, so this
  // also proves the change drops it rather than serving a stale keyset.
  assert.ok(openVaultKeys(dir, PASSPHRASE));

  const report = changeVaultPassphrase(dir, PASSPHRASE, NEW_PASSPHRASE);
  assert.equal(report.slotsRewritten, 1);
  assert.equal(report.slotsPreserved, 0);

  assert.throws(() => openVaultKeys(dir, PASSPHRASE), /wrong passphrase/iu);
  assert.ok(openVaultKeys(dir, NEW_PASSPHRASE));

  // And again from disk, with nothing cached at all.
  forgetVaultKeys();
  assert.ok(openVaultKeys(dir, NEW_PASSPHRASE));
  assert.throws(() => openVaultKeys(dir, PASSPHRASE), /wrong passphrase/iu);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("no object is re-encrypted: notes, attachments and key-value entries survive unchanged", () => {
  const { dir, attachmentId } = seedVault();
  const before = hashDocuments(dir);
  assert.notEqual(Object.keys(before).length, 0, "the seeded vault must have documents to compare");

  changeVaultPassphrase(dir, PASSPHRASE, NEW_PASSPHRASE);
  forgetVaultKeys();

  assert.deepEqual(
    hashDocuments(dir),
    before,
    "every object under documents/ must be byte-identical: nothing was re-encrypted",
  );

  const vault = new DocumentVault(dir, NEW_PASSPHRASE);
  assert.deepEqual(
    vault.list().map((note) => note.path),
    ["Atlas/First.md"],
  );
  assert.deepEqual(
    vault.listAttachments().map((info) => info.id),
    [attachmentId],
    "the attachment content address must not move",
  );
  vault.lock();
  assert.equal(loadVaultFile(dir, "health", NEW_PASSPHRASE)[0].value, "0 Rh+");
  assert.equal(
    verifyAudit(dir, NEW_PASSPHRASE).valid,
    true,
    "the audit key is permanent, so the pre-change chain must still verify",
  );

  fs.rmSync(dir, { recursive: true, force: true });
});

test("the change raises an old vault's KDF cost to the current default", () => {
  const dir = tempDir("cost");
  const keys = randomKeySet();
  // 2**14 is the lowest cost the format accepts, which keeps this test fast.
  writeKeyring(dir, { version: 2, slots: [wrapKeySet(keys, PASSPHRASE, 2 ** 14)] });
  const oldSalt = readSlots(dir)[0].kdf.salt;

  const report = changeVaultPassphrase(dir, PASSPHRASE, NEW_PASSPHRASE);

  assert.equal(report.previousN, 2 ** 14);
  assert.equal(report.newN, DEFAULT_SCRYPT_N);
  const [slot] = readSlots(dir);
  assert.equal(slot.kdf.N, DEFAULT_SCRYPT_N);
  assert.notEqual(slot.kdf.salt, oldSalt, "a re-wrap must draw a fresh salt");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("a slot the current passphrase cannot open is preserved untouched", () => {
  const dir = tempDir("slots");
  const keys = randomKeySet();
  const recovery = wrapKeySet(keys, "recovery-slot-passphrase", 2 ** 14);
  writeKeyring(dir, { version: 2, slots: [wrapKeySet(keys, PASSPHRASE, 2 ** 14), recovery] });

  const report = changeVaultPassphrase(dir, PASSPHRASE, NEW_PASSPHRASE);

  assert.equal(report.slotsRewritten, 1);
  assert.equal(report.slotsPreserved, 1);
  const slots = readSlots(dir);
  assert.deepEqual(
    slots.find((slot) => slot.id === recovery.id),
    recovery,
    "the foreign slot must survive byte for byte",
  );
  forgetVaultKeys();
  assert.ok(openVaultKeys(dir, "recovery-slot-passphrase"));

  fs.rmSync(dir, { recursive: true, force: true });
});

test("every refusal leaves keyring.json byte-identical", () => {
  const { dir } = seedVault();
  const before = fs.readFileSync(path.join(dir, "keyring.json"));

  assert.throws(() => changeVaultPassphrase(dir, PASSPHRASE, "short"), /at least 12 characters/iu);
  assert.throws(
    () => changeVaultPassphrase(dir, PASSPHRASE, PASSPHRASE),
    /same as the current one/iu,
  );
  assert.throws(
    () => changeVaultPassphrase(dir, "wrong-current-passphrase", NEW_PASSPHRASE),
    /wrong passphrase/iu,
  );

  assert.deepEqual(fs.readFileSync(path.join(dir, "keyring.json")), before);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("a legacy vault is refused and pointed at vbrain migrate", () => {
  const dir = tempDir("legacy");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "schema.json"), '{"version":1,"files":{}}\n');

  assert.throws(() => changeVaultPassphrase(dir, PASSPHRASE, NEW_PASSPHRASE), /vbrain migrate/u);
  assert.ok(!fs.existsSync(path.join(dir, "keyring.json")), "a refusal must not create a keyring");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("--allow-same-passphrase re-wraps at the current cost without changing the passphrase", () => {
  const dir = tempDir("same");
  const keys = randomKeySet();
  writeKeyring(dir, { version: 2, slots: [wrapKeySet(keys, PASSPHRASE, 2 ** 14)] });

  const report = changeVaultPassphrase(dir, PASSPHRASE, PASSPHRASE, { allowSamePassphrase: true });

  assert.equal(report.newN, DEFAULT_SCRYPT_N);
  assert.equal(readSlots(dir)[0].kdf.N, DEFAULT_SCRYPT_N);
  forgetVaultKeys();
  assert.ok(openVaultKeys(dir, PASSPHRASE));

  fs.rmSync(dir, { recursive: true, force: true });
});

test("the minimum length is the documented one", () => {
  assert.equal(MIN_PASSPHRASE_LENGTH, 12);
});

/** A fake credential store. `failOnStore` makes writes throw, as a locked keychain does. */
function fakeKeychain({ failOnStore = false } = {}) {
  const entries = new Map();
  return {
    entries,
    backend: {
      name: "fake",
      available: () => true,
      store(account, secret) {
        if (failOnStore) throw new Error("credential store is locked");
        entries.set(account, secret);
      },
      lookup: (account) => entries.get(account),
      forget: (account) => entries.delete(account),
    },

  };
}

test("a remembered passphrase is replaced with the new one", () => {
  const { dir } = seedVault();
  const fake = fakeKeychain();
  setKeychainBackend(fake.backend);
  try {
    fake.backend.store(accountFor(dir), PASSPHRASE);

    const result = updateRememberedPassphrase(dir, NEW_PASSPHRASE);

    assert.equal(result.updated, true);
    assert.equal(result.backend, "fake");
    assert.equal(result.error, undefined);
    assert.equal(fake.entries.get(accountFor(dir)), NEW_PASSPHRASE);
  } finally {
    setKeychainBackend(undefined);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a vault with nothing remembered is left alone", () => {
  const { dir } = seedVault();
  const fake = fakeKeychain();
  setKeychainBackend(fake.backend);
  try {
    const result = updateRememberedPassphrase(dir, NEW_PASSPHRASE);

    assert.equal(result.updated, false);
    assert.equal(result.error, undefined);
    assert.equal(fake.entries.size, 0, "nothing may be stored for a vault that had nothing");
  } finally {
    setKeychainBackend(undefined);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a store that refuses the write is reported rather than thrown", () => {
  const { dir } = seedVault();
  const fake = fakeKeychain({ failOnStore: true });
  setKeychainBackend(fake.backend);
  try {
    fake.entries.set(accountFor(dir), PASSPHRASE);

    const result = updateRememberedPassphrase(dir, NEW_PASSPHRASE);

    assert.equal(result.updated, false);
    assert.match(result.error ?? "", /locked/u);
  } finally {
    setKeychainBackend(undefined);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
