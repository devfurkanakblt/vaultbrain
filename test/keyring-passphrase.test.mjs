import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

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
import {
  accountFor,
  forgetPassphrase,
  keychain,
  rememberPassphrase,
  setKeychainBackend,
  updateRememberedPassphrase,
} from "../dist/keychain.js";
import { changeVaultPassphrase } from "../dist/keyring-passphrase.js";
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
  assert.deepEqual(report.preserved, [
    { id: recovery.id, label: recovery.label, createdAt: recovery.createdAt, n: recovery.kdf.N },
  ]);
  const slots = readSlots(dir);
  assert.equal(slots.length, 2, "no slot may be dropped or added");
  assert.deepEqual(
    slots[1],
    recovery,
    "the foreign slot must survive byte for byte, still at its original index",
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

test("an 11-character new passphrase is refused and a 12-character one is accepted", () => {
  const { dir } = seedVault();

  assert.throws(
    () => changeVaultPassphrase(dir, PASSPHRASE, "a".repeat(11)),
    /at least 12 characters/iu,
  );

  const report = changeVaultPassphrase(dir, PASSPHRASE, "b".repeat(12));
  assert.equal(report.slotsRewritten, 1);
  forgetVaultKeys();
  assert.ok(openVaultKeys(dir, "b".repeat(12)));

  fs.rmSync(dir, { recursive: true, force: true });
});

test("two slots that both open under the current passphrase but carry different keysets are refused", () => {
  const dir = tempDir("mismatched-slots");
  const keysA = randomKeySet();
  const keysB = randomKeySet();
  writeKeyring(dir, {
    version: 2,
    slots: [wrapKeySet(keysA, PASSPHRASE, 2 ** 14), wrapKeySet(keysB, PASSPHRASE, 2 ** 14)],
  });
  const before = fs.readFileSync(path.join(dir, "keyring.json"));

  assert.throws(
    () => changeVaultPassphrase(dir, PASSPHRASE, NEW_PASSPHRASE),
    /different keyset/iu,
  );
  assert.deepEqual(
    fs.readFileSync(path.join(dir, "keyring.json")),
    before,
    "a refusal must leave the keyring untouched",
  );

  fs.rmSync(dir, { recursive: true, force: true });
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

test("a store that refuses the write is reported rather than thrown, and never leaks the passphrase", () => {
  const { dir } = seedVault();
  const fake = fakeKeychain({ failOnStore: true });
  setKeychainBackend(fake.backend);
  try {
    fake.entries.set(accountFor(dir), PASSPHRASE);

    const result = updateRememberedPassphrase(dir, NEW_PASSPHRASE);

    assert.equal(result.updated, false);
    assert.ok(result.error, "a failure must be reported");
    for (const value of Object.values(result)) {
      if (typeof value === "string") {
        assert.ok(
          !value.includes(NEW_PASSPHRASE),
          `field must not contain the passphrase: ${value}`,
        );
      }
    }
  } finally {
    setKeychainBackend(undefined);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a failed credential update forgets the stale credential instead of leaving it behind", () => {
  const { dir } = seedVault();
  const fake = fakeKeychain({ failOnStore: true });
  setKeychainBackend(fake.backend);
  try {
    fake.entries.set(accountFor(dir), PASSPHRASE);

    const result = updateRememberedPassphrase(dir, NEW_PASSPHRASE);

    assert.equal(result.updated, false);
    assert.equal(result.cleared, true);
    assert.equal(fake.entries.has(accountFor(dir)), false, "the stale credential must be gone");
  } finally {
    setKeychainBackend(undefined);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

const cliPath = fileURLToPath(new URL("../dist/cli.js", import.meta.url));

function runCli(args, env) {
  return spawnSync(process.execPath, [cliPath, ...args], {
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
}

test("the CLI changes the passphrase end to end", () => {
  const { dir } = seedVault();

  const result = runCli(["--vault", dir, "passphrase", "change"], {
    VBRAIN_PASSPHRASE: PASSPHRASE,
    VBRAIN_NEW_PASSPHRASE: NEW_PASSPHRASE,
  });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Passphrase changed/u);
  assert.match(result.stdout, /does not re-encrypt/u);
  assert.match(result.stdout, /vbrain rekey/u);

  forgetVaultKeys();
  assert.ok(openVaultKeys(dir, NEW_PASSPHRASE));
  assert.throws(() => openVaultKeys(dir, PASSPHRASE), /wrong passphrase/iu);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("the CLI refuses a short new passphrase and leaves the vault alone", () => {
  const { dir } = seedVault();
  const before = fs.readFileSync(path.join(dir, "keyring.json"));

  const result = runCli(["--vault", dir, "passphrase", "change"], {
    VBRAIN_PASSPHRASE: PASSPHRASE,
    VBRAIN_NEW_PASSPHRASE: "short",
  });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /at least 12 characters/u);
  assert.deepEqual(fs.readFileSync(path.join(dir, "keyring.json")), before);

  forgetVaultKeys();
  assert.ok(openVaultKeys(dir, PASSPHRASE), "the old passphrase must still work");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("the CLI never takes the current passphrase from the OS credential store", (t) => {
  if (!keychain().available()) {
    t.skip("no OS credential store is available on this machine");
    return;
  }

  const { dir } = seedVault();
  rememberPassphrase(dir, PASSPHRASE);
  try {
    // VBRAIN_PASSPHRASE is deliberately unset, and stdin is not a TTY (the
    // default for a spawned child with no `input`), so it reads EOF rather
    // than a real answer. Before the fix, `getPassphrase` would have quietly
    // used the credential store instead of prompting, and the command would
    // have completed anyway; the command must now not complete.
    const childEnv = { ...process.env, VBRAIN_NEW_PASSPHRASE: NEW_PASSPHRASE };
    delete childEnv.VBRAIN_PASSPHRASE;
    const result = spawnSync(process.execPath, [cliPath, "--vault", dir, "passphrase", "change"], {
      encoding: "utf8",
      timeout: 10_000,
      env: childEnv,
    });

    assert.doesNotMatch(result.stdout ?? "", /Passphrase changed/u);

    forgetVaultKeys();
    assert.ok(openVaultKeys(dir, PASSPHRASE), "the vault must still open under the original passphrase");
  } finally {
    forgetPassphrase(dir);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("the CLI's --allow-same-passphrase re-wraps the keyring end to end", () => {
  const { dir } = seedVault();

  const result = runCli(["--vault", dir, "passphrase", "change", "--allow-same-passphrase"], {
    VBRAIN_PASSPHRASE: PASSPHRASE,
    VBRAIN_NEW_PASSPHRASE: PASSPHRASE,
  });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Passphrase changed/u);
  assert.match(result.stdout, new RegExp(`N=${DEFAULT_SCRYPT_N}`, "u"));

  forgetVaultKeys();
  assert.ok(openVaultKeys(dir, PASSPHRASE), "the vault must still open under the same passphrase");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("the CLI refuses a legacy vault and names vbrain migrate", () => {
  const dir = tempDir("cli-legacy");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "schema.json"), '{"version":1,"files":{}}\n');

  const result = runCli(["--vault", dir, "passphrase", "change"], {
    VBRAIN_PASSPHRASE: PASSPHRASE,
    VBRAIN_NEW_PASSPHRASE: NEW_PASSPHRASE,
  });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /vbrain migrate/u);

  fs.rmSync(dir, { recursive: true, force: true });
});
