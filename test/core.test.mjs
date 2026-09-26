import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { appendAudit, verifyAudit } from "../dist/audit.js";
import { decrypt, encrypt } from "../dist/crypto.js";
import { parseKV, serializeKV } from "../dist/format.js";
import { buildSchema, filterNotesByDate } from "../dist/schema.js";
import { loadVaultFile, saveVaultFile, upsertEntry, vaultFilePath } from "../dist/store.js";

const PASSPHRASE = "correct horse battery staple";

function tempVault() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "vault-brain-test-"));
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

test("KV format round-trips quotes, backslashes and newlines", () => {
  const entries = [
    {
      key: "MULTILINE_NOTE",
      desc: "safe tag",
      value: 'first line\nsecond = line with \\"quotes\\" and C:\\\\notes',
    },
  ];
  assert.deepEqual(parseKV(serializeKV(entries)), entries);
});

test("AES-GCM rejects a wrong passphrase and modified ciphertext", () => {
  const payload = encrypt("private", PASSPHRASE);
  assert.equal(decrypt(payload, PASSPHRASE), "private");
  assert.throws(() => decrypt(payload, "wrong passphrase"));
  const tampered = { ...payload, ciphertext: payload.ciphertext.slice(0, -2) + "AA" };
  assert.throws(() => decrypt(tampered, PASSPHRASE));
});

test("new encrypted payloads reject weak passphrases", () => {
  assert.throws(() => encrypt("private", "short"), /at least 12 characters/);
  assert.throws(() => encrypt("private", "passwordpassword"), /less predictable/);
});

test("vault category cannot escape the selected vault directory", () => {
  const vault = tempVault();
  assert.throws(() => vaultFilePath(vault, "../outside"), /Invalid vault category/);
  assert.throws(() => vaultFilePath(vault, "..\\outside"), /Invalid vault category/);
  assert.throws(() => vaultFilePath(vault, "C:\\outside"), /Invalid vault category/);
  assert.equal(vaultFilePath(vault, "health"), path.join(vault, "health.kv.enc"));
});

// A category's name is also its file's AEAD identity. On a case-insensitive
// filesystem "HEALTH" opens health.kv.enc and then fails authentication, which
// reads as a damaged vault; on a case-sensitive one it silently starts a second
// category that collides the moment the vault reaches Windows or macOS.
test("a category asked for in the wrong case is refused by name, on every platform", () => {
  const vault = tempVault();
  upsertEntry(vault, "health", "BLOOD", "A Rh+", "blood type", PASSPHRASE);

  assert.throws(() => loadVaultFile(vault, "HEALTH", PASSPHRASE), (error) => {
    assert.match(error.message, /No category "HEALTH"/u);
    assert.match(error.message, /"health"/u, "the message names the category that is stored");
    assert.doesNotMatch(error.message, /authenticate/u);
    return true;
  });
});

test("a write in the wrong case is refused and starts no second category", () => {
  const vault = tempVault();
  upsertEntry(vault, "health", "BLOOD", "A Rh+", "blood type", PASSPHRASE);

  assert.throws(() => upsertEntry(vault, "Health", "X", "1", "x", PASSPHRASE), /No category "Health"/u);

  assert.deepEqual(
    fs.readdirSync(vault).filter((name) => name.endsWith(".kv.enc")),
    ["health.kv.enc"],
  );
  assert.deepEqual(
    loadVaultFile(vault, "health", PASSPHRASE).map((entry) => [entry.key, entry.value]),
    [["BLOOD", "A Rh+"]],
  );
});

test("a category's own spelling, and a new one in any case, still work", () => {
  const vault = tempVault();
  upsertEntry(vault, "Travel", "PASSPORT", "U123", "passport number", PASSPHRASE);
  assert.equal(loadVaultFile(vault, "Travel", PASSPHRASE)[0].value, "U123");
  assert.deepEqual(loadVaultFile(vault, "work", PASSPHRASE), [], "an absent category is still just empty");
});

test("encrypted storage writes atomically and schema never contains values", () => {
  const vault = tempVault();
  fs.writeFileSync(path.join(vault, "schema.json"), '{"legacy":"plaintext"}');
  upsertEntry(vault, "health", "BLOOD_TYPE", "0 Rh+", "Kan grubu", PASSPHRASE);
  upsertEntry(vault, "health", "NOTE", "line 1\nline 2", "safe note", PASSPHRASE);

  assert.equal(loadVaultFile(vault, "health", PASSPHRASE)[1].value, "line 1\nline 2");
  const schema = buildSchema(vault, PASSPHRASE);
  const onDisk = fs.readFileSync(path.join(vault, "schema.enc"), "utf8");
  assert.equal(onDisk.includes("0 Rh+"), false);
  assert.equal(onDisk.includes("line 1"), false);
  assert.equal(onDisk.includes("BLOOD_TYPE"), false, "key names are encrypted at rest too");
  assert.equal(fs.existsSync(path.join(vault, "schema.json")), false);
  assert.equal(schema.files.health.length, 2);
  assert.deepEqual(
    fs.readdirSync(vault).filter((name) => name.endsWith(".tmp")),
    [],
  );
});

test("atomic vault writes preserve Unicode paths and private modes on the host filesystem", () => {
  const root = tempVault();
  const vault = path.join(root, "Masaüstü vault space");
  upsertEntry(vault, "health", "PRIVATE_NOTE", "complete replacement", "path test", PASSPHRASE);

  const encrypted = vaultFilePath(vault, "health");
  assert.equal(loadVaultFile(vault, "health", PASSPHRASE)[0].value, "complete replacement");
  assert.deepEqual(
    fs.readdirSync(vault).filter((name) => name.endsWith(".tmp")),
    [],
  );
  if (process.platform !== "win32") {
    assert.equal(fs.statSync(vault).mode & 0o777, 0o700);
    assert.equal(fs.statSync(encrypted).mode & 0o777, 0o600);
  }
});

test("date-only upper bounds include the complete UTC day", () => {
  const schema = {
    generatedAt: new Date().toISOString(),
    files: {
      journal: [
        { key: "NOTE_20260830_235959_abcdef", desc: "late note" },
        { key: "NOTE_20260831_000000_abcdef", desc: "next day" },
      ],
    },
  };
  const hits = filterNotesByDate(schema, { from: "2026-08-30", to: "2026-08-30" });
  assert.equal(hits.length, 1);
  assert.equal(hits[0].desc, "late note");
});

test("audit entries form a passphrase-authenticated chain", () => {
  const vault = tempVault();
  seedLegacyVault(vault);
  saveVaultFile(vault, "health", [], PASSPHRASE);
  appendAudit(vault, { actor: "cli-direct-write", file: "health", key: "BLOOD_TYPE" }, PASSPHRASE);
  appendAudit(vault, { actor: "cli-direct", file: "health", key: "BLOOD_TYPE" }, PASSPHRASE);
  assert.deepEqual(verifyAudit(vault, PASSPHRASE), {
    valid: true,
    signedEntries: 2,
    legacyEntries: 0,
  });
  assert.equal(verifyAudit(vault, "wrong passphrase").valid, false);

  const logPath = path.join(vault, "audit.log");
  fs.writeFileSync(logPath, fs.readFileSync(logPath, "utf8").replace("BLOOD_TYPE", "ALTERED_KEY"));
  assert.equal(verifyAudit(vault, PASSPHRASE).valid, false);
});
