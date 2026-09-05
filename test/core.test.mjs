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
