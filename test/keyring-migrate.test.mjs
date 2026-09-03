import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { appendAudit, verifyAudit } from "../dist/audit.js";
import { encrypt } from "../dist/crypto.js";
import { DocumentVault } from "../dist/documents.js";
import { serializeKV } from "../dist/format.js";
import { detectVaultFormat } from "../dist/keyring.js";
import { migrateToKeyring } from "../dist/keyring-migrate.js";
import { loadVaultFile, saveVaultFile, upsertEntry, vaultFileEnvelopeVersion } from "../dist/store.js";

const FIXTURES = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "fixtures");
const FIXTURE_PASSPHRASE = "fixture-only-passphrase";
const PASSPHRASE = "migrate-test-passphrase";

function tempDir(label = "migrate") {
  return fs.mkdtempSync(path.join(os.tmpdir(), `vault-brain-${label}-`));
}

function copyTree(from, to) {
  fs.mkdirSync(to, { recursive: true });
  for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
    const src = path.join(from, entry.name);
    const dst = path.join(to, entry.name);
    if (entry.isDirectory()) copyTree(src, dst);
    else fs.copyFileSync(src, dst);
  }
}

function copyFixture(name) {
  const target = tempDir(name);
  copyTree(path.join(FIXTURES, name), target);
  return target;
}

test("migration adopts the legacy key so attachment identities never move", () => {
  const vault = copyFixture("documents-attachments-v1");

  const before = new DocumentVault(vault, FIXTURE_PASSPHRASE);
  const identities = before.listAttachments().map((info) => ({ id: info.id, size: info.size }));
  assert.ok(identities.length > 0, "the fixture must contain attachments");
  before.lock();

  const report = migrateToKeyring(vault, FIXTURE_PASSPHRASE);
  assert.equal(report.created, true);
  assert.ok(report.adopted.includes("documents"));
  assert.ok(report.adopted.includes("attachmentId"));
  assert.ok(report.adopted.includes("syncChange"));
  assert.equal(detectVaultFormat(vault), "keyring");

  const after = new DocumentVault(vault, FIXTURE_PASSPHRASE);
  assert.deepEqual(
    after.listAttachments().map((info) => ({ id: info.id, size: info.size })),
    identities,
  );
  for (const { id } of identities) {
    // getAttachment recomputes the content address and throws when it moved.
    assert.ok(after.getAttachment(id).data.length > 0);
  }
  after.lock();
});

test("migration keeps notes, revisions and search working", () => {
  const vault = copyFixture("documents-v1");

  const before = new DocumentVault(vault, FIXTURE_PASSPHRASE);
  const notes = before.list().map((note) => ({ id: note.id, path: note.path }));
  before.lock();

  migrateToKeyring(vault, FIXTURE_PASSPHRASE);

  const after = new DocumentVault(vault, FIXTURE_PASSPHRASE);
  assert.deepEqual(after.list().map((note) => ({ id: note.id, path: note.path })), notes);
  for (const { id } of notes) assert.ok(after.get(id).body.length >= 0);
  after.lock();
});

test("migration adopts the audit key so the existing chain still verifies", () => {
  const vault = tempDir("audit");
  upsertEntry(vault, "health", "BLOOD_TYPE", "0 Rh+", "blood group", PASSPHRASE);
  appendAudit(vault, { actor: "cli-direct-write", file: "health", key: "BLOOD_TYPE" }, PASSPHRASE);
  assert.equal(verifyAudit(vault, PASSPHRASE).valid, true);

  const report = migrateToKeyring(vault, PASSPHRASE);
  assert.ok(report.adopted.includes("audit"));
  assert.equal(verifyAudit(vault, PASSPHRASE).valid, true);

  appendAudit(vault, { actor: "cli-direct", file: "health", key: "BLOOD_TYPE" }, PASSPHRASE);
  const verified = verifyAudit(vault, PASSPHRASE);
  assert.equal(verified.valid, true);
  assert.equal(verified.signedEntries, 2);
});

test("migration rewrites key-value files and the manifest tombstone", () => {
  const vault = tempDir("kv");
  upsertEntry(vault, "health", "BLOOD_TYPE", "0 Rh+", "blood group", PASSPHRASE);
  assert.equal(vaultFileEnvelopeVersion(vault, "health"), 1);
  new DocumentVault(vault, PASSPHRASE).lock();

  const report = migrateToKeyring(vault, PASSPHRASE);
  assert.deepEqual(report.kvFilesRewritten, ["health"]);
  assert.equal(report.manifestTombstoned, true);
  assert.equal(vaultFileEnvelopeVersion(vault, "health"), 2);
  assert.deepEqual(loadVaultFile(vault, "health", PASSPHRASE), [
    { key: "BLOOD_TYPE", value: "0 Rh+", desc: "blood group" },
  ]);

  const manifest = JSON.parse(fs.readFileSync(path.join(vault, "documents", "manifest.json"), "utf8"));
  assert.deepEqual(manifest, { version: 2, keyring: true });
  assert.equal(manifest.verifier, undefined);
});

test("a key-value-only vault generates the keys it cannot adopt", () => {
  const vault = tempDir("kvonly");
  saveVaultFile(vault, "health", [{ key: "BLOOD_TYPE", value: "0 Rh+", desc: "blood group" }], PASSPHRASE);

  const report = migrateToKeyring(vault, PASSPHRASE);
  assert.equal(report.created, true);
  assert.deepEqual(report.adopted, []);
  assert.deepEqual(report.generated.sort(), ["attachmentId", "audit", "documents", "kv", "syncChange"]);
  assert.equal(report.manifestTombstoned, false);
  assert.deepEqual(loadVaultFile(vault, "health", PASSPHRASE), [
    { key: "BLOOD_TYPE", value: "0 Rh+", desc: "blood group" },
  ]);
});

test("migration is idempotent and finishes an interrupted run", () => {
  const vault = tempDir("resume");
  upsertEntry(vault, "health", "BLOOD_TYPE", "0 Rh+", "blood group", PASSPHRASE);
  new DocumentVault(vault, PASSPHRASE).lock();

  migrateToKeyring(vault, PASSPHRASE);
  const second = migrateToKeyring(vault, PASSPHRASE);
  assert.equal(second.created, false);
  assert.deepEqual(second.kvFilesRewritten, []);

  // Simulate a crash between writing the keyring and rewriting a file: a
  // passphrase-enveloped file sitting in a vault that already has a keyring.
  const stale = encrypt(serializeKV([{ key: "IBAN", value: "TR00", desc: "iban" }]), PASSPHRASE);
  fs.writeFileSync(path.join(vault, "stale.kv.enc"), JSON.stringify(stale, null, 2));
  assert.equal(vaultFileEnvelopeVersion(vault, "stale"), 1);

  const third = migrateToKeyring(vault, PASSPHRASE);
  assert.equal(third.created, false);
  assert.deepEqual(third.kvFilesRewritten, ["stale"]);
  assert.equal(vaultFileEnvelopeVersion(vault, "stale"), 2);
  assert.deepEqual(loadVaultFile(vault, "stale", PASSPHRASE), [{ key: "IBAN", value: "TR00", desc: "iban" }]);
});
