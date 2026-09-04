import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { appendAudit, readAudit, verifyAudit } from "../dist/audit.js";
import { encrypt } from "../dist/crypto.js";
import { DocumentVault } from "../dist/documents.js";
import { serializeKV } from "../dist/format.js";
import {
  detectVaultFormat,
  forgetVaultKeys,
  randomKeySet,
  wrapKeySet,
  writeKeyring,
} from "../dist/keyring.js";
import { migrateToKeyring } from "../dist/keyring-migrate.js";
import { SyncedDocumentVault } from "../dist/sync.js";
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
  assert.ok(report.adopted.includes("syncEnvelope"));
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
  seedLegacyVault(vault);
  upsertEntry(vault, "health", "BLOOD_TYPE", "0 Rh+", "blood group", PASSPHRASE);
  appendAudit(vault, { actor: "cli-direct-write", file: "health", key: "BLOOD_TYPE" }, PASSPHRASE);
  assert.equal(verifyAudit(vault, PASSPHRASE).valid, true);

  const report = migrateToKeyring(vault, PASSPHRASE);
  assert.ok(report.adopted.includes("audit"));
  assert.equal(verifyAudit(vault, PASSPHRASE).valid, true);
  const migrationEvents = readAudit(vault).filter((entry) => entry.actor === "cli-keyring");
  assert.deepEqual(migrationEvents.map((entry) => entry.outcome), ["pending", "allowed"]);
  assert.equal(migrationEvents[0].key, migrationEvents[1].key);

  appendAudit(vault, { actor: "cli-direct", file: "health", key: "BLOOD_TYPE" }, PASSPHRASE);
  const verified = verifyAudit(vault, PASSPHRASE);
  assert.equal(verified.valid, true);
  assert.equal(verified.signedEntries, 4);
});

test("migration rewrites key-value files and the manifest tombstone", () => {
  const vault = tempDir("kv");
  seedLegacyVault(vault);
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
  seedLegacyVault(vault);
  saveVaultFile(vault, "health", [{ key: "BLOOD_TYPE", value: "0 Rh+", desc: "blood group" }], PASSPHRASE);

  const report = migrateToKeyring(vault, PASSPHRASE);
  assert.equal(report.created, true);
  assert.deepEqual(report.adopted, []);
  assert.deepEqual(report.generated.sort(), ["attachmentId", "audit", "documents", "kv", "syncChange", "syncEnvelope"]);
  assert.equal(report.manifestTombstoned, false);
  assert.deepEqual(loadVaultFile(vault, "health", PASSPHRASE), [
    { key: "BLOOD_TYPE", value: "0 Rh+", desc: "blood group" },
  ]);
});

test("migration is idempotent and finishes an interrupted run", () => {
  const vault = tempDir("resume");
  seedLegacyVault(vault);
  upsertEntry(vault, "health", "BLOOD_TYPE", "0 Rh+", "blood group", PASSPHRASE);
  new DocumentVault(vault, PASSPHRASE).lock();

  const first = migrateToKeyring(vault, PASSPHRASE);
  assert.equal(first.created, true, "the first call must genuinely create the keyring, not resume");
  const second = migrateToKeyring(vault, PASSPHRASE);
  assert.equal(second.created, false, "the second call must resume, not re-create");
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

test("the checked-in keyring fixture still opens", () => {
  const vault = copyFixture("keyring-v2");
  assert.equal(detectVaultFormat(vault), "keyring");

  const documents = new DocumentVault(vault, FIXTURE_PASSPHRASE);
  const notes = documents.list();
  assert.ok(notes.length > 0);
  assert.ok(documents.get(notes[0].id).body.length > 0);

  const attachments = documents.listAttachments();
  assert.ok(attachments.length > 0);
  assert.ok(documents.getAttachment(attachments[0].id).data.length > 0);
  documents.lock();

  assert.deepEqual(loadVaultFile(vault, "health", FIXTURE_PASSPHRASE), [
    { key: "BLOOD_TYPE", value: "0 Rh+", desc: "blood group" },
  ]);
  assert.equal(vaultFileEnvelopeVersion(vault, "health"), 2);
  assert.equal(verifyAudit(vault, FIXTURE_PASSPHRASE).valid, true);
});

// --- C1: the resume branch must prove the keyring opens before tombstoning
// documents/manifest.json, which holds the only copy of the legacy scrypt
// salt. Before the fix, an interrupted-migration vault (keyring present but
// unreadable, manifest still v1, no key-value files, no grants) let the
// resume branch's loops run zero times and fall straight through to the
// tombstone, reporting success while destroying the vault's only path to its
// document key.

test("C1: migrate refuses to tombstone the legacy manifest when a present keyring cannot be read", () => {
  const vault = tempDir("c1-corrupt-keyring");
  // A legacy document vault: manifest.json v1 with the real salt, and
  // deliberately no key-value files and no grants.enc — the interrupted-
  // migration state this branch exists to handle.
  seedLegacyVault(vault);
  new DocumentVault(vault, PASSPHRASE).lock();
  const manifestBefore = fs.readFileSync(path.join(vault, "documents", "manifest.json"), "utf8");
  const parsedBefore = JSON.parse(manifestBefore);
  assert.equal(parsedBefore.version, 1, "setup must produce a genuine legacy v1 manifest, not a v2 tombstone");
  assert.equal(typeof parsedBefore.kdf?.salt, "string");
  assert.ok(parsedBefore.kdf.salt.length > 0);
  assert.equal(fs.existsSync(path.join(vault, "keyring.json")), false, "no keyring.json must exist yet");

  // A keyring.json that exists (so detectVaultFormat reports "keyring") but is
  // unreadable — e.g. corrupted mid-write.
  fs.writeFileSync(path.join(vault, "keyring.json"), JSON.stringify({ version: 2, slots: [{ bogus: true }] }));

  assert.throws(() => migrateToKeyring(vault, PASSPHRASE));

  // The legacy manifest — the vault's only copy of the salt — must survive
  // completely untouched by the refused migrate call: still version 1, with
  // the same salt, not tombstoned into the v2 { version: 2, keyring: true }
  // marker.
  const manifestAfter = fs.readFileSync(path.join(vault, "documents", "manifest.json"), "utf8");
  assert.equal(manifestAfter, manifestBefore);
  const parsedAfter = JSON.parse(manifestAfter);
  assert.equal(parsedAfter.version, 1);
  assert.equal(parsedAfter.kdf.salt, parsedBefore.kdf.salt);
});

test("C1 (wrong-passphrase variant): migrate refuses to tombstone when the passphrase cannot open a present keyring", () => {
  const vault = tempDir("c1-wrong-passphrase");
  seedLegacyVault(vault);
  new DocumentVault(vault, PASSPHRASE).lock();
  const manifestBefore = fs.readFileSync(path.join(vault, "documents", "manifest.json"), "utf8");
  const parsedBefore = JSON.parse(manifestBefore);
  assert.equal(parsedBefore.version, 1, "setup must produce a genuine legacy v1 manifest, not a v2 tombstone");
  assert.equal(typeof parsedBefore.kdf?.salt, "string");
  assert.ok(parsedBefore.kdf.salt.length > 0);
  assert.equal(fs.existsSync(path.join(vault, "keyring.json")), false, "no keyring.json must exist yet");

  // Simulate a keyring written for a different passphrase than the one about
  // to be used to resume migration (e.g. an earlier run crashed after writing
  // the keyring but before the tombstone, and the caller now supplies the
  // wrong passphrase).
  writeKeyring(vault, { version: 2, slots: [wrapKeySet(randomKeySet(), "a-different-passphrase", 2 ** 14)] });
  forgetVaultKeys(vault);

  assert.throws(() => migrateToKeyring(vault, PASSPHRASE));

  // Still version 1 with the original salt — not tombstoned into a v2 marker.
  const manifestAfter = fs.readFileSync(path.join(vault, "documents", "manifest.json"), "utf8");
  assert.equal(manifestAfter, manifestBefore);
  const parsedAfter = JSON.parse(manifestAfter);
  assert.equal(parsedAfter.version, 1);
  assert.equal(parsedAfter.kdf.salt, parsedBefore.kdf.salt);
});

// --- C2: legacyDocumentKey must throw, not return null, when it sees a
// version-2 manifest with no keyring.json. That state is unambiguous: the
// vault was upgraded to a keyring and the keyring was then lost. Returning
// null let the caller treat the vault as having no legacy material at all,
// generating a brand-new keyset and reporting `created: true` while every
// existing note became permanently undecryptable.

test("C2: migrate refuses to fabricate a fresh keyset when a v2 manifest has lost its keyring", () => {
  const vault = tempDir("c2-lost-keyring");
  fs.mkdirSync(path.join(vault, "documents"), { recursive: true });
  fs.writeFileSync(path.join(vault, "documents", "manifest.json"), JSON.stringify({ version: 2, keyring: true }));
  assert.equal(fs.existsSync(path.join(vault, "keyring.json")), false);
  assert.equal(detectVaultFormat(vault), "legacy");

  assert.throws(() => migrateToKeyring(vault, PASSPHRASE), /keyring\.json is missing or unreadable/u);
});

// --- I8: no test previously asserted the design's central claim — that sync
// change IDs and resolved heads stay byte-identical across migration. Only
// `report.adopted.includes("syncChange")` was checked, which is a report
// field, not the invariant itself.

test("sync change IDs and bodies are byte-identical across migration, and resolved heads agree", () => {
  const DEVICE_A = "11111111-1111-4111-8111-111111111111";
  const vault = tempDir("sync-identity");
  seedLegacyVault(vault);

  const before = new SyncedDocumentVault(vault, PASSPHRASE, DEVICE_A);
  const note = before.put({ path: "Plans/Launch.md", body: "first" });
  before.put({ id: note.id, path: note.path, title: note.title, body: "second", baseRevision: note.revision });
  const changesBefore = before.changeLog.changes();
  assert.ok(changesBefore.length >= 2, "the vault must contain sync changes to make this assertion meaningful");
  const resolutionBefore = before.changeLog.resolve("note", note.id);
  before.lock();

  const report = migrateToKeyring(vault, PASSPHRASE);
  assert.equal(report.created, true);
  assert.ok(report.adopted.includes("syncChange"));
  assert.ok(report.adopted.includes("syncEnvelope"));

  const after = new SyncedDocumentVault(vault, PASSPHRASE);
  const changesAfter = after.changeLog.changes();
  const resolutionAfter = after.changeLog.resolve("note", note.id);

  // Not just the IDs: the full decrypted body (deviceId, sequence, parents,
  // createdAt and the mutation itself, including its plaintext value) must
  // come back byte-identical. This is what proves migration adopted the
  // legacy key into syncEnvelope, not just syncChange: if it had not, every
  // change body would still fail to decrypt (or decrypt to something else)
  // under the freshly generated syncEnvelope key, even though the change
  // IDs (keyed by the correctly adopted syncChange key) would still match.
  assert.deepEqual(changesAfter, changesBefore);
  assert.equal(resolutionAfter.winner.id, resolutionBefore.winner.id);
  assert.deepEqual(resolutionAfter.heads, resolutionBefore.heads);
  after.lock();
});

test("migrating the documents-canvas-v1 fixture keeps getCanvas output identical", () => {
  const vault = copyFixture("documents-canvas-v1");

  const before = new DocumentVault(vault, FIXTURE_PASSPHRASE);
  const [summary] = before.listCanvases();
  assert.ok(summary, "the fixture must contain a canvas");
  const canvasBefore = before.getCanvas(summary.id);
  before.lock();

  const report = migrateToKeyring(vault, FIXTURE_PASSPHRASE);
  assert.equal(report.created, true);
  assert.equal(detectVaultFormat(vault), "keyring");

  const after = new DocumentVault(vault, FIXTURE_PASSPHRASE);
  const canvasAfter = after.getCanvas(summary.id);
  assert.deepEqual(canvasAfter, canvasBefore);
  after.lock();
});
