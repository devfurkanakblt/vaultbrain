import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { appendAudit, verifyAudit } from "../dist/audit.js";
import { DocumentVault } from "../dist/documents.js";
import { detectVaultFormat, forgetVaultKeys, openOrCreateVaultKeys, openVaultKeys } from "../dist/keyring.js";
import { loadVaultFile, upsertEntry, vaultFileEnvelopeVersion } from "../dist/store.js";

const FIXTURES = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "fixtures");
const FIXTURE_PASSPHRASE = "fixture-only-passphrase";
const PASSPHRASE = "create-test-passphrase";

function tempDir(label = "create") {
  return fs.mkdtempSync(path.join(os.tmpdir(), `vault-brain-${label}-`));
}

// fs.cpSync crashes the Node process on this machine; see the plan's constraints.
function copyTree(from, to) {
  fs.mkdirSync(to, { recursive: true });
  for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
    const src = path.join(from, entry.name);
    const dst = path.join(to, entry.name);
    if (entry.isDirectory()) copyTree(src, dst);
    else fs.copyFileSync(src, dst);
  }
}

test("a fresh vault becomes keyring-native on its first key-value write", () => {
  const dir = tempDir();
  upsertEntry(dir, "health", "BLOOD_TYPE", "0 Rh+", "blood group", PASSPHRASE);

  assert.equal(detectVaultFormat(dir), "keyring");
  assert.ok(fs.existsSync(path.join(dir, "keyring.json")));
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(dir, "documents", "manifest.json"), "utf8")), {
    version: 2,
    keyring: true,
  });
  assert.equal(vaultFileEnvelopeVersion(dir, "health"), 2);

  // Not from the process cache: the keyring on disk has to be the one that opens.
  forgetVaultKeys();
  assert.equal(loadVaultFile(dir, "health", PASSPHRASE)[0].value, "0 Rh+");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("a fresh vault becomes keyring-native on its first document write", () => {
  const dir = tempDir();
  const vault = new DocumentVault(dir, PASSPHRASE);
  vault.put({ path: "Atlas/First.md", title: "First", body: "# First\n\nbody" });
  vault.lock();

  assert.equal(detectVaultFormat(dir), "keyring");
  assert.equal(JSON.parse(fs.readFileSync(path.join(dir, "documents", "manifest.json"), "utf8")).version, 2);

  forgetVaultKeys();
  const reopened = new DocumentVault(dir, PASSPHRASE);
  assert.equal(reopened.get("Atlas/First.md").title, "First");
  reopened.lock();
  fs.rmSync(dir, { recursive: true, force: true });
});

test("reading an empty vault creates nothing", () => {
  const dir = tempDir();
  assert.deepEqual(loadVaultFile(dir, "health", PASSPHRASE), []);
  assert.equal(openVaultKeys(dir, PASSPHRASE), null);
  assert.equal(fs.existsSync(path.join(dir, "keyring.json")), false);
  assert.equal(detectVaultFormat(dir), "empty");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("a legacy key-value vault keeps its format and its audit chain when written to", () => {
  const dir = tempDir("legacy-kv");
  copyTree(path.join(FIXTURES, "kv-envelope-v0"), dir);
  appendAudit(dir, { actor: "test", file: "health", key: "BLOOD_TYPE" }, FIXTURE_PASSPHRASE);

  upsertEntry(dir, "health", "ALLERGY", "none", "allergies", FIXTURE_PASSPHRASE);

  assert.equal(fs.existsSync(path.join(dir, "keyring.json")), false);
  assert.equal(detectVaultFormat(dir), "legacy");
  assert.equal(verifyAudit(dir, FIXTURE_PASSPHRASE).valid, true);
  assert.equal(loadVaultFile(dir, "health", FIXTURE_PASSPHRASE).find((e) => e.key === "ALLERGY").value, "none");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("a legacy document vault opens and is written to without gaining a keyring", () => {
  const dir = tempDir("legacy-docs");
  copyTree(path.join(FIXTURES, "documents-v1"), dir);
  const vault = new DocumentVault(dir, FIXTURE_PASSPHRASE);
  assert.ok(vault.list().length > 0);
  vault.put({ path: "Atlas/Added.md", title: "Added", body: "# Added" });
  vault.lock();

  assert.equal(fs.existsSync(path.join(dir, "keyring.json")), false);
  assert.equal(JSON.parse(fs.readFileSync(path.join(dir, "documents", "manifest.json"), "utf8")).version, 1);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("creating a keyring is idempotent and every key is independent", () => {
  const dir = tempDir("idempotent");
  const first = openOrCreateVaultKeys(dir, PASSPHRASE);
  const keyringText = fs.readFileSync(path.join(dir, "keyring.json"), "utf8");
  const second = openOrCreateVaultKeys(dir, PASSPHRASE);

  assert.deepEqual(second.documents, first.documents);
  assert.equal(fs.readFileSync(path.join(dir, "keyring.json"), "utf8"), keyringText);
  const seen = new Set(Object.values(first).map((key) => key.toString("hex")));
  assert.equal(seen.size, 6, "a fresh vault must get six independent random keys");
  fs.rmSync(dir, { recursive: true, force: true });
});
