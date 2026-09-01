import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { decrypt, encrypt, ENVELOPE_VERSION, envelopeVersion } from "../dist/crypto.js";
import { DocumentVault } from "../dist/documents.js";
import { applyFrontmatter, parseFrontmatter } from "../dist/frontmatter.js";
import {
  accountFor,
  forgetPassphrase,
  keychain,
  recallPassphrase,
  rememberPassphrase,
  setKeychainBackend,
} from "../dist/keychain.js";
import { getPassphrase } from "../dist/passphrase.js";
import { loadVaultFile, migrateVault, vaultFileEnvelopeVersion } from "../dist/store.js";
import { lockHolder, VaultBusyError, withVaultLock } from "../dist/vault-lock.js";

const FIXTURES = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "fixtures");
const FIXTURE_PASSPHRASE = "fixture-only-passphrase";
const PASSPHRASE = "durability-test-passphrase";

function tempDir(label = "durability") {
  return fs.mkdtempSync(path.join(os.tmpdir(), `vault-brain-${label}-`));
}

function copyFixture(name) {
  const target = tempDir(name);
  fs.cpSync(path.join(FIXTURES, name), target, { recursive: true });
  return target;
}

function objectPath(vaultDir, id) {
  return path.join(vaultDir, "documents", "objects", `${id}.note.enc`);
}

function journalPath(vaultDir) {
  return path.join(vaultDir, "documents", "journal.json");
}

test("the current envelope records its version and authenticates its own parameters", () => {
  const payload = encrypt("one key, one fact", PASSPHRASE);
  assert.equal(payload.version, ENVELOPE_VERSION);
  assert.equal(payload.cipher, "aes-256-gcm");
  assert.equal(payload.kdf.name, "scrypt");
  assert.ok(payload.kdf.N >= 2 ** 15 && payload.kdf.r >= 1 && payload.kdf.p >= 1);
  assert.equal(decrypt(payload, PASSPHRASE), "one key, one fact");

  // Rewriting the recorded cost must not silently weaken the next derivation.
  assert.throws(() => decrypt({ ...payload, kdf: { ...payload.kdf, N: 2 ** 14 } }, PASSPHRASE));
  assert.throws(() => decrypt({ ...payload, version: 9 }, PASSPHRASE), /envelope version 9/u);
  assert.throws(
    () => decrypt({ ...payload, kdf: { ...payload.kdf, N: 2 ** 24 } }, PASSPHRASE),
    /unacceptable scrypt cost/u
  );
  assert.throws(() => decrypt(payload, "wrong passphrase"));
});

test("a pre-versioning vault file still opens and migrates in place", () => {
  const vaultDir = copyFixture("kv-envelope-v0");
  assert.equal(vaultFileEnvelopeVersion(vaultDir, "health"), 0);

  const before = loadVaultFile(vaultDir, "health", FIXTURE_PASSPHRASE);
  assert.equal(before.find((entry) => entry.key === "BLOOD_TYPE").value, "0 Rh+");
  assert.equal(before.find((entry) => entry.key === "DOCTOR_NEXT_APPOINTMENT").value, "2026-09-15");

  const [report] = migrateVault(vaultDir, FIXTURE_PASSPHRASE);
  assert.deepEqual(report, { name: "health", from: 0, to: ENVELOPE_VERSION, migrated: true });
  assert.equal(vaultFileEnvelopeVersion(vaultDir, "health"), ENVELOPE_VERSION);
  assert.deepEqual(loadVaultFile(vaultDir, "health", FIXTURE_PASSPHRASE), before);

  // Migration is idempotent: a second run rewrites nothing.
  assert.equal(migrateVault(vaultDir, FIXTURE_PASSPHRASE)[0].migrated, false);
  assert.equal(
    envelopeVersion(JSON.parse(fs.readFileSync(path.join(vaultDir, "health.kv.enc"), "utf8"))),
    ENVELOPE_VERSION
  );
});

test("a checked-in document vault from the current format still opens and resolves links", () => {
  const vaultDir = copyFixture("documents-v1");
  const vault = new DocumentVault(vaultDir, FIXTURE_PASSPHRASE);

  const notes = vault.list();
  assert.equal(notes.length, 2);
  assert.deepEqual(notes.map((note) => note.title).sort(), ["Format contract", "Second note"]);
  assert.ok(vault.search("frozen").length > 0);

  const target = vault.get("Atlas/Second note");
  const backlinks = vault.backlinks(target.id);
  assert.deepEqual(backlinks.map((note) => note.title), ["Format contract"]);
  assert.throws(() => new DocumentVault(vaultDir, "wrong passphrase"), /wrong passphrase/u);
});

test("a checked-in canvas vault keeps encrypted boards and stable references readable", () => {
  const vaultDir = copyFixture("documents-canvas-v1");
  const vault = new DocumentVault(vaultDir, FIXTURE_PASSPHRASE);
  const [canvas] = vault.listCanvases();
  assert.equal(canvas.title, "Frozen roadmap");
  assert.equal(canvas.nodeCount, 2);
  assert.equal(canvas.edgeCount, 1);
  const document = vault.getCanvas(canvas.id);
  const note = vault.get("Atlas/Canvas contract");
  assert.equal(document.nodes[0].noteId, note.id);
  assert.deepEqual(vault.canvasesReferencing(note.id).map((item) => item.id), [canvas.id]);
});

test("an interrupted write is replayed from its journal on the next unlock", () => {
  const live = tempDir("crash");
  const vault = new DocumentVault(live, PASSPHRASE);
  const alpha = vault.put({ path: "Notes/Alpha.md", body: "# Alpha\n\nPoints at [[Notes/Beta]]." });
  vault.put({ path: "Notes/Beta.md", body: "# Beta\n\nNothing yet." });

  // Snapshot the vault, then advance it: the snapshot now holds a stale index.
  const crashed = tempDir("crash-copy");
  fs.rmSync(crashed, { recursive: true, force: true });
  fs.cpSync(live, crashed, { recursive: true });
  vault.put({ id: alpha.id, path: "Notes/Alpha.md", body: "# Alpha\n\nrecoverytoken [[Notes/Beta]]." });

  // A crash between the object write and the index write leaves exactly this:
  // the new object on disk, the old index, and a journal naming the note.
  const stale = tempDir("crash-stale");
  fs.rmSync(stale, { recursive: true, force: true });
  fs.cpSync(crashed, stale, { recursive: true });
  fs.copyFileSync(objectPath(live, alpha.id), objectPath(crashed, alpha.id));
  fs.copyFileSync(objectPath(live, alpha.id), objectPath(stale, alpha.id));
  fs.writeFileSync(
    journalPath(crashed),
    JSON.stringify({ version: 1, startedAt: new Date().toISOString(), scope: "notes", ids: [alpha.id] })
  );

  // Without the journal the index stays stale — which is what it is there for.
  assert.equal(new DocumentVault(stale, PASSPHRASE).search("recoverytoken").length, 0);

  const recovered = new DocumentVault(crashed, PASSPHRASE);
  const hits = recovered.search("recoverytoken");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].id, alpha.id);
  assert.equal(fs.existsSync(journalPath(crashed)), false);
  assert.equal(recovered.list().length, 2);
  assert.deepEqual(
    recovered.backlinks(recovered.get("Notes/Beta").id).map((note) => note.title),
    ["Alpha"]
  );
});

test("recovery drops a note whose object never landed, and rebuilds after a bulk crash", () => {
  const vaultDir = tempDir("crash-missing");
  const vault = new DocumentVault(vaultDir, PASSPHRASE);
  const ghost = vault.put({ path: "Notes/Ghost.md", body: "# Ghost" });
  vault.put({ path: "Notes/Real.md", body: "# Real" });

  fs.rmSync(objectPath(vaultDir, ghost.id));
  fs.writeFileSync(
    journalPath(vaultDir),
    JSON.stringify({ version: 1, startedAt: new Date().toISOString(), scope: "notes", ids: [ghost.id] })
  );
  const repaired = new DocumentVault(vaultDir, PASSPHRASE);
  assert.deepEqual(repaired.list().map((note) => note.title), ["Real"]);
  assert.equal(fs.existsSync(journalPath(vaultDir)), false);

  // A bulk transaction cannot name its notes up front, so it rebuilds instead.
  fs.writeFileSync(
    journalPath(vaultDir),
    JSON.stringify({ version: 1, startedAt: new Date().toISOString(), scope: "bulk", ids: [] })
  );
  const rebuilt = new DocumentVault(vaultDir, PASSPHRASE);
  assert.deepEqual(rebuilt.list().map((note) => note.title), ["Real"]);
  assert.equal(fs.existsSync(journalPath(vaultDir)), false);

  // A missing index is rebuilt from the objects alone.
  fs.rmSync(path.join(vaultDir, "documents", "index.enc"));
  assert.deepEqual(new DocumentVault(vaultDir, PASSPHRASE).list().map((note) => note.title), ["Real"]);
});

test("a second writer is refused while a live lock is held, and reclaims a stale one", () => {
  const vaultDir = tempDir("locking");
  const vault = new DocumentVault(vaultDir, PASSPHRASE);
  vault.put({ path: "Notes/First.md", body: "# First" });

  const lockPath = path.join(vaultDir, ".sbrain.lock");
  const foreign = (acquiredAt) =>
    JSON.stringify({ token: "another-process", pid: 999_999, host: "elsewhere", acquiredAt });

  fs.writeFileSync(lockPath, foreign(new Date().toISOString()));
  assert.equal(lockHolder(vaultDir).pid, 999_999);
  assert.throws(
    () => vault.put({ path: "Notes/Second.md", body: "# Second" }),
    (error) => error instanceof VaultBusyError && /being written by process 999999/u.test(error.message)
  );

  // A lock left behind by a crashed process must not wedge the vault forever.
  fs.writeFileSync(lockPath, foreign(new Date(Date.now() - 120_000).toISOString()));
  vault.put({ path: "Notes/Second.md", body: "# Second" });
  assert.equal(vault.list().length, 2);
  assert.equal(fs.existsSync(lockPath), false);
});

test("the vault lock is reentrant within one process and released afterwards", () => {
  const vaultDir = tempDir("reentrant");
  const seen = withVaultLock(vaultDir, () =>
    withVaultLock(vaultDir, () => {
      assert.ok(lockHolder(vaultDir));
      return "inner";
    })
  );
  assert.equal(seen, "inner");
  assert.equal(lockHolder(vaultDir), undefined);
});

test("locking a session zeroizes the key and refuses further work", () => {
  const vaultDir = tempDir("lock-lifecycle");
  const vault = new DocumentVault(vaultDir, PASSPHRASE);
  vault.put({ path: "Notes/Kept.md", body: "# Kept" });

  assert.equal(vault.isLocked, false);
  vault.lock();
  assert.equal(vault.isLocked, true);
  assert.throws(() => vault.list(), /session is locked/u);
  assert.throws(() => vault.put({ path: "Notes/After.md", body: "# After" }), /session is locked/u);
  assert.throws(() => vault.search("Kept"), /session is locked/u);
  vault.lock(); // locking twice is not an error

  // The data itself is untouched: a fresh session opens it normally.
  const reopened = new DocumentVault(vaultDir, PASSPHRASE);
  assert.deepEqual(reopened.list().map((note) => note.title), ["Kept"]);
});

test("a remembered passphrase is scoped per vault and resolves ahead of the prompt", async () => {
  const store = new Map();
  setKeychainBackend({
    name: "test-fake",
    available: () => true,
    store: (account, secret) => void store.set(account, secret),
    lookup: (account) => store.get(account),
    forget: (account) => store.delete(account),
  });
  try {
    const first = tempDir("keychain-a");
    const second = tempDir("keychain-b");
    assert.notEqual(accountFor(first), accountFor(second));
    assert.equal(keychain().name, "test-fake");

    assert.equal(rememberPassphrase(first, "first-secret"), "test-fake");
    assert.equal(recallPassphrase(first), "first-secret");
    assert.equal(recallPassphrase(second), undefined);

    delete process.env.SBRAIN_PASSPHRASE;
    assert.equal(await getPassphrase({ vaultDir: first }), "first-secret");

    process.env.SBRAIN_PASSPHRASE = "environment-wins";
    assert.equal(await getPassphrase({ vaultDir: first }), "environment-wins");
    delete process.env.SBRAIN_PASSPHRASE;

    assert.equal(forgetPassphrase(first), true);
    assert.equal(forgetPassphrase(first), false);
    assert.equal(recallPassphrase(first), undefined);
  } finally {
    setKeychainBackend(undefined);
    delete process.env.SBRAIN_PASSPHRASE;
  }
});

test("frontmatter keeps its comments, order and style through a round-trip", () => {
  const vaultDir = tempDir("frontmatter");
  const vault = new DocumentVault(vaultDir, PASSPHRASE);
  const original = [
    "---",
    "# how this note is filed",
    'title: "Quoted title"',
    "status: living   # reviewed every quarter",
    "tags:",
    "  - product",
    "  - evergreen",
    "confidence: 0.92",
    "---",
    "# Quoted title",
    "",
    "Body stays exactly as written.",
  ].join("\n");

  const note = vault.importMarkdown("Atlas/Round trip.md", original);
  const exported = vault.exportMarkdown(note.id);

  assert.match(exported, /# how this note is filed/u);
  // Comments survive; their exact column does not (the emitter re-pads them).
  assert.match(exported, /status: living\s+# reviewed every quarter/u);
  assert.match(exported, /tags:\n {2}- product\n {2}- evergreen/u);
  assert.match(exported, /title: "Quoted title"/u);
  assert.ok(exported.indexOf("title:") < exported.indexOf("status:"), "original key order survives");
  assert.match(exported, /confidence: 0\.92/u);
  assert.ok(exported.endsWith("Body stays exactly as written."), "body is untouched");
  assert.match(exported, /sbrain_id: /u);

  // Changing one property rewrites that entry and leaves the rest alone.
  const updated = vault.put({
    id: note.id,
    path: note.path,
    title: note.title,
    body: note.body,
    aliases: note.aliases,
    tags: note.tags,
    properties: { ...note.properties, status: "archived" },
  });
  const afterEdit = vault.exportMarkdown(updated.id);
  assert.match(afterEdit, /status: archived/u);
  assert.match(afterEdit, /# how this note is filed/u);
  assert.match(afterEdit, /title: "Quoted title"/u);
  assert.doesNotMatch(afterEdit, /status: living/u);
});

test("applyFrontmatter adds, updates and removes keys without reformatting the rest", () => {
  const source = ["# leading note", 'kept: "as written"', "removed: true", "changed: 1"].join("\n");
  const result = applyFrontmatter(source, { kept: "as written", changed: 2, added: "new" }, "body");
  const parsed = parseFrontmatter(result);

  assert.deepEqual(parsed.attributes, { kept: "as written", changed: 2, added: "new" });
  assert.equal(parsed.body, "body");
  assert.match(result, /# leading note/u);
  assert.match(result, /kept: "as written"/u);
  assert.doesNotMatch(result, /removed:/u);
  assert.match(result, /changed: 2/u);
  assert.match(result, /added: new/u);

  // Frontmatter we cannot parse falls back to a clean re-serialization.
  const broken = applyFrontmatter("this: [is: not: yaml", { a: 1 }, "body");
  assert.deepEqual(parseFrontmatter(broken).attributes, { a: 1 });
});
