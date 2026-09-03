/**
 * Regenerates the checked-in format fixtures under test/fixtures/.
 *
 * These files exist so a future change to the storage format has to prove it
 * can still open what earlier versions wrote. Run with:
 *
 *   npm run build && node scripts/make-fixtures.mjs
 *
 * Only run this deliberately: overwriting a fixture destroys the evidence that
 * the old format is still readable. Adding a NEW fixture directory for a new
 * format version is almost always the right move instead.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { appendAudit } from "../dist/audit.js";
import { DocumentVault } from "../dist/documents.js";
import { migrateToKeyring } from "../dist/keyring-migrate.js";
import { upsertEntry } from "../dist/store.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.resolve(here, "..", "test", "fixtures");
export const FIXTURE_PASSPHRASE = "fixture-only-passphrase";

function writeCanvasFixture() {
  const canvasDir = path.join(fixtures, "documents-canvas-v1");
  fs.rmSync(canvasDir, { recursive: true, force: true });
  fs.mkdirSync(canvasDir, { recursive: true });
  const canvasVault = new DocumentVault(canvasDir, FIXTURE_PASSPHRASE);
  const note = canvasVault.put({
    path: "Atlas/Canvas contract.md",
    title: "Canvas contract",
    body: "# Canvas contract\n\nThe encrypted board beside this note must stay readable. #fixture",
    properties: { status: "frozen" },
  });
  canvasVault.putCanvas({
    path: "Boards/Frozen roadmap.canvas",
    title: "Frozen roadmap",
    nodes: [
      {
        id: "contract",
        type: "file",
        noteId: note.id,
        file: note.path,
        x: 0,
        y: 0,
        width: 320,
        height: 200,
      },
      {
        id: "text",
        type: "text",
        text: "This fixture links to [[Atlas/Canvas contract]].",
        x: 400,
        y: 0,
        width: 320,
        height: 200,
      },
    ],
    edges: [{ id: "edge", fromNode: "contract", toNode: "text", toEnd: "arrow" }],
  });
  fs.rmSync(path.join(canvasDir, ".sbrain.lock"), { force: true });
}

if (process.argv.includes("--canvas-only")) {
  writeCanvasFixture();
  console.log(`Canvas fixture written to ${path.join(fixtures, "documents-canvas-v1")}`);
  process.exit(0);
}

/** The pre-versioning envelope, reproduced exactly as v0 wrote it. */
function encryptLegacy(plaintext, passphrase) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(passphrase, salt, 32, { N: 2 ** 15, maxmem: 64 * 1024 * 1024 });
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return {
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64"),
    ciphertext: enc.toString("base64"),
  };
}

const legacyDir = path.join(fixtures, "kv-envelope-v0");
fs.rmSync(legacyDir, { recursive: true, force: true });
fs.mkdirSync(legacyDir, { recursive: true });
const legacyPlaintext = [
  "# @desc: Dummy blood type for format tests",
  'BLOOD_TYPE="0 Rh+"',
  "",
  '# @desc: Dummy appointment with a quoted \\"note\\" inside',
  'DOCTOR_NEXT_APPOINTMENT="2026-09-15"',
  "",
].join("\n");
fs.writeFileSync(
  path.join(legacyDir, "health.kv.enc"),
  JSON.stringify(encryptLegacy(legacyPlaintext, FIXTURE_PASSPHRASE), null, 2),
  { mode: 0o600 },
);

const documentDir = path.join(fixtures, "documents-v1");
fs.rmSync(documentDir, { recursive: true, force: true });
fs.mkdirSync(documentDir, { recursive: true });
const vault = new DocumentVault(documentDir, FIXTURE_PASSPHRASE);
vault.putMany([
  {
    path: "Atlas/Format contract.md",
    title: "Format contract",
    body: "# Format contract\n\nThis fixture must stay readable. It links to [[Atlas/Second note]].\n\n#fixture",
    properties: { status: "frozen", ordinal: 1 },
    aliases: ["Contract"],
  },
  {
    path: "Atlas/Second note.md",
    title: "Second note",
    body: "# Second note\n\nBacklink target for the fixture. #fixture",
    properties: { status: "frozen", ordinal: 2 },
  },
]);

/**
 * Attachments written by the TypeScript core, opened by the Rust desktop core's
 * own test suite. Content addressing only holds if both implementations derive
 * the same attachment ID and authenticate the same associated data, so this
 * fixture is the gate that catches either one drifting.
 */
const attachmentDir = path.join(fixtures, "documents-attachments-v1");
fs.rmSync(attachmentDir, { recursive: true, force: true });
fs.mkdirSync(attachmentDir, { recursive: true });
const attachmentVault = new DocumentVault(attachmentDir, FIXTURE_PASSPHRASE);
attachmentVault.putMany([
  {
    path: "Atlas/Attachment contract.md",
    title: "Attachment contract",
    body: "# Attachment contract\n\nThe attachments beside this note must stay readable. #fixture",
    properties: { status: "frozen" },
  },
]);
attachmentVault.putAttachment(
  Buffer.from("This attachment was written by the TypeScript core and must stay readable.\n", "utf8"),
  "frozen-note.txt",
  "text/plain",
);
attachmentVault.putAttachment(
  Buffer.from(Array.from({ length: 4096 }, (_value, index) => index % 256)),
  "frozen-payload.bin",
  "application/octet-stream",
);
fs.rmSync(path.join(attachmentDir, ".sbrain.lock"), { force: true });

writeCanvasFixture();

function writeKeyringFixture() {
  const dir = path.join(fixtures, "keyring-v2");
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });

  const vault = new DocumentVault(dir, FIXTURE_PASSPHRASE);
  vault.put({
    path: "Atlas/Keyring contract.md",
    title: "Keyring contract",
    body: "# Keyring contract\n\nThe wrapped keyset must stay openable. #fixture",
    properties: { status: "frozen" },
  });
  vault.putAttachment(Buffer.from("keyring fixture attachment"), "keyring.txt", "text/plain");
  vault.lock();

  upsertEntry(dir, "health", "BLOOD_TYPE", "0 Rh+", "blood group", FIXTURE_PASSPHRASE);
  appendAudit(dir, { actor: "cli-direct-write", file: "health", key: "BLOOD_TYPE" }, FIXTURE_PASSPHRASE);

  migrateToKeyring(dir, FIXTURE_PASSPHRASE);
  fs.rmSync(path.join(dir, ".sbrain.lock"), { force: true });
}
writeKeyringFixture();

fs.writeFileSync(
  path.join(fixtures, "README.md"),
  `# Format fixtures

Checked-in vaults written by earlier releases. Vault Brain is the product name,
but these fixtures retain immutable pre-rename storage and cryptographic
identifiers so tests prove upgrades do not orphan existing data.

**Passphrase for every fixture here: \`${FIXTURE_PASSPHRASE}\`.**

They contain dummy data only. Never point a fixture at a real vault.

| Directory | Format | What it pins |
|---|---|---|
| \`kv-envelope-v0/\` | key-value envelope, pre-versioning | Unversioned \`{salt,iv,authTag,ciphertext}\` files still decrypt, and \`vbrain migrate\` upgrades them in place |
| \`documents-v1/\` | document vault manifest v1, index v2 | An encrypted note vault written by the current format still opens, searches and resolves links |
| \`documents-attachments-v1/\` | document vault with chunk-encrypted attachments | Content-addressed attachments written by the TypeScript core still open in the Rust desktop core |
| \`documents-canvas-v1/\` | document vault with encrypted canvas objects | Canvas objects, identities, references and AAD written by the TypeScript core stay readable |
| \`keyring-v2/\` | vault keyring v2, keyset v1, key-value envelope v2 | A migrated vault opens through its wrapped keyset, its key-value files use the keyed envelope, and its adopted audit chain still verifies |

Regenerate deliberately (see \`scripts/make-fixtures.mjs\`) — overwriting a
fixture throws away the evidence it was there to provide. To cover a new
format version, add a new directory instead of editing an old one.
`,
);

console.log(`Fixtures written to ${fixtures}`);
