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

import { DocumentVault } from "../dist/documents.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.resolve(here, "..", "test", "fixtures");
export const FIXTURE_PASSPHRASE = "fixture-only-passphrase";

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
  "# @desc: Dummy appointment with a quoted \\\"note\\\" inside",
  'DOCTOR_NEXT_APPOINTMENT="2026-09-15"',
  "",
].join("\n");
fs.writeFileSync(
  path.join(legacyDir, "health.kv.enc"),
  JSON.stringify(encryptLegacy(legacyPlaintext, FIXTURE_PASSPHRASE), null, 2),
  { mode: 0o600 }
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

fs.writeFileSync(
  path.join(fixtures, "README.md"),
  `# Format fixtures

Checked-in vaults written by earlier releases. Tests open them to prove that a
change to the storage format did not silently orphan existing data.

**Passphrase for every fixture here: \`${FIXTURE_PASSPHRASE}\`.**

They contain dummy data only. Never point a fixture at a real vault.

| Directory | Format | What it pins |
|---|---|---|
| \`kv-envelope-v0/\` | key-value envelope, pre-versioning | Unversioned \`{salt,iv,authTag,ciphertext}\` files still decrypt, and \`sbrain migrate\` upgrades them in place |
| \`documents-v1/\` | document vault manifest v1, index v2 | An encrypted note vault written by the current format still opens, searches and resolves links |

Regenerate deliberately (see \`scripts/make-fixtures.mjs\`) — overwriting a
fixture throws away the evidence it was there to provide. To cover a new
format version, add a new directory instead of editing an old one.
`
);

console.log(`Fixtures written to ${fixtures}`);
