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
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { appendAudit } from "../dist/audit.js";
import { openDocumentKey } from "../dist/document-crypto.js";
import { DocumentVault } from "../dist/documents.js";
import { migrateToKeyring } from "../dist/keyring-migrate.js";
import { upsertEntry } from "../dist/store.js";
import {
  SyncChangeLog,
  SyncDeviceManager,
  SyncedDocumentVault,
  parseAttachmentSnapshot,
  sealSyncChange,
} from "../dist/sync.js";

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

/**
 * A vault that has been through one epoch rotation: an owner device, a revoked
 * device, a pre-rotation change sealed at epoch 1 and a post-rotation change
 * sealed with the epoch 2 content key. Pins the version 2 registry and
 * envelope shapes, and the fact that both envelope versions coexist.
 */
function writeSyncEpochFixture() {
  const dir = path.join(fixtures, "sync-epoch-v2");
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });

  const ownerId = "11111111-1111-4111-8111-111111111111";
  const revokedId = "22222222-2222-4222-8222-222222222222";
  const noteId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const mutation = (baseRevision, revision, body) => ({
    objectType: "note",
    objectId: noteId,
    operation: "put",
    baseRevision,
    revision,
    value: { title: "Frozen", body },
  });

  const manager = new SyncDeviceManager(dir, FIXTURE_PASSPHRASE);
  manager.initializeOwner("Owner laptop", ownerId, "2026-09-03T00:00:00.000Z");

  // A second device is required to produce a proof-of-possession enrollment
  // request, but two independently created vaults can never share key
  // material (each derives from its own random KDF salt). So the peer is a
  // copy of the owner's freshly initialized vault, in a temporary directory,
  // with the owner's private keys stripped -- it never gets committed.
  const peerDir = fs.mkdtempSync(path.join(os.tmpdir(), "secondbrain-fixture-peer-"));
  fs.rmSync(peerDir, { recursive: true, force: true });
  fs.cpSync(dir, peerDir, { recursive: true });
  fs.rmSync(path.join(peerDir, "documents", "sync", "identity", "authority.key.enc"));
  fs.rmSync(path.join(peerDir, "documents", "sync", "identity", `${ownerId}.key.enc`));
  fs.rmSync(path.join(peerDir, "documents", "sync", "identity", `${ownerId}.x25519.key.enc`));

  const log = new SyncChangeLog(dir, FIXTURE_PASSPHRASE);
  const peer = new SyncDeviceManager(peerDir, FIXTURE_PASSPHRASE);
  try {
    manager.enroll(
      peer.createEnrollmentRequest("Travel laptop", revokedId, "2026-09-03T00:00:01.000Z"),
      "2026-09-03T00:00:01.000Z"
    );

    // Sealed at epoch 1 with the vault key.
    log.append(ownerId, mutation(null, 1, "before rotation"), "2026-09-03T00:00:02.000Z");
    manager.createCheckpoint(log.changes(), "2026-09-03T00:00:03.000Z");

    // Revocation rotates to epoch 2 and wraps the new key to the owner only.
    manager.revoke(revokedId, 1, "2026-09-03T00:00:04.000Z");

    // Sealed at epoch 2 with the wrapped content key.
    log.append(ownerId, mutation(1, 2, "after rotation"), "2026-09-03T00:00:05.000Z");
  } finally {
    log.close();
    manager.close();
    peer.close();
    fs.rmSync(peerDir, { recursive: true, force: true });
  }
}

/**
 * A vault whose attachment travels as blob references instead of base64 bytes.
 *
 * `source/` holds an owner-enrolled vault with two changes: a note change and
 * an attachment change carrying a `version: 3` body — the blob manifest form,
 * `filename`/`mime`/`size`/`chunks`/`blobs[]` — plus the four sealed 1 MiB
 * chunks staged under `documents/sync/blobs/`. `target/` is the very same
 * vault copied before the attachment existed, so it shares the key material
 * and the device registry and can admit and apply the change the way a second
 * device would.
 *
 * The writer stamps `version: 3` on a blob-manifest attachment change of its
 * own accord (`changeBodyVersion` in `src/sync.ts`), so the re-seal below now
 * rewrites the same body under the same change id rather than upgrading it,
 * as it once did. It is kept as a guard: if the writer ever stops choosing 3,
 * this fixture still pins a version 3 body instead of silently drifting.
 */
function writeAttachmentBlobFixture() {
  const dir = path.join(fixtures, "sync-attachment-blobs-v3");
  fs.rmSync(dir, { recursive: true, force: true });
  const sourceDir = path.join(dir, "source");
  const targetDir = path.join(dir, "target");
  fs.mkdirSync(sourceDir, { recursive: true });

  const ownerId = "11111111-1111-4111-8111-111111111111";

  const manager = new SyncDeviceManager(sourceDir, FIXTURE_PASSPHRASE);
  manager.initializeOwner("Owner laptop", ownerId, "2026-09-04T00:00:00.000Z");
  manager.close();

  let vault = new SyncedDocumentVault(sourceDir, FIXTURE_PASSPHRASE, ownerId);
  vault.put({
    path: "Atlas/Blob contract.md",
    title: "Blob contract",
    body: "# Blob contract\n\nThe attachment beside this note travels as blobs. #fixture",
    properties: { status: "frozen" },
  });
  vault.lock();
  fs.rmSync(path.join(sourceDir, ".sbrain.lock"), { force: true });

  // The receiving device: the same vault, before the attachment exists.
  fs.cpSync(sourceDir, targetDir, { recursive: true });

  // 1.5 MiB of deterministic bytes -> exactly two 1 MiB chunks, so the
  // recorded SHA-256 is stable across regenerations even though every sealed
  // chunk (and therefore every blob id) is fresh. Two chunks is the smallest
  // size that still pins multi-blob reassembly, chunk ordering and the AAD
  // index binding; the heavy 12-blob case is exercised at runtime by
  // test/sync-blob-transport.test.mjs rather than carried in git forever.
  const data = Buffer.alloc(1024 * 1024 + 512 * 1024);
  for (let index = 0; index < data.length; index += 1) data[index] = (index * 31 + 7) & 0xff;

  vault = new SyncedDocumentVault(sourceDir, FIXTURE_PASSPHRASE, ownerId);
  const info = vault.putAttachment(data, "frozen-blob.bin", "application/octet-stream");
  vault.lock();
  fs.rmSync(path.join(sourceDir, ".sbrain.lock"), { force: true });

  // Normalize the attachment change body to version 3 and re-seal. Nothing references its
  // ID -- it is the newest change on the device chain -- so replacing the file
  // leaves the DAG, the device sequence and the applied state consistent.
  const log = new SyncChangeLog(sourceDir, FIXTURE_PASSPHRASE);
  const changes = log.changes();
  log.close();
  const attachmentChange = changes.find((change) => change.mutation.objectType === "attachment");
  const { id: previousId, ...body } = attachmentChange;
  const session = openDocumentKey(sourceDir, FIXTURE_PASSPHRASE);
  let envelope;
  try {
    envelope = sealSyncChange({ ...body, version: 3 }, {
      syncChangeKey: session.syncChangeKey,
      syncEnvelopeKey: session.syncEnvelopeKey,
    });
  } finally {
    session.key.fill(0);
    session.attachmentIdKey.fill(0);
    session.syncChangeKey.fill(0);
    session.syncEnvelopeKey.fill(0);
  }
  const changesDir = path.join(sourceDir, "documents", "sync", "changes");
  fs.rmSync(path.join(changesDir, `${previousId}.change.enc`));
  fs.writeFileSync(path.join(changesDir, `${envelope.id}.change.enc`), JSON.stringify(envelope), { mode: 0o600 });

  // Read the fixture back through the ordinary reader, so a broken generator
  // fails here rather than in CI.
  const verify = new SyncChangeLog(sourceDir, FIXTURE_PASSPHRASE);
  const stored = verify.changes();
  verify.close();
  const reread = stored.find((change) => change.mutation.objectType === "attachment");
  if (reread.version !== 3) throw new Error("The attachment change body was not re-sealed at version 3.");
  const snapshot = parseAttachmentSnapshot(reread.mutation.value);
  if (snapshot.chunks !== 2) throw new Error("The blob fixture must hold exactly two chunks.");

  fs.writeFileSync(
    path.join(dir, "manifest.json"),
    `${JSON.stringify(
      {
        deviceId: ownerId,
        changeCount: stored.length,
        changeBodyVersion: reread.version,
        attachmentId: info.id,
        filename: snapshot.filename,
        mime: snapshot.mime,
        size: snapshot.size,
        chunks: snapshot.chunks,
        blobs: snapshot.blobs,
        sha256: crypto.createHash("sha256").update(data).digest("hex"),
      },
      null,
      2,
    )}\n`,
  );
  fs.rmSync(path.join(sourceDir, ".sbrain.lock"), { force: true });
  fs.rmSync(path.join(targetDir, ".sbrain.lock"), { force: true });
}

if (process.argv.includes("--blobs-only")) {
  writeAttachmentBlobFixture();
  console.log(`Attachment blob fixture written to ${path.join(fixtures, "sync-attachment-blobs-v3")}`);
  process.exit(0);
}

if (process.argv.includes("--canvas-only")) {
  writeCanvasFixture();
  console.log(`Canvas fixture written to ${path.join(fixtures, "documents-canvas-v1")}`);
  process.exit(0);
}

if (process.argv.includes("--keyring-only")) {
  writeKeyringFixture();
  console.log(`Keyring fixture written to ${path.join(fixtures, "keyring-v2")}`);
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
writeSyncEpochFixture();
writeAttachmentBlobFixture();

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
| \`sync-epoch-v2/\` | sync registry v2, change envelopes v1 and v2 | A rotated vault still opens: epoch 1 changes stay vault-key sealed, epoch 2 changes need the wrapped content key, and the revoked device holds no wrap |
| \`sync-attachment-blobs-v3/\` | sync change body v3, attachment blob manifest | An attachment change that carries \`size\`/\`chunks\`/\`blobs[]\` instead of base64 bytes still opens; \`source/\` stages the two sealed chunks, \`target/\` is the same vault before the attachment and reassembles it from them. \`manifest.json\` records the blob ids and the plaintext SHA-256 |

Regenerate deliberately (see \`scripts/make-fixtures.mjs\`) — overwriting a
fixture throws away the evidence it was there to provide. To cover a new
format version, add a new directory instead of editing an old one.

\`keyring-vector.json\` is written by \`scripts/make-keyring-vector.mjs\` and
refuses to overwrite itself without \`--force\`. Its passphrase is
\`vector-only-passphrase\`, not the shared fixture passphrase, because it is a
format vector rather than a vault.
`,
);

console.log(`Fixtures written to ${fixtures}`);
