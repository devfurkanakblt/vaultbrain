import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createBackup, restoreBackup, verifyBackup } from "../dist/backup.js";
import { DocumentVault } from "../dist/documents.js";

const PASSPHRASE = "vault-backup-test-passphrase";

function tempDirectory(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), label));
}

/** A vault with one of everything a backup has to carry. */
function seededVault() {
  const dir = tempDirectory("vault-brain-backup-vault-");
  const vault = new DocumentVault(dir, PASSPHRASE);
  const attachment = vault.putAttachment(Buffer.from("diagram bytes"), "diagram.png", "image/png");
  const note = vault.put({
    path: "People/Ada.md",
    title: "Ada",
    tags: ["person"],
    body: "# Ada\n\nA sentence that must survive the round trip.\n",
  });
  // A second revision, so history is part of what the archive carries.
  vault.put({ id: note.id, path: note.path, title: "Ada", body: "# Ada\n\nEdited.\n", baseRevision: 1 });
  const canvas = vault.putCanvas({
    path: "Boards/Roadmap.canvas",
    title: "Roadmap",
    nodes: [{ id: "n1", type: "text", text: "Ship backup", x: 0, y: 0, width: 200, height: 100 }],
    edges: [],
  });
  return { dir, note, canvas, attachment };
}

test("a backup round-trips a whole vault into a directory that opens with the same passphrase", () => {
  const { dir, note, canvas, attachment } = seededVault();
  const outside = tempDirectory("vault-brain-backup-out-");
  const archive = path.join(outside, "vault.vbrainbackup");

  const report = createBackup(dir, archive, PASSPHRASE);

  assert.equal(report.archive, archive);
  assert.ok(report.files > 0);
  assert.equal(report.archiveBytes, fs.statSync(archive).size);

  // Verification is a read: it reports the same shape without writing.
  const verified = verifyBackup(archive, PASSPHRASE);
  assert.equal(verified.files, report.files);
  assert.equal(verified.bytes, report.bytes);
  assert.equal(verified.createdAt, report.createdAt);
  assert.equal(verified.formatVersion, "1.0");

  const destination = path.join(outside, "restored");
  const restored = restoreBackup(archive, destination, PASSPHRASE);
  assert.equal(restored.destination, destination);
  assert.equal(restored.files, report.files);

  const reopened = new DocumentVault(destination, PASSPHRASE);
  assert.equal(reopened.get(note.id).body.trim(), "# Ada\n\nEdited.".trim());
  assert.equal(reopened.get(note.id).revision, 2);
  assert.equal(reopened.revisions(note.id).length >= 1, true);
  assert.equal(reopened.getCanvas(canvas.id).title, "Roadmap");
  assert.equal(reopened.getAttachment(attachment.id).data.toString("utf8"), "diagram bytes");
  assert.equal(reopened.list().length, 1);
});

test("the archive is encrypted, and carries no session file", () => {
  const { dir } = seededVault();
  const outside = tempDirectory("vault-brain-backup-shape-");
  const archive = path.join(outside, "vault.vbrainbackup");
  createBackup(dir, archive, PASSPHRASE);

  const bytes = fs.readFileSync(archive);
  assert.equal(bytes.includes(Buffer.from("A sentence that must survive")), false);
  assert.equal(bytes.includes(Buffer.from("Ship backup")), false);
  assert.equal(bytes.includes(Buffer.from("diagram bytes")), false);

  // The header is readable, and names the keyring a restore needs.
  const header = JSON.parse(bytes.subarray(0, bytes.indexOf(0x0a)).toString("utf8"));
  assert.equal(header.kind, "vaultbrain-backup");
  assert.equal(header.version, 1);
  assert.equal(JSON.parse(header.keyring).version, 2);
  assert.equal(header.files.some((entry) => entry.path === "keyring.json"), false);
  assert.equal(header.files.some((entry) => entry.path === ".sbrain.lock"), false);
  assert.ok(header.files.some((entry) => entry.path.startsWith("documents/objects/")));
});

test("a backup the passphrase cannot open is refused before anything is written", () => {
  const { dir } = seededVault();
  const outside = tempDirectory("vault-brain-backup-wrong-");
  const archive = path.join(outside, "vault.vbrainbackup");
  createBackup(dir, archive, PASSPHRASE);
  const destination = path.join(outside, "restored");

  assert.throws(() => verifyBackup(archive, "not-the-passphrase"), /Unable to unlock/u);
  assert.throws(() => restoreBackup(archive, destination, "not-the-passphrase"), /Unable to unlock/u);
  assert.equal(fs.existsSync(destination), false);
  // The staging directory is gone too: a failed restore leaves no debris.
  assert.deepEqual(
    fs.readdirSync(outside).filter((name) => name.includes("restoring")),
    [],
  );
});

test("an altered archive is refused rather than half-restored", () => {
  const { dir } = seededVault();
  const outside = tempDirectory("vault-brain-backup-tamper-");
  const archive = path.join(outside, "vault.vbrainbackup");
  createBackup(dir, archive, PASSPHRASE);
  const original = fs.readFileSync(archive);

  // A byte in the sealed body: the entry's AEAD tag catches it.
  const body = Buffer.from(original);
  body[body.length - 40] ^= 0xff;
  fs.writeFileSync(archive, body);
  assert.throws(() => verifyBackup(archive, PASSPHRASE), /does not open/u);
  assert.throws(() => restoreBackup(archive, path.join(outside, "a"), PASSPHRASE), /does not open/u);
  assert.equal(fs.existsSync(path.join(outside, "a")), false);

  // A byte in the header line: the seal over the header catches it.
  const headerEnd = original.indexOf(0x0a);
  const header = Buffer.from(original);
  const digitAt = header.indexOf(Buffer.from('"size":'), 0) + 7;
  header[digitAt] = header[digitAt] === 0x39 ? 0x38 : header[digitAt] + 1;
  assert.ok(digitAt < headerEnd);
  fs.writeFileSync(archive, header);
  assert.throws(() => verifyBackup(archive, PASSPHRASE), /does not match its seal/u);

  // A truncated archive: the header describes bytes that are not there.
  fs.writeFileSync(archive, original.subarray(0, original.length - 64));
  assert.throws(() => verifyBackup(archive, PASSPHRASE), /truncated/u);

  // Appended bytes are not silently ignored either.
  fs.writeFileSync(archive, Buffer.concat([original, Buffer.from("extra")]));
  assert.throws(() => verifyBackup(archive, PASSPHRASE), /bytes its header does not describe/u);

  // The unaltered archive still restores, so none of the above was a false alarm.
  fs.writeFileSync(archive, original);
  assert.equal(restoreBackup(archive, path.join(outside, "good"), PASSPHRASE).files > 0, true);
});

test("a restore refuses to land on a directory that already holds something", () => {
  const { dir } = seededVault();
  const outside = tempDirectory("vault-brain-backup-refuse-");
  const archive = path.join(outside, "vault.vbrainbackup");
  createBackup(dir, archive, PASSPHRASE);

  const occupied = path.join(outside, "occupied");
  fs.mkdirSync(occupied);
  fs.writeFileSync(path.join(occupied, "keyring.json"), "someone else's vault");

  assert.throws(() => restoreBackup(archive, occupied, PASSPHRASE), /not empty/u);
  assert.deepEqual(fs.readdirSync(occupied), ["keyring.json"]);
  assert.equal(fs.readFileSync(path.join(occupied, "keyring.json"), "utf8"), "someone else's vault");

  // An empty directory is fine: it is a destination, not a vault.
  const empty = path.join(outside, "empty");
  fs.mkdirSync(empty);
  assert.equal(restoreBackup(archive, empty, PASSPHRASE).files > 0, true);
});

test("a backup refuses to overwrite a file or to be written inside the vault", () => {
  const { dir } = seededVault();
  const outside = tempDirectory("vault-brain-backup-place-");
  const archive = path.join(outside, "vault.vbrainbackup");
  createBackup(dir, archive, PASSPHRASE);

  assert.throws(() => createBackup(dir, archive, PASSPHRASE), /Refusing to overwrite/u);
  assert.throws(
    () => createBackup(dir, path.join(dir, "inside.vbrainbackup"), PASSPHRASE),
    /outside the vault it protects/u,
  );
  assert.equal(fs.existsSync(path.join(dir, "inside.vbrainbackup")), false);
});
