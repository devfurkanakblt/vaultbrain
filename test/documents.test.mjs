import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { DocumentVault } from "../dist/documents.js";
import { analyzeMarkdown, normalizeNotePath } from "../dist/markdown.js";

const PASSPHRASE = "document-vault-test-passphrase";

function tempVault() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "vault-brain-documents-test-"));
}

test("Markdown analysis extracts knowledge structure but ignores code", () => {
  const analysis = analyzeMarkdown(
    [
      "# Project Alpha",
      "See [[People/Ada#Biography|Ada]] and ![[Diagram]].",
      "#project/active #important",
      "`[[Ignored]] #ignored`",
      "```md",
      "[[Also ignored]] #ignored-too",
      "```",
    ].join("\n"),
  );

  assert.deepEqual(
    analysis.links.map((link) => link.target),
    ["People/Ada", "Diagram"],
  );
  assert.deepEqual(analysis.tags, ["important", "project/active"]);
  assert.deepEqual(analysis.headings, [{ level: 1, text: "Project Alpha", slug: "project-alpha" }]);
  assert.equal(analysis.links[0].heading, "Biography");
  assert.equal(analysis.links[0].alias, "Ada");
  assert.equal(analysis.links[1].embed, true);
});

test("document vault provides encrypted notes, stable revisions, search and backlinks", () => {
  const dir = tempVault();
  const vault = new DocumentVault(dir, PASSPHRASE);
  const alpha = vault.put({
    path: "Projects/Alpha",
    title: "Project Alpha",
    body: "# Alpha\nSecret launch plan. Owner: [[People/Ada]]. #project/active",
    properties: { status: "active", priority: 1 },
  });
  const ada = vault.put({
    path: "People/Ada.md",
    title: "Ada Lovelace",
    aliases: ["Ada"],
    body: "# Biography\nWorks on [[Projects/Alpha]]. #person",
  });

  const updated = vault.put({
    path: "Projects/Alpha.md",
    title: "Project Alpha",
    body: "# Alpha\nSecret launch plan updated. Owner: [[People/Ada]]. #project/active",
    properties: { status: "active", priority: 2 },
  });
  assert.equal(updated.id, alpha.id);
  assert.equal(updated.revision, 2);
  assert.equal(vault.get("Project Alpha").properties.priority, 2);
  assert.throws(
    () => vault.put({ id: alpha.id, path: alpha.path, body: "stale overwrite", baseRevision: 1 }),
    /note revision conflict/iu,
  );
  assert.match(vault.get(alpha.id).body, /updated/u);

  const search = vault.search('"launch plan" tag:project/active');
  assert.equal(search.length, 1);
  assert.equal(search[0].id, alpha.id);
  assert.match(search[0].excerpt, /launch plan/iu);
  assert.deepEqual(
    vault.backlinks(alpha.id).map((note) => note.id),
    [ada.id],
  );
  assert.equal(vault.outgoing(alpha.id)[0].resolvedId, ada.id);

  const diskText =
    fs
      .readdirSync(path.join(dir, "documents", "objects"))
      .map((name) => fs.readFileSync(path.join(dir, "documents", "objects", name), "utf8"))
      .join("\n") + fs.readFileSync(path.join(dir, "documents", "index.enc"), "utf8");
  assert.equal(diskText.includes("Secret launch plan"), false);
  assert.equal(diskText.includes("Ada Lovelace"), false);
});

test("document key is derived once per unlocked vault session and wrong passwords fail", () => {
  const dir = tempVault();
  const vault = new DocumentVault(dir, PASSPHRASE);
  vault.put({ path: "Inbox", body: "hello" });
  assert.throws(() => new DocumentVault(dir, "wrong passphrase"), /wrong passphrase/iu);
});

test("portable Markdown export imports into another encrypted vault", () => {
  const sourceDir = tempVault();
  const source = new DocumentVault(sourceDir, PASSPHRASE);
  const note = source.put({
    path: "Journal/Today.md",
    title: "Today",
    body: "A **portable** note with [[Another]].",
    aliases: ["Daily"],
    tags: ["journal"],
    properties: { mood: "great", score: 9 },
  });
  const portable = source.exportMarkdown(note.id);

  const targetDir = tempVault();
  const target = new DocumentVault(targetDir, "another-passphrase");
  const imported = target.importMarkdown("Imported/Today.md", portable);
  assert.equal(imported.id, note.id);
  assert.equal(imported.title, "Today");
  assert.equal(imported.body, note.body);
  assert.deepEqual(imported.properties, note.properties);
  assert.deepEqual(imported.aliases, note.aliases);

  fs.unlinkSync(path.join(targetDir, "documents", "index.enc"));
  const rebuilt = new DocumentVault(targetDir, "another-passphrase");
  assert.equal(rebuilt.list()[0].id, note.id);
});

test("logical note paths cannot traverse or become absolute", () => {
  assert.throws(() => normalizeNotePath("../outside.md"));
  assert.throws(() => normalizeNotePath("folder/../../outside.md"));
  assert.throws(() => normalizeNotePath("C:\\outside.md"));
  assert.equal(normalizeNotePath("Fikirler/Yeni ürün"), "Fikirler/Yeni ürün.md");
});

test("reverse link index incrementally resolves, invalidates and reports links", () => {
  const dir = tempVault();
  const vault = new DocumentVault(dir, PASSPHRASE);
  const source = vault.put({ path: "Source", body: "Waiting for [[Future]]." });
  assert.equal(vault.unresolvedLinks().length, 1);

  const target = vault.put({ path: "Future", body: "Now I exist." });
  assert.deepEqual(
    vault.backlinks(target.id).map((note) => note.id),
    [source.id],
  );
  assert.equal(vault.unresolvedLinks().length, 0);

  const renamed = vault.rename(target.id, "Archive/Renamed", "Renamed");
  assert.equal(renamed.id, target.id);
  assert.equal(renamed.revision, 2);
  assert.equal(vault.backlinks(target.id).length, 0);
  assert.equal(vault.unresolvedLinks()[0].links[0].target, "Future");

  vault.put({ path: "Source", body: "Updated link: [[Archive/Renamed]]." });
  assert.deepEqual(
    vault.backlinks(target.id).map((note) => note.id),
    [source.id],
  );
  assert.equal(vault.outgoing(source.id)[0].resolvedId, target.id);
});

test("encrypted history restores active and deleted notes with monotonic revisions", () => {
  const dir = tempVault();
  const vault = new DocumentVault(dir, PASSPHRASE);
  const first = vault.put({ path: "Journal", body: "first version" });
  const second = vault.put({ path: "Journal", body: "second version" });
  assert.equal(second.revision, 2);
  assert.deepEqual(
    vault.revisions(first.id).map((item) => item.revision),
    [2, 1],
  );
  assert.equal(vault.getRevision(first.id, 1).body, "first version");

  const restored = vault.restore(first.id, 1);
  assert.equal(restored.revision, 3);
  assert.equal(restored.body, "first version");
  vault.remove(first.id);
  assert.deepEqual(
    vault.revisions(first.id).map((item) => item.revision),
    [3, 2, 1],
  );

  const recoveredDeleted = vault.restore(first.id, 2);
  assert.equal(recoveredDeleted.revision, 4);
  assert.equal(recoveredDeleted.body, "second version");
  assert.equal(recoveredDeleted.id, first.id);
});

test("attachments are deduplicated, chunk-encrypted and integrity checked", () => {
  const dir = tempVault();
  const vault = new DocumentVault(dir, PASSPHRASE);
  const data = Buffer.alloc(1024 * 1024 + 137, 0x5a);
  Buffer.from("private attachment prefix").copy(data, 0);
  const first = vault.putAttachment(data, "private-report.bin", "application/octet-stream");
  const duplicate = vault.putAttachment(data, "different-name.bin", "application/octet-stream");
  assert.equal(first.id, duplicate.id);
  assert.equal(first.chunks, 2);
  assert.deepEqual(vault.getAttachment(first.id).data, data);
  assert.equal(vault.listAttachments().length, 1);

  const attachmentDir = path.join(dir, "documents", "attachments", first.id);
  const diskText = fs
    .readdirSync(attachmentDir)
    .map((name) => fs.readFileSync(path.join(attachmentDir, name), "utf8"))
    .join("\n");
  assert.equal(diskText.includes("private-report.bin"), false);
  assert.equal(diskText.includes("private attachment prefix"), false);

  const chunkPath = path.join(attachmentDir, "0.chunk.enc");
  const chunk = JSON.parse(fs.readFileSync(chunkPath, "utf8"));
  chunk.ciphertext = `${chunk.ciphertext[0] === "A" ? "B" : "A"}${chunk.ciphertext.slice(1)}`;
  fs.writeFileSync(chunkPath, JSON.stringify(chunk));
  assert.throws(() => vault.getAttachment(first.id));
  assert.equal(vault.removeAttachment(first.id).id, first.id);
  assert.equal(vault.listAttachments().length, 0);
});
