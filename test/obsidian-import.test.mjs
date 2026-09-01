import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { DocumentVault } from "../dist/documents.js";
import { importObsidianVault } from "../dist/obsidian-import.js";

const PASSPHRASE = "obsidian-import-test-passphrase";

function tempDirectory(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), label));
}

function write(root, relative, contents) {
  const destination = path.join(root, ...relative.split("/"));
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.writeFileSync(destination, contents);
}

test("an Obsidian vault imports notes, assets and canvases with a useful integrity report", () => {
  const source = tempDirectory("vault-brain-obsidian-source-");
  const destination = tempDirectory("vault-brain-obsidian-target-");
  write(source, ".obsidian/app.json", "{}");
  write(source, "People/Ada.md", ["---", "id: ada-human-slug", "aliases: [Ada]", "---", "# Ada"].join("\n"));
  write(
    source,
    "Projects/Alpha.md",
    [
      "# Alpha",
      "Owner: [[People/Ada]].",
      "Diagram: ![[assets/diagram.png]].",
      "Missing embed: ![[missing.png]].",
      "![Photo](../assets/photo.jpg)",
      "[Missing note](../People/Missing.md)",
    ].join("\n"),
  );
  write(source, "Broken.md", "---\na: 1\na: 2\n---\ninvalid frontmatter");
  write(source, "assets/diagram.png", Buffer.from("diagram"));
  write(source, "assets/photo.jpg", Buffer.from("photo"));
  write(source, "one/cover.png", Buffer.from("cover one"));
  write(source, "two/cover.png", Buffer.from("cover two"));
  write(
    source,
    "Boards/Overview.canvas",
    JSON.stringify({
      nodes: [
        { id: "note", type: "file", file: "People/Ada.md", x: 0, y: 0, width: 200, height: 100 },
        { id: "asset", type: "file", file: "assets/diagram.png", x: 250, y: 0, width: 200, height: 100 },
      ],
      edges: [],
    }),
  );

  const report = importObsidianVault(source, destination, PASSPHRASE);
  assert.equal(report.ok, false);
  assert.deepEqual(report.notes, { discovered: 3, imported: 2 });
  assert.deepEqual(report.attachments, { discovered: 4, imported: 4, unique: 4 });
  assert.deepEqual(report.canvases, { discovered: 1, imported: 1 });
  assert.equal(report.ignoredEntries, 1);
  assert.ok(report.issues.some((issue) => issue.code === "note-import-failed" && issue.path === "Broken.md"));
  assert.ok(
    report.issues.some((issue) => issue.code === "missing-attachment" && issue.reference === "![[missing.png]]"),
  );
  assert.ok(report.issues.some((issue) => issue.code === "missing-markdown-link"));
  assert.ok(report.issues.some((issue) => issue.code === "ambiguous-attachment-name"));
  assert.ok(!report.issues.some((issue) => issue.reference === "![[assets/diagram.png]]"));
  assert.ok(!report.issues.some((issue) => issue.reference === "../assets/photo.jpg"));

  const vault = new DocumentVault(destination, PASSPHRASE);
  assert.equal(vault.list().length, 2);
  assert.equal(vault.listAttachments().length, 4);
  assert.equal(vault.listCanvases().length, 1);
  assert.equal(vault.get("People/Ada").properties.id, "ada-human-slug");
  assert.equal(vault.outgoing("Projects/Alpha")[0].resolvedId, vault.get("People/Ada").id);
  const canvas = vault.getCanvas("Boards/Overview");
  assert.equal(canvas.nodes[0].noteId, vault.get("People/Ada").id);
  assert.ok(canvas.nodes[1].attachmentId);

  const encryptedText = fs
    .readdirSync(path.join(destination, "documents", "objects"))
    .map((name) => fs.readFileSync(path.join(destination, "documents", "objects", name), "utf8"))
    .join("\n");
  assert.equal(encryptedText.includes("ada-human-slug"), false);
  assert.equal(encryptedText.includes("# Alpha"), false);
});

test("the encrypted destination cannot be nested inside the source vault", () => {
  const source = tempDirectory("vault-brain-obsidian-nesting-");
  write(source, "Note.md", "hello");
  assert.throws(() => importObsidianVault(source, path.join(source, "encrypted"), PASSPHRASE), /must be outside/iu);
});
