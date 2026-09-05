import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { DocumentVault } from "../dist/documents.js";
import { exportVault } from "../dist/export.js";
import { importObsidianVault } from "../dist/obsidian-import.js";

const PASSPHRASE = "vault-export-test-passphrase";

function tempDirectory(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), label));
}

function read(root, relative) {
  return fs.readFileSync(path.join(root, ...relative.split("/")), "utf8");
}

function entries(root) {
  const found = [];
  const visit = (directory, prefix) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) visit(path.join(directory, entry.name), relative);
      else found.push(relative);
    }
  };
  visit(root, "");
  return found.sort();
}

test("a vault exports as Markdown, JSON Canvas and attachment files, and imports back whole", () => {
  const vaultDir = tempDirectory("vault-brain-export-vault-");
  const destination = path.join(tempDirectory("vault-brain-export-out-"), "export");
  const vault = new DocumentVault(vaultDir, PASSPHRASE);

  const diagram = vault.putAttachment(Buffer.from("diagram bytes"), "diagram.png", "image/png");
  const ada = vault.put({
    path: "People/Ada.md",
    title: "Ada",
    aliases: ["Ada L"],
    tags: ["person"],
    body: "# Ada\n\nWorks on [[Projects/Alpha]].\n",
    properties: { role: "engineer" },
  });
  const alpha = vault.put({
    path: "Projects/Alpha.md",
    title: "Alpha",
    body: "# Alpha\n\nOwner: [[People/Ada]].\n\nDiagram: ![[diagram.png]]\n",
  });
  vault.putCanvas({
    path: "Boards/Roadmap.canvas",
    title: "Roadmap",
    nodes: [
      { id: "n1", type: "text", text: "Ship export", x: 0, y: 0, width: 200, height: 100 },
      {
        id: "n2",
        type: "file",
        attachmentId: diagram.id,
        file: "diagram.png",
        x: 300,
        y: 0,
        width: 200,
        height: 100,
      },
    ],
    edges: [{ id: "e1", fromNode: "n1", toNode: "n2", toEnd: "arrow" }],
  });

  const report = exportVault(vaultDir, destination, PASSPHRASE);

  assert.equal(report.ok, true);
  assert.deepEqual(report.notes, { total: 2, written: 2 });
  assert.deepEqual(report.canvases, { total: 1, written: 1 });
  assert.equal(report.attachments.written, 1);
  assert.equal(report.attachments.bytes, Buffer.byteLength("diagram bytes"));
  assert.deepEqual(entries(destination), [
    "Boards/Roadmap.canvas",
    "People/Ada.md",
    "Projects/Alpha.md",
    "assets/diagram.png",
  ]);

  // Frontmatter carries the portable identity, so a re-import is the same note
  // rather than a copy of it.
  const exportedAda = read(destination, "People/Ada.md");
  assert.match(exportedAda, new RegExp(`vbrain_id: ${ada.id}`, "u"));
  assert.match(exportedAda, /role: engineer/u);
  assert.match(exportedAda, /Works on \[\[Projects\/Alpha\]\]/u);

  // The canvas names the attachment by its exported path, not its vault id.
  const roadmap = JSON.parse(read(destination, "Boards/Roadmap.canvas"));
  assert.equal(roadmap.nodes[1].file, "assets/diagram.png");
  assert.equal(fs.readFileSync(path.join(destination, "assets", "diagram.png"), "utf8"), "diagram bytes");

  // The export is the shape the importer reads: one format, not two.
  const reimported = tempDirectory("vault-brain-export-reimport-");
  const back = importObsidianVault(destination, reimported, PASSPHRASE);
  assert.equal(back.ok, true, JSON.stringify(back.issues));
  assert.equal(back.notes.imported, 2);
  assert.equal(back.canvases.imported, 1);
  assert.equal(back.attachments.imported, 1);

  const restored = new DocumentVault(reimported, PASSPHRASE);
  const restoredAlpha = restored.get(alpha.id);
  assert.equal(restoredAlpha.path, "Projects/Alpha.md");
  assert.equal(restoredAlpha.title, "Alpha");
  assert.match(restoredAlpha.body, /Owner: \[\[People\/Ada\]\]/u);
  assert.equal(restored.get(ada.id).properties.role, "engineer");
  assert.equal(
    restored.getAttachment(restored.listAttachments()[0].id).data.toString("utf8"),
    "diagram bytes",
  );
});

test("paths a filesystem cannot take are renamed rather than dropped, and the report says so", () => {
  const vaultDir = tempDirectory("vault-brain-export-names-");
  const destination = path.join(tempDirectory("vault-brain-export-names-out-"), "export");
  const vault = new DocumentVault(vaultDir, PASSPHRASE);

  // Every one of these is a legal vault path and an illegal Windows filename,
  // or collides with another only once a case-insensitive filesystem is
  // involved. Without the rename, each one is a note that does not arrive.
  vault.put({ path: "Q3: results.md", title: "Q3", body: "colon" });
  vault.put({ path: "aux.md", title: "aux", body: "reserved device name" });
  vault.put({ path: "Fine.md", title: "Fine", body: "portable already" });
  // Attachment filenames are not vault paths and are not deduplicated, so two
  // that differ only in case are two objects here and one file on Windows.
  vault.putAttachment(Buffer.from("upper"), "Cover.png", "image/png");
  vault.putAttachment(Buffer.from("lower"), "cover.png", "image/png");

  const report = exportVault(vaultDir, destination, PASSPHRASE);

  assert.equal(report.ok, true);
  assert.deepEqual(report.notes, { total: 3, written: 3 });
  assert.equal(report.attachments.written, 2);
  const written = entries(destination);
  assert.equal(written.length, 5);
  assert.ok(written.includes("Q3- results.md"), written.join(", "));
  assert.ok(written.includes("_aux.md"), written.join(", "));
  assert.ok(written.includes("Fine.md"), written.join(", "));

  // Both covers survive, under names that differ by more than case.
  const covers = written.filter((name) => /^assets\/cover/iu.test(name));
  assert.equal(covers.length, 2);
  assert.equal(new Set(covers.map((name) => name.toLowerCase())).size, 2);
  assert.deepEqual(covers.map((name) => read(destination, name)).sort(), ["lower", "upper"]);

  const adjusted = report.issues.filter((issue) => issue.code === "note-path-adjusted");
  assert.equal(adjusted.length, 2);
  assert.ok(adjusted.every((issue) => issue.severity === "warning"));
  assert.ok(adjusted.some((issue) => issue.reference === "Q3: results.md"));
  assert.ok(adjusted.every((issue) => issue.reference !== "Fine.md"));
});

test("two attachments sharing a filename both survive, and the ambiguity is reported", () => {
  const vaultDir = tempDirectory("vault-brain-export-assets-");
  const destination = path.join(tempDirectory("vault-brain-export-assets-out-"), "export");
  const vault = new DocumentVault(vaultDir, PASSPHRASE);
  const first = vault.putAttachment(Buffer.from("cover one"), "cover.png", "image/png");
  const second = vault.putAttachment(Buffer.from("cover two"), "cover.png", "image/png");
  vault.putCanvas({
    path: "Boards/Covers.canvas",
    title: "Covers",
    nodes: [
      { id: "a", type: "file", attachmentId: first.id, file: "cover.png", x: 0, y: 0, width: 100, height: 100 },
      { id: "b", type: "file", attachmentId: second.id, file: "cover.png", x: 200, y: 0, width: 100, height: 100 },
    ],
    edges: [],
  });

  const report = exportVault(vaultDir, destination, PASSPHRASE);

  assert.equal(report.attachments.written, 2);
  assert.deepEqual(entries(destination), [
    "Boards/Covers.canvas",
    "assets/cover (2).png",
    "assets/cover.png",
  ]);
  assert.deepEqual(
    ["assets/cover.png", "assets/cover (2).png"].map((name) => read(destination, name)).sort(),
    ["cover one", "cover two"],
  );
  assert.equal(report.issues.filter((issue) => issue.code === "ambiguous-attachment-name").length, 1);
  assert.equal(report.ok, true);

  // Each node names the file its own bytes were written to. Naming the
  // filename alone would send both nodes to whichever attachment won the
  // collision, and which one that is depends on the id ordering.
  const covers = JSON.parse(read(destination, "Boards/Covers.canvas"));
  const nodeFiles = Object.fromEntries(covers.nodes.map((node) => [node.id, node.file]));
  assert.notEqual(nodeFiles.a, nodeFiles.b);
  assert.equal(read(destination, nodeFiles.a), "cover one");
  assert.equal(read(destination, nodeFiles.b), "cover two");
});

test("an export refuses to land inside the vault, or on top of existing files", () => {
  const vaultDir = tempDirectory("vault-brain-export-refuse-");
  const outside = tempDirectory("vault-brain-export-refuse-out-");
  new DocumentVault(vaultDir, PASSPHRASE).put({ path: "Note.md", title: "Note", body: "body" });

  assert.throws(
    () => exportVault(vaultDir, path.join(vaultDir, "export"), PASSPHRASE),
    /outside the vault it exports/u,
  );
  assert.throws(() => exportVault(vaultDir, vaultDir, PASSPHRASE), /outside the vault it exports/u);

  fs.writeFileSync(path.join(outside, "already-here.txt"), "mine");
  assert.throws(() => exportVault(vaultDir, outside, PASSPHRASE), /not empty/u);
  // Nothing was written into the directory it refused.
  assert.deepEqual(fs.readdirSync(outside), ["already-here.txt"]);
});
