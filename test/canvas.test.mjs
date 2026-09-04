import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { normalizeCanvasPath } from "../dist/canvas.js";
import { decryptDocument, encryptDocument, openDocumentKey } from "../dist/document-crypto.js";
import { DocumentVault } from "../dist/documents.js";

const PASSPHRASE = "canvas-vault-test-passphrase";

function tempVault(label = "canvas") {
  return fs.mkdtempSync(path.join(os.tmpdir(), `vault-brain-${label}-`));
}

function board(overrides = {}) {
  return {
    path: "Boards/Roadmap",
    nodes: [
      { id: "n1", type: "text", text: "Start here", x: 0, y: 0, width: 200, height: 100 },
      { id: "n2", type: "link", url: "https://example.com/spec", x: 300, y: 0, width: 200, height: 100 },
    ],
    edges: [{ id: "e1", fromNode: "n1", toNode: "n2", toEnd: "arrow" }],
    ...overrides,
  };
}

function canvasObjectPath(vaultDir, id) {
  return path.join(vaultDir, "documents", "objects", `${id}.canvas.enc`);
}

function indexPath(vaultDir) {
  return path.join(vaultDir, "documents", "index.enc");
}

function journalPath(vaultDir) {
  return path.join(vaultDir, "documents", "journal.json");
}

test("canvas paths normalize to a .canvas label and refuse traversal", () => {
  assert.equal(normalizeCanvasPath("Boards/Roadmap"), "Boards/Roadmap.canvas");
  assert.equal(normalizeCanvasPath("Boards\\Roadmap.canvas"), "Boards/Roadmap.canvas");
  assert.equal(normalizeCanvasPath("Boards/Roadmap.CANVAS"), "Boards/Roadmap.canvas");
  assert.throws(() => normalizeCanvasPath(""));
  assert.throws(() => normalizeCanvasPath("../outside"));
  assert.throws(() => normalizeCanvasPath("folder/../../outside"));
  assert.throws(() => normalizeCanvasPath("C:\\outside"));
});

test("a canvas round-trips with its own identity, revisions and optimistic concurrency", () => {
  const dir = tempVault();
  const vault = new DocumentVault(dir, PASSPHRASE);
  const created = vault.putCanvas(board());

  assert.equal(created.version, 1);
  assert.equal(created.path, "Boards/Roadmap.canvas");
  assert.equal(created.title, "Roadmap");
  assert.equal(created.revision, 1);
  assert.deepEqual(
    created.nodes.map((node) => node.id),
    ["n1", "n2"],
  );
  assert.equal(created.nodes[0].text, "Start here");
  assert.equal(created.nodes[1].url, "https://example.com/spec");
  assert.equal(created.edges[0].toEnd, "arrow");

  assert.deepEqual(vault.getCanvas(created.id), created);
  assert.deepEqual(vault.getCanvas("Boards/Roadmap.canvas"), created);
  assert.deepEqual(vault.getCanvas("Roadmap"), created);

  const updated = vault.putCanvas(board({ id: created.id, baseRevision: 1, title: "Product roadmap" }));
  assert.equal(updated.id, created.id);
  assert.equal(updated.revision, 2);
  assert.equal(updated.title, "Product roadmap");
  assert.equal(updated.createdAt, created.createdAt);

  // A write from a stale copy is refused rather than silently overwriting.
  assert.throws(() => vault.putCanvas(board({ id: created.id, baseRevision: 1 })), /revision 2/u);

  assert.deepEqual(vault.listCanvases(), [
    {
      id: created.id,
      path: "Boards/Roadmap.canvas",
      title: "Product roadmap",
      nodeCount: 2,
      edgeCount: 1,
      updatedAt: updated.updatedAt,
      revision: 2,
    },
  ]);

  const diskText =
    fs
      .readdirSync(path.join(dir, "documents", "objects"))
      .map((name) => fs.readFileSync(path.join(dir, "documents", "objects", name), "utf8"))
      .join("\n") + fs.readFileSync(path.join(dir, "documents", "index.enc"), "utf8");
  assert.equal(diskText.includes("Start here"), false);
  assert.equal(diskText.includes("Product roadmap"), false);
});

test("opening a canvas object as a note fails cryptographically, and the reverse", () => {
  const dir = tempVault();
  const vault = new DocumentVault(dir, PASSPHRASE);
  const canvas = vault.putCanvas(board());
  const note = vault.put({ path: "Notes/Plain.md", body: "# Plain" });

  const session = openDocumentKey(dir, PASSPHRASE);
  const canvasPayload = JSON.parse(fs.readFileSync(canvasObjectPath(dir, canvas.id), "utf8"));
  const notePayload = JSON.parse(
    fs.readFileSync(path.join(dir, "documents", "objects", `${note.id}.note.enc`), "utf8"),
  );

  assert.equal(
    JSON.parse(decryptDocument(canvasPayload, session.key, `secondbrain-vault:canvas:v1:${canvas.id}`)).id,
    canvas.id,
  );
  assert.throws(
    () => decryptDocument(canvasPayload, session.key, `secondbrain-vault:note:v1:${canvas.id}`),
    /unable to authenticate|bad decrypt/iu,
  );
  assert.throws(
    () => decryptDocument(notePayload, session.key, `secondbrain-vault:canvas:v1:${note.id}`),
    /unable to authenticate|bad decrypt/iu,
  );

  // The two ID spaces never collide through the public API either.
  assert.throws(() => vault.get(canvas.id), /not found/iu);
  assert.throws(() => vault.getCanvas(note.id), /not found/iu);
});

test("canvas history archives one revision per write and restores like a note", () => {
  const dir = tempVault();
  const vault = new DocumentVault(dir, PASSPHRASE);
  const first = vault.putCanvas(board());
  const second = vault.putCanvas(
    board({
      id: first.id,
      nodes: [{ id: "only", type: "text", text: "second", x: 0, y: 0, width: 10, height: 10 }],
      edges: [],
    }),
  );
  assert.equal(second.revision, 2);
  assert.deepEqual(
    vault.canvasRevisions(first.id).map((item) => item.revision),
    [2, 1],
  );
  assert.equal(vault.getCanvasRevision(first.id, 1).nodes.length, 2);

  const restored = vault.restoreCanvas(first.id, 1);
  assert.equal(restored.revision, 3);
  assert.deepEqual(
    restored.nodes.map((node) => node.id),
    ["n1", "n2"],
  );

  const removed = vault.removeCanvas(first.id);
  assert.equal(removed.id, first.id);
  assert.equal(vault.listCanvases().length, 0);
  assert.equal(fs.existsSync(canvasObjectPath(dir, first.id)), false);
  assert.deepEqual(
    vault.canvasRevisions(first.id).map((item) => item.revision),
    [3, 2, 1],
  );

  const recovered = vault.restoreCanvas(first.id, 2);
  assert.equal(recovered.id, first.id);
  assert.equal(recovered.revision, 4);
  assert.equal(recovered.nodes[0].text, "second");
});

test("renaming a canvas keeps its ID and frees the old label", () => {
  const dir = tempVault();
  const vault = new DocumentVault(dir, PASSPHRASE);
  const created = vault.putCanvas(board());
  const renamed = vault.renameCanvas(created.id, "Archive/Old roadmap");

  assert.equal(renamed.id, created.id);
  assert.equal(renamed.path, "Archive/Old roadmap.canvas");
  assert.equal(renamed.revision, 2);
  assert.equal(vault.getCanvas("Archive/Old roadmap").id, created.id);
  assert.throws(() => vault.getCanvas("Boards/Roadmap.canvas"), /not found/iu);
});

test("a file node keeps its note identity while its path label follows the note", () => {
  const dir = tempVault();
  const vault = new DocumentVault(dir, PASSPHRASE);
  const note = vault.put({ path: "People/Ada.md", title: "Ada Lovelace", body: "# Ada" });
  const canvas = vault.putCanvas({
    path: "Boards/People",
    nodes: [{ id: "ada", type: "file", noteId: note.id, file: "People/Ada.md", x: 0, y: 0, width: 400, height: 300 }],
    edges: [],
  });
  assert.deepEqual(
    vault.canvasesReferencing(note.id).map((item) => item.id),
    [canvas.id],
  );

  vault.rename(note.id, "Archive/Ada.md");
  const afterRename = vault.getCanvas(canvas.id);
  assert.equal(afterRename.nodes[0].file, "Archive/Ada.md");
  assert.equal(afterRename.nodes[0].noteId, note.id);
  assert.equal(afterRename.revision, 1, "re-deriving a label writes nothing to disk");

  vault.remove(note.id);
  const afterDelete = vault.getCanvas(canvas.id);
  assert.equal(afterDelete.nodes.length, 1, "a deleted note leaves a broken reference, not a lost node");
  assert.equal(afterDelete.nodes[0].noteId, note.id);
  assert.equal(afterDelete.nodes[0].file, "Archive/Ada.md");
  assert.deepEqual(
    vault.canvasesReferencing(note.id).map((item) => item.id),
    [canvas.id],
  );
});

test("canvas validation enforces every format limit at the storage boundary", () => {
  const vault = new DocumentVault(tempVault("validation"), PASSPHRASE);
  const putNodes = (nodes, edges = []) => vault.putCanvas({ path: "Boards/Invalid", nodes, edges });
  const textNode = (overrides = {}) => ({
    id: "node",
    type: "text",
    text: "ok",
    x: 0,
    y: 0,
    width: 10,
    height: 10,
    ...overrides,
  });

  assert.throws(() => putNodes([textNode({ id: "bad id" })]), /node ID/iu);
  assert.throws(() => putNodes([textNode(), textNode()]), /Duplicate canvas node ID/u);
  assert.throws(() => putNodes(Array.from({ length: 5_001 }, (_, i) => textNode({ id: `n${i}` }))), /5000/u);
  assert.throws(
    () =>
      putNodes(
        [textNode()],
        Array.from({ length: 10_001 }, (_, i) => ({ id: `e${i}`, fromNode: "node", toNode: "node" })),
      ),
    /10000/u,
  );
  assert.throws(() => putNodes([textNode({ x: 0.5 })]), /finite integer/u);
  assert.throws(() => putNodes([textNode({ width: 0 })]), /at least 1/u);
  assert.throws(() => putNodes([textNode({ y: 10_000_001 })]), /10000000/u);
  assert.throws(() => putNodes([textNode({ color: "red" })]), /preset 1-6/iu);
  assert.throws(() => putNodes([textNode({ text: "x".repeat(256 * 1024 + 1) })]), /256 KiB/u);
  assert.throws(
    () => putNodes([{ id: "g", type: "group", label: "two\nlines", x: 0, y: 0, width: 10, height: 10 }]),
    /single line/iu,
  );
  assert.throws(
    () => putNodes([{ id: "l", type: "link", url: "javascript:alert(1)", x: 0, y: 0, width: 10, height: 10 }]),
    /only http/iu,
  );
  assert.throws(
    () =>
      putNodes([{ id: "f", type: "file", noteId: "not-a-uuid", file: "Note.md", x: 0, y: 0, width: 10, height: 10 }]),
    /invalid noteId/u,
  );
  assert.throws(
    () =>
      putNodes([
        {
          id: "f",
          type: "file",
          noteId: "a".repeat(36),
          attachmentId: "b".repeat(64),
          file: "x",
          x: 0,
          y: 0,
          width: 10,
          height: 10,
        },
      ]),
    /cannot set both/u,
  );
  assert.throws(
    () =>
      putNodes([
        {
          id: "f",
          type: "file",
          attachmentId: "b".repeat(64),
          file: "x",
          subpath: "heading",
          x: 0,
          y: 0,
          width: 10,
          height: 10,
        },
      ]),
    /subpath/u,
  );
  assert.throws(
    () => putNodes([textNode()], [{ id: "edge", fromNode: "node", toNode: "missing" }]),
    /does not name a node/u,
  );
  assert.throws(
    () =>
      putNodes(
        [textNode()],
        [
          { id: "edge", fromNode: "node", toNode: "node" },
          { id: "edge", fromNode: "node", toNode: "node" },
        ],
      ),
    /Duplicate canvas edge ID/u,
  );
  assert.throws(
    () => putNodes(Array.from({ length: 32 }, (_, i) => textNode({ id: `large${i}`, text: "x".repeat(256 * 1024) }))),
    /8 MiB/u,
  );
});

test("JSON Canvas import/export preserves standard fields, binds identities and rejects unknown nodes", () => {
  const dir = tempVault("json-canvas");
  const vault = new DocumentVault(dir, PASSPHRASE);
  const note = vault.put({ path: "Notes/Golden.md", body: "# Golden" });
  const attachment = vault.putAttachment(Buffer.from("asset"), "diagram.png", "image/png");
  const goldenPath = path.join("test", "fixtures", "json-canvas-v1", "roadmap.canvas");
  const imported = vault.importCanvas("Boards/Golden", fs.readFileSync(goldenPath, "utf8"));
  assert.equal(imported.nodes.find((node) => node.id === "note").noteId, note.id);

  const withAsset = vault.putCanvas({
    id: imported.id,
    path: imported.path,
    title: imported.title,
    nodes: [
      ...imported.nodes,
      {
        id: "asset",
        type: "file",
        attachmentId: attachment.id,
        file: "old.png",
        x: 600,
        y: 0,
        width: 200,
        height: 200,
      },
    ],
    edges: imported.edges,
    baseRevision: imported.revision,
  });
  const portable = JSON.parse(vault.exportCanvas(withAsset.id));
  const portableNote = portable.nodes.find((node) => node.id === "note");
  const portableAsset = portable.nodes.find((node) => node.id === "asset");
  assert.equal(portableNote.file, "Notes/Golden.md");
  assert.equal("noteId" in portableNote, false);
  assert.equal(portableAsset.file, "assets/diagram.png");
  assert.equal("attachmentId" in portableAsset, false);

  const roundTrip = vault.importCanvas("Boards/Round trip", `${JSON.stringify(portable)}\n`);
  assert.equal(roundTrip.nodes.find((node) => node.id === "note").noteId, note.id);
  assert.equal(roundTrip.nodes.find((node) => node.id === "asset").attachmentId, attachment.id);

  const broken = vault.importCanvas(
    "Boards/Broken",
    JSON.stringify({
      nodes: [{ id: "missing", type: "file", file: "Missing.md", x: 0, y: 0, width: 10, height: 10 }],
      edges: [],
    }),
  );
  assert.equal(broken.nodes[0].file, "Missing.md");
  assert.equal(broken.nodes[0].noteId, undefined);
  assert.throws(
    () =>
      vault.importCanvas(
        "Boards/Future",
        JSON.stringify({ nodes: [{ id: "x", type: "video", x: 0, y: 0, width: 10, height: 10 }], edges: [] }),
      ),
    /unsupported node type/iu,
  );
});

test("canvas references, rebuilds and unreferenced attachment reports stay derived and non-destructive", () => {
  const dir = tempVault("index");
  const vault = new DocumentVault(dir, PASSPHRASE);
  const first = vault.put({ path: "Notes/First.md", body: "# First" });
  const second = vault.put({ path: "Notes/Second.md", body: "# Second" });
  const used = vault.putAttachment(Buffer.from("used"), "used.bin");
  const embedded = vault.putAttachment(Buffer.from("embedded"), "embedded.bin");
  const unused = vault.putAttachment(Buffer.from("unused"), "unused.bin");
  vault.put({ path: "Notes/Embed.md", body: "![[embedded.bin]]" });
  const canvas = vault.putCanvas({
    path: "Boards/Refs",
    nodes: [
      { id: "first", type: "file", noteId: first.id, file: first.path, x: 0, y: 0, width: 10, height: 10 },
      { id: "links", type: "text", text: "[[Second]] and [[Missing]]", x: 20, y: 0, width: 10, height: 10 },
      { id: "asset", type: "file", attachmentId: used.id, file: "used.bin", x: 40, y: 0, width: 10, height: 10 },
    ],
    edges: [],
  });
  assert.deepEqual(
    vault.canvasesReferencing(first.id).map((item) => item.id),
    [canvas.id],
  );
  assert.deepEqual(
    vault.canvasesReferencing(second.id).map((item) => item.id),
    [canvas.id],
  );
  assert.deepEqual(
    vault.unreferencedAttachments().map((item) => item.id),
    [unused.id],
  );

  const ambiguous = vault.put({ path: "Other/Second.md", title: "Second", body: "# Other" });
  assert.deepEqual(vault.canvasesReferencing(second.id), [], "an ambiguous text wikilink becomes unresolved");
  vault.remove(ambiguous.id);
  assert.deepEqual(
    vault.canvasesReferencing(second.id).map((item) => item.id),
    [canvas.id],
  );

  fs.rmSync(indexPath(dir));
  const rebuilt = new DocumentVault(dir, PASSPHRASE);
  assert.equal(rebuilt.listCanvases()[0].nodeCount, 3);
  assert.deepEqual(
    rebuilt.canvasesReferencing(second.id).map((item) => item.id),
    [canvas.id],
  );

  rebuilt.removeCanvas(canvas.id);
  assert.deepEqual(
    rebuilt
      .unreferencedAttachments()
      .map((item) => item.id)
      .sort(),
    [unused.id, used.id].sort(),
  );
  assert.equal(rebuilt.listAttachments().length, 3, "the report never deletes attachment bytes");
  assert.equal(
    rebuilt.unreferencedAttachments().some((item) => item.id === embedded.id),
    false,
  );
});

test("derived layout migration rebuilds once and canvas journal recovery heals a stale index", () => {
  const dir = tempVault("derived");
  const vault = new DocumentVault(dir, PASSPHRASE);
  const canvas = vault.putCanvas(board());
  const session = openDocumentKey(dir, PASSPHRASE);
  const encryptedIndex = JSON.parse(fs.readFileSync(indexPath(dir), "utf8"));
  const index = JSON.parse(decryptDocument(encryptedIndex, session.key, "secondbrain-vault:document-index:v1"));
  index.derived = 4;
  fs.writeFileSync(
    indexPath(dir),
    JSON.stringify(encryptDocument(JSON.stringify(index), session.key, "secondbrain-vault:document-index:v1")),
  );
  const migrated = new DocumentVault(dir, PASSPHRASE);
  assert.equal(migrated.listCanvases().length, 1);
  const afterMigration = fs.readFileSync(indexPath(dir), "utf8");
  assert.equal(new DocumentVault(dir, PASSPHRASE).listCanvases().length, 1);
  assert.equal(fs.readFileSync(indexPath(dir), "utf8"), afterMigration, "a current index is not rebuilt twice");

  const crashed = tempVault("journal");
  fs.rmSync(crashed, { recursive: true, force: true });
  fs.cpSync(dir, crashed, { recursive: true });
  const stale = tempVault("journal-control");
  fs.rmSync(stale, { recursive: true, force: true });
  fs.cpSync(dir, stale, { recursive: true });
  const updated = vault.putCanvas(
    board({
      id: canvas.id,
      nodes: [...board().nodes, { id: "n3", type: "text", text: "new", x: 0, y: 200, width: 10, height: 10 }],
    }),
  );
  fs.copyFileSync(canvasObjectPath(dir, canvas.id), canvasObjectPath(crashed, canvas.id));
  fs.copyFileSync(canvasObjectPath(dir, canvas.id), canvasObjectPath(stale, canvas.id));
  fs.writeFileSync(
    journalPath(crashed),
    JSON.stringify({ version: 1, startedAt: new Date().toISOString(), scope: "canvases", ids: [canvas.id] }),
  );

  assert.equal(new DocumentVault(stale, PASSPHRASE).listCanvases()[0].nodeCount, 2);
  const recovered = new DocumentVault(crashed, PASSPHRASE);
  assert.equal(recovered.listCanvases()[0].nodeCount, 3);
  assert.equal(recovered.listCanvases()[0].revision, updated.revision);
  assert.equal(fs.existsSync(journalPath(crashed)), false);

  const unknownScope = tempVault("journal-unknown");
  fs.rmSync(unknownScope, { recursive: true, force: true });
  fs.cpSync(stale, unknownScope, { recursive: true });
  fs.writeFileSync(
    journalPath(unknownScope),
    JSON.stringify({ version: 1, startedAt: new Date().toISOString(), scope: "future-scope", ids: [] }),
  );
  assert.equal(new DocumentVault(unknownScope, PASSPHRASE).listCanvases()[0].nodeCount, 3);
  assert.equal(fs.existsSync(journalPath(unknownScope)), false);
});
