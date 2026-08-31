import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { DocumentVault } from "../dist/documents.js";
import { SyncedDocumentVault } from "../dist/sync.js";

const PASSPHRASE = "sync-transaction-test-passphrase";
const DEVICE_A = "11111111-1111-4111-8111-111111111111";
const PHASES = ["prepared", "storage-written", "envelope-installed", "cursor-written", "cleared"];

function tempVault(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `secondbrain-sync-transaction-${label}-`));
}

function snapshotTree(root) {
  const entries = new Map();
  const visit = (directory, prefix = "") => {
    for (const entry of fs
      .readdirSync(directory, { withFileTypes: true })
      .sort((a, b) => a.name.localeCompare(b.name))) {
      const relative = path.join(prefix, entry.name);
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        entries.set(`${relative}${path.sep}`, "directory");
        visit(absolute, relative);
      } else if (entry.isSymbolicLink()) {
        entries.set(relative, `symlink:${fs.readlinkSync(absolute)}`);
      } else {
        entries.set(relative, fs.readFileSync(absolute).toString("base64"));
      }
    }
  };
  visit(root);
  return [...entries].sort(([left], [right]) => left.localeCompare(right));
}

function pendingPath(vaultDir) {
  return path.join(vaultDir, "documents", "sync", "pending-local.enc");
}

function closeAndRemove(vault, vaultDir) {
  vault?.lock();
  fs.rmSync(vaultDir, { recursive: true, force: true });
}

test("missing or invalid device IDs fail before any synchronized storage or log access", () => {
  const invalidDir = tempVault("invalid-device");
  const invalidBefore = snapshotTree(invalidDir);
  assert.throws(
    () => new SyncedDocumentVault(invalidDir, PASSPHRASE, "NOT-A-DEVICE"),
    /device ID must be a lowercase UUID/iu,
  );
  assert.deepEqual(snapshotTree(invalidDir), invalidBefore, "invalid construction must not initialize a vault");
  fs.rmSync(invalidDir, { recursive: true, force: true });

  const cases = [
    {
      label: "note-put",
      seed: () => undefined,
      mutate: (vault) => vault.put({ path: "Rejected.md", body: "must not land" }),
    },
    {
      label: "note-delete",
      seed: (vault) => vault.put({ path: "Kept.md", body: "must stay" }),
      mutate: (vault, seeded) => vault.remove(seeded.id),
    },
    {
      label: "canvas-put",
      seed: () => undefined,
      mutate: (vault) => vault.putCanvas({ path: "Rejected.canvas", nodes: [], edges: [] }),
    },
    {
      label: "canvas-delete",
      seed: (vault) => vault.putCanvas({ path: "Kept.canvas", nodes: [], edges: [] }),
      mutate: (vault, seeded) => vault.removeCanvas(seeded.id),
    },
    {
      label: "attachment-put",
      seed: () => undefined,
      mutate: (vault) => vault.putAttachment(Buffer.from("must not land"), "rejected.txt", "text/plain"),
    },
    {
      label: "attachment-delete",
      seed: (vault) => vault.putAttachment(Buffer.from("must stay"), "kept.txt", "text/plain"),
      mutate: (vault, seeded) => vault.removeAttachment(seeded.id),
    },
    {
      label: "put-many",
      seed: () => undefined,
      mutate: (vault) =>
        vault.putMany([
          { path: "One.md", body: "one" },
          { path: "Two.md", body: "two" },
        ]),
    },
  ];

  for (const scenario of cases) {
    const vaultDir = tempVault(`missing-${scenario.label}`);
    const seedVault = new DocumentVault(vaultDir, PASSPHRASE);
    const seeded = scenario.seed(seedVault);
    seedVault.lock();
    const vault = new SyncedDocumentVault(vaultDir, PASSPHRASE);
    const before = snapshotTree(vaultDir);
    assert.throws(() => scenario.mutate(vault, seeded), /device ID is required/iu, scenario.label);
    assert.deepEqual(snapshotTree(vaultDir), before, `${scenario.label} changed disk before device preflight`);
    closeAndRemove(vault, vaultDir);
  }
});

test("putMany validates the complete evolving batch before persisting intent or storage", () => {
  const vaultDir = tempVault("batch-preflight");
  const vault = new SyncedDocumentVault(vaultDir, PASSPHRASE, DEVICE_A);
  const duplicateId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const before = snapshotTree(vaultDir);
  assert.throws(
    () =>
      vault.putMany([
        { id: duplicateId, path: "First.md", body: "first", baseRevision: 0 },
        { id: duplicateId, path: "Second.md", body: "second", baseRevision: 99 },
      ]),
    /revision conflict/iu,
  );
  assert.deepEqual(snapshotTree(vaultDir), before);
  assert.equal(fs.existsSync(pendingPath(vaultDir)), false);
  closeAndRemove(vault, vaultDir);
});

function faultAt(phase, timing = "after-marker") {
  return ({ phase: current, timing: currentTiming }) => {
    if (current === phase && currentTiming === timing) throw new Error(`Injected ${phase} ${timing} fault.`);
  };
}

function setupScenario(label) {
  const vaultDir = tempVault(label);
  const legacy = new DocumentVault(vaultDir, PASSPHRASE);
  switch (label) {
    case "note-put":
      legacy.lock();
      return {
        vaultDir,
        mutate: (vault) => vault.put({ path: "New.md", body: "new note secret" }),
        verify: (vault) => {
          const note = vault.get("New.md");
          assert.equal(note.body, "new note secret");
          assert.equal(note.revision, 1);
          return [["note", note.id, "put", 1]];
        },
      };
    case "note-update": {
      const note = legacy.put({ path: "Legacy.md", body: "legacy note secret" });
      legacy.lock();
      return {
        vaultDir,
        mutate: (vault) =>
          vault.put({ id: note.id, path: note.path, body: "updated note secret", baseRevision: note.revision }),
        verify: (vault) => {
          const updated = vault.get(note.id);
          assert.equal(updated.body, "updated note secret");
          assert.equal(updated.revision, 2);
          assert.deepEqual(
            vault.revisions(note.id).map((entry) => entry.revision),
            [2, 1],
          );
          return [
            ["note", note.id, "put", 1],
            ["note", note.id, "put", 2],
          ];
        },
      };
    }
    case "note-delete": {
      const note = legacy.put({ path: "Legacy.md", body: "legacy note secret" });
      legacy.lock();
      return {
        vaultDir,
        mutate: (vault) => vault.remove(note.id),
        verify: (vault) => {
          assert.throws(() => vault.get(note.id), /not found/iu);
          assert.deepEqual(
            vault.revisions(note.id).map((entry) => entry.revision),
            [1],
          );
          return [
            ["note", note.id, "put", 1],
            ["note", note.id, "delete", 2],
          ];
        },
      };
    }
    case "canvas-put":
      legacy.lock();
      return {
        vaultDir,
        mutate: (vault) => vault.putCanvas({ path: "New.canvas", nodes: [], edges: [] }),
        verify: (vault) => {
          const canvas = vault.getCanvas("New.canvas");
          assert.equal(canvas.revision, 1);
          return [["canvas", canvas.id, "put", 1]];
        },
      };
    case "canvas-delete": {
      const canvas = legacy.putCanvas({ path: "Legacy.canvas", nodes: [], edges: [] });
      legacy.lock();
      return {
        vaultDir,
        mutate: (vault) => vault.removeCanvas(canvas.id),
        verify: (vault) => {
          assert.throws(() => vault.getCanvas(canvas.id), /not found/iu);
          assert.deepEqual(
            vault.canvasRevisions(canvas.id).map((entry) => entry.revision),
            [1],
          );
          return [
            ["canvas", canvas.id, "put", 1],
            ["canvas", canvas.id, "delete", 2],
          ];
        },
      };
    }
    case "canvas-update": {
      const canvas = legacy.putCanvas({ path: "Legacy.canvas", nodes: [], edges: [] });
      legacy.lock();
      return {
        vaultDir,
        mutate: (vault) =>
          vault.putCanvas({
            id: canvas.id,
            path: canvas.path,
            nodes: [{ id: "text", type: "text", x: 0, y: 0, width: 100, height: 100, text: "updated" }],
            edges: [],
            baseRevision: canvas.revision,
          }),
        verify: (vault) => {
          const updated = vault.getCanvas(canvas.id);
          assert.equal(updated.nodes[0].text, "updated");
          assert.equal(updated.revision, 2);
          assert.deepEqual(
            vault.canvasRevisions(canvas.id).map((entry) => entry.revision),
            [2, 1],
          );
          return [
            ["canvas", canvas.id, "put", 1],
            ["canvas", canvas.id, "put", 2],
          ];
        },
      };
    }
    case "attachment-put":
      legacy.lock();
      return {
        vaultDir,
        mutate: (vault) => vault.putAttachment(Buffer.from("new attachment secret"), "new.txt", "text/plain"),
        verify: (vault) => {
          const [info] = vault.listAttachments();
          assert.equal(vault.getAttachment(info.id).data.toString(), "new attachment secret");
          return [["attachment", info.id, "put", 1]];
        },
      };
    case "attachment-delete": {
      const attachment = legacy.putAttachment(Buffer.from("legacy attachment secret"), "legacy.txt", "text/plain");
      legacy.lock();
      return {
        vaultDir,
        mutate: (vault) => vault.removeAttachment(attachment.id),
        verify: (vault) => {
          assert.equal(
            vault.listAttachments().some((item) => item.id === attachment.id),
            false,
          );
          return [
            ["attachment", attachment.id, "put", 1],
            ["attachment", attachment.id, "delete", 2],
          ];
        },
      };
    }
    case "put-many":
      legacy.lock();
      return {
        vaultDir,
        mutate: (vault) =>
          vault.putMany([
            { path: "Batch/One.md", body: "batch one secret" },
            { path: "Batch/Two.md", body: "batch two secret" },
          ]),
        verify: (vault) => {
          const first = vault.get("Batch/One.md");
          const second = vault.get("Batch/Two.md");
          assert.equal(first.revision, 1);
          assert.equal(second.revision, 1);
          return [
            ["note", first.id, "put", 1],
            ["note", second.id, "put", 1],
          ];
        },
      };
    default:
      throw new Error(`Unknown scenario ${label}`);
  }
}

function verifyRecoveredTransaction(vault, expected) {
  const actual = vault.changeLog
    .changes()
    .map((change) => [
      change.mutation.objectType,
      change.mutation.objectId,
      change.mutation.operation,
      change.mutation.revision,
    ]);
  assert.deepEqual(actual, expected);
  for (const [objectType, objectId, operation, revision] of expected) {
    const cursor = vault.changeLog.applied(objectType, objectId);
    if (
      revision ===
      Math.max(...expected.filter((entry) => entry[0] === objectType && entry[1] === objectId).map((entry) => entry[3]))
    ) {
      assert.equal(cursor.revision, revision);
      assert.equal(cursor.operation, operation);
    }
  }
}

for (const scenarioName of [
  "note-put",
  "note-delete",
  "canvas-put",
  "canvas-delete",
  "attachment-put",
  "attachment-delete",
  "put-many",
]) {
  test(`${scenarioName} rolls forward exactly once after every durable boundary`, () => {
    for (const phase of PHASES) {
      const scenario = setupScenario(`${scenarioName}`);
      let crashed = new SyncedDocumentVault(scenario.vaultDir, PASSPHRASE, DEVICE_A, {
        faultInjector: faultAt(phase),
      });
      assert.throws(() => scenario.mutate(crashed), new RegExp(`Injected ${phase}`, "u"), phase);
      const encryptedIntent = fs.existsSync(pendingPath(scenario.vaultDir))
        ? fs.readFileSync(pendingPath(scenario.vaultDir), "utf8")
        : "";
      assert.doesNotMatch(encryptedIntent, /secret|Legacy|Batch/iu);
      crashed.lock();
      crashed = undefined;

      const recovered = new SyncedDocumentVault(scenario.vaultDir, PASSPHRASE, DEVICE_A);
      const expected = scenario.verify(recovered);
      verifyRecoveredTransaction(recovered, expected);
      assert.equal(fs.existsSync(pendingPath(scenario.vaultDir)), false);
      closeAndRemove(recovered, scenario.vaultDir);
    }
  });
}

test("recovery recognizes updated storage already written before its durable phase marker", () => {
  for (const scenarioName of ["note-update", "canvas-update", "attachment-put"]) {
    const scenario = setupScenario(scenarioName);
    const crashed = new SyncedDocumentVault(scenario.vaultDir, PASSPHRASE, DEVICE_A, {
      faultInjector: faultAt("storage-written", "after-effect"),
    });
    assert.throws(() => scenario.mutate(crashed), /storage-written after-effect/iu);
    crashed.lock();

    const recovered = new SyncedDocumentVault(scenario.vaultDir, PASSPHRASE, DEVICE_A);
    const expected = scenario.verify(recovered);
    verifyRecoveredTransaction(recovered, expected);
    assert.equal(fs.existsSync(pendingPath(scenario.vaultDir)), false);
    closeAndRemove(recovered, scenario.vaultDir);
  }
});

test("putMany replays repeated paths and IDs as one evolving transaction", () => {
  const vaultDir = tempVault("batch-evolving-replay");
  const id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  const crashed = new SyncedDocumentVault(vaultDir, PASSPHRASE, DEVICE_A, {
    faultInjector: faultAt("storage-written", "after-effect"),
  });
  assert.throws(
    () =>
      crashed.putMany([
        { id, path: "Repeated.md", body: "first", baseRevision: 0 },
        { id, path: "Repeated.md", body: "second", baseRevision: 1 },
      ]),
    /storage-written after-effect/iu,
  );
  crashed.lock();

  const recovered = new SyncedDocumentVault(vaultDir, PASSPHRASE, DEVICE_A);
  assert.equal(recovered.get(id).body, "second");
  assert.equal(recovered.get(id).revision, 2);
  assert.equal(recovered.getRevision(id, 1).body, "first");
  assert.deepEqual(
    recovered.changeLog.changes().map((change) => [change.mutation.operation, change.mutation.revision]),
    [
      ["put", 1],
      ["put", 2],
    ],
  );
  assert.equal(recovered.changeLog.applied("note", id).revision, 2);
  assert.equal(fs.existsSync(pendingPath(vaultDir)), false);
  closeAndRemove(recovered, vaultDir);
});
