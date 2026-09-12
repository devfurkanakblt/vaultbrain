import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createBackup, restoreBackup } from "../dist/backup.js";
import { SyncedDocumentVault } from "../dist/sync.js";
import { attachmentBlobIds, startSyncRelay, SyncRelayClient } from "../dist/sync-relay.js";

/** Synthetic live-storage recovery, separate from the signed checkpoint drill. */
export async function runPortableRecoveryDrill() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "portable-recovery-"));
  const pass = "synthetic-portable-recovery-passphrase";
  const token = "synthetic-portable-relay-token-0123456789";
  const owner = "11111111-1111-4111-8111-111111111111";
  let source, restored, relay;
  try {
    const sourceDir = path.join(root, "source"),
      targetDir = path.join(root, "restored");
    source = new SyncedDocumentVault(sourceDir, pass, owner);
    const note = source.put({ path: "Recover.md", body: "backup version" });
    source.lock();
    createBackup(sourceDir, path.join(root, "backup.vbrainbackup"), pass);
    source = new SyncedDocumentVault(sourceDir, pass, owner);
    source.put({ id: note.id, path: note.path, body: "relay-only version", baseRevision: 1 });
    const attachment = source.putAttachment(Buffer.from("relay-only binary bytes"), "recover.bin");
    const canvas = source.putCanvas({ path: "Recover.canvas", nodes: [], edges: [] });
    const plugin = source.installPlugin({
      manifest: {
        manifestVersion: 1,
        id: "recovery-plugin",
        name: "Recovery",
        version: "1.0.0",
        description: "Synthetic fixture",
        author: "Tests",
        capabilities: [],
      },
      source: "export function activate() {}",
    });
    source.setPluginRestrictedMode(true);
    const workspace = {
      version: 1,
      bookmarks: [{ id: note.id, label: "Recovered bookmark", createdAt: "2026-09-11T00:00:00.000Z" }],
      layouts: [
        {
          id: "layout",
          name: "Recovered layout",
          tabs: [note.id],
          active: note.id,
          secondary: null,
          view: "notes",
          createdAt: "2026-09-11T00:00:00.000Z",
          updatedAt: "2026-09-11T00:00:00.000Z",
        },
      ],
    };
    const views = {
      version: 1,
      views: [
        {
          id: "view",
          name: "Recovered view",
          filter: "",
          tags: [],
          sort: "title",
          direction: "asc",
          columns: ["title"],
          createdAt: "2026-09-11T00:00:00.000Z",
          updatedAt: "2026-09-11T00:00:00.000Z",
        },
      ],
    };
    source.setPortableState("workspace", workspace);
    source.setPortableState("saved-views", views);
    relay = await startSyncRelay({ storageDir: path.join(root, "relay"), token });
    const vaultId = "a".repeat(64);
    const uploader = new SyncRelayClient(relay.url, token, vaultId, sourceDir);
    const changes = source.changeLog.changes();
    await uploader.uploadChanges(source.changeLog.envelopes(), changes);
    restoreBackup(path.join(root, "backup.vbrainbackup"), targetDir, pass);
    restored = new SyncedDocumentVault(targetDir, pass);
    const downloader = new SyncRelayClient(relay.url, token, vaultId, targetDir);
    restored.changeLog.import(await downloader.downloadChanges());
    await downloader.pullBlobs([...new Set(changes.flatMap(attachmentBlobIds))]);
    const objects = [
      ...new Map(
        changes.map((change) => [`${change.mutation.objectType}:${change.mutation.objectId}`, change.mutation]),
      ).values(),
    ];
    for (const object of objects) restored.applyResolved(object.objectType, object.objectId);
    for (const object of objects)
      assert.equal(restored.applyResolved(object.objectType, object.objectId).alreadyApplied, true);
    assert.equal(restored.get(note.id).body, "relay-only version");
    assert.equal(restored.getCanvas(canvas.id).id, canvas.id);
    assert.deepEqual(restored.getAttachment(attachment.id).data, Buffer.from("relay-only binary bytes"));
    assert.equal(restored.getPlugin(plugin.manifest.id).source, plugin.source);
    assert.equal(restored.pluginSecurityPolicy().restrictedMode, true);
    assert.deepEqual(restored.getPortableState("workspace"), workspace);
    assert.deepEqual(restored.getPortableState("saved-views"), views);
    return {
      ok: true,
      liveObjects: objects.length,
      duplicateApply: "idempotent",
      portableState: ["bookmarks", "layouts", "saved-views"],
    };
  } finally {
    source?.lock();
    restored?.lock();
    await relay?.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
}
