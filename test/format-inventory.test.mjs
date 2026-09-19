import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import ts from "typescript";
import * as format from "../dist/format-version.js";
import { DocumentVault } from "../dist/documents.js";
import { planRekey } from "../dist/keyring-rekey.js";
import { SyncDeviceManager, SyncedDocumentVault } from "../dist/sync.js";
import { openDocumentKey } from "../dist/document-crypto.js";
import { writePortableState } from "../dist/portable-state.js";
import { saveVaultFile } from "../dist/store.js";
import { buildSchema } from "../dist/schema.js";
import { addGrant } from "../dist/grants.js";
import { createBackup } from "../dist/backup.js";
import { createRecoveryKit } from "../dist/keyring-recovery.js";
import { saveEpochKey } from "../dist/sync-epoch.js";
import { SyncApplyReceiptStore } from "../dist/sync/transaction.js";
import { removeTree } from "../scripts/fs-tree.mjs";

function literals(source) {
  const result = [];
  const tree = ts.createSourceFile("source.ts", source, ts.ScriptTarget.Latest, true);
  function visit(node) {
    if (
      (ts.isStringLiteral(node) ||
        ts.isNoSubstitutionTemplateLiteral(node) ||
        node.kind === ts.SyntaxKind.TemplateHead) &&
      node.text.startsWith("secondbrain-vault:")
    )
      result.push(node.text);
    ts.forEachChild(node, visit);
  }
  visit(tree);
  return result;
}

function assertDomains(source, allowed) {
  for (const value of literals(source)) assert.ok(allowed.has(value), `Uncatalogued crypto domain: ${value}`);
}

test("all TS domains and shared Rust domains match the frozen inventory", () => {
  const expected = JSON.parse(fs.readFileSync(new URL("./fixtures/format-domains.json", import.meta.url), "utf8"));
  assert.deepEqual(format.AAD, expected);
  const allowed = new Set(Object.values(expected));
  for (const file of fs.readdirSync("src", { recursive: true }).filter((file) => file.endsWith(".ts"))) {
    assertDomains(fs.readFileSync(path.join("src", file), "utf8"), allowed);
  }
  for (const file of fs.readdirSync("src-tauri/src", { recursive: true }).filter((file) => file.endsWith(".rs"))) {
    const source = fs
      .readFileSync(path.join("src-tauri/src", file), "utf8")
      .split("#[cfg(test)]")[0]
      .replace(/\/\/[^\n]*/gu, "");
    for (const match of source.matchAll(/"(secondbrain-vault:[^"\n]*)"/gu)) {
      const value = match[1].split("{")[0].replaceAll("\\0", "\0");
      assert.ok(allowed.has(value), `${file}: divergent Rust domain ${value}`);
    }
  }
  assert.throws(() => assertDomains('const aad = "secondbrain-vault:unregistered:v1";', allowed), /Uncatalogued/);
  const omitted = new Set(allowed);
  omitted.delete(expected.keyedEnvelope);
  assert.throws(() => assertDomains('const aad = "secondbrain-vault:kv:v2";', omitted), /Uncatalogued/);
});

test("format catalogue records durable, temporary, nested, and external control artifacts", () => {
  const expected = {
    vaultKeyring: ["persistent", "encrypted"],
    documentManifest: ["persistent", "plaintext"],
    documentJournal: ["transient", "plaintext"],
    rekeyJournal: ["transient", "plaintext"],
    rekeyNewTree: ["nested", "encrypted"],
    rekeyOldTree: ["nested", "encrypted"],
    typescriptAtomicTemp: ["transient", "encrypted"],
    rustAtomicTemp: ["transient", "encrypted"],
    syncEnrollmentRequest: ["external", "encrypted"],
    vaultBackup: ["external", "encrypted"],
    recoveryKit: ["external", "encrypted"],
  };
  for (const [name, [persistence, protection]] of Object.entries(expected)) {
    assert.equal(format.FORMAT_COMPATIBILITY[name].persistence, persistence, name);
    assert.equal(format.FORMAT_COMPATIBILITY[name].protection, protection, name);
  }
  assert.equal(format.FORMAT_COMPATIBILITY.syncIdentity.rekey.normal, "reencrypt");
  assert.equal(format.FORMAT_COMPATIBILITY.syncIdentity.rekey.rotateIdentities, "reset");
  assert.equal(format.FORMAT_COMPATIBILITY.documentIndex.rekey.rotateIdentities, "rewrite-identities");
  assert.throws(() => format.artifactForPath("documents/.unknown.tmp"), /Uncatalogued/);
  assert.throws(() => format.artifactForPath(".anything.999.tmp"), /Uncatalogued/);
  assert.throws(() => format.artifactForPath("documents/journal.json"), /Uncatalogued/);
  assert.match(".index.enc.42.11111111-1111-4111-8111-111111111111.tmp", format.FORMAT_COMPATIBILITY.typescriptAtomicTemp.temporaryPattern);
  assert.match(".index.enc.11111111-1111-4111-8111-111111111111.tmp", format.FORMAT_COMPATIBILITY.rustAtomicTemp.temporaryPattern);
  assert.doesNotMatch(".unknown.tmp", format.FORMAT_COMPATIBILITY.typescriptAtomicTemp.temporaryPattern);
});

test("real writers produce only catalogued, explicitly rekeyed encrypted files", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "format-inventory-"));
  let vault;
  try {
    vault = new DocumentVault(root, "format-inventory-passphrase");
    const note = vault.put({ path: "Catalogue.md", body: "first" });
    vault.put({ id: note.id, path: note.path, body: "second" });
    const canvas = vault.putCanvas({ path: "Catalogue.canvas", nodes: [], edges: [] });
    vault.putCanvas({ id: canvas.id, path: canvas.path, nodes: [{ id: "node", type: "text", text: "revised", x: 0, y: 0, width: 1, height: 1 }], edges: [], baseRevision: 1 });
    vault.putAttachment(Buffer.from("catalogue bytes"), "catalogue.bin");
    vault.setRetentionPolicy({ version: 1, keepRevisions: 4, keepDays: null });
    const plugin = vault.installPlugin({
      manifest: {
        manifestVersion: 1,
        id: "catalogue-plugin",
        name: "Catalogue",
        version: "1.0.0",
        description: "Synthetic fixture",
        author: "Tests",
        capabilities: [],
      },
      source: "export function activate() {}",
    });
    vault.setPluginStorage(plugin.id, { preference: "value" });
    vault.setPluginRestrictedMode(true);
    vault.lock();
    saveVaultFile(root, "catalogue", [{ key: "value", value: "key-value", desc: "fixture" }], "format-inventory-passphrase");
    addGrant(root, { agent: "catalogue-agent", scopes: [{ file: "*", keys: ["*"], actions: ["discover"], redact: "none" }] }, "format-inventory-passphrase");
    // The discovery catalog every `vbrain add` refreshes. Leaving it out of
    // this fixture is how it stayed outside the re-key inventory long enough
    // to make an ordinary vault un-re-keyable.
    buildSchema(root, "format-inventory-passphrase");
    const portable = openDocumentKey(root, "format-inventory-passphrase");
    writePortableState(portable, "workspace", { version: 1, bookmarks: [], layouts: [] });
    writePortableState(portable, "saved-views", { version: 1, views: [] });
    saveEpochKey(portable.rootDir, portable.key, 2, Buffer.alloc(32, 7));
    for (const key of [portable.key, portable.attachmentIdKey, portable.syncChangeKey, portable.syncEnvelopeKey]) key.fill(0);
    const deviceId = "11111111-1111-4111-8111-111111111111";
    const devices = new SyncDeviceManager(root, "format-inventory-passphrase");
    devices.initializeOwner("Catalogue device", deviceId, "2026-09-13T00:00:00.000Z");
    devices.close();
    const synced = new SyncedDocumentVault(root, "format-inventory-passphrase", deviceId);
    synced.put({ path: "Synced.md", body: "sync change" });
    synced.putAttachment(Buffer.from("sync blob"), "sync.bin", "application/octet-stream");
    const receiptChange = synced.changeLog.changes()[0];
    const checkpointWriter = new SyncDeviceManager(root, "format-inventory-passphrase");
    checkpointWriter.createCheckpoint(synced.changeLog.changes(), "2026-09-13T00:01:00.000Z");
    checkpointWriter.close();
    synced.lock();
    const interrupted = new SyncedDocumentVault(root, "format-inventory-passphrase", deviceId, {
      faultInjector: ({ phase, timing }) => {
        if (phase === "prepared" && timing === "after-marker") throw new Error("injected interruption");
      },
    });
    assert.throws(() => interrupted.put({ path: "Interrupted.md", body: "pending intent" }), /injected interruption/);
    interrupted.lock();
    assert.equal(fs.existsSync(path.join(root, "documents", "sync", "pending-local.enc")), true);
    const receiptStore = new SyncApplyReceiptStore(root, "format-inventory-passphrase");
    receiptStore.begin(receiptChange, { objectId: receiptChange.mutation.objectId, storageRevision: null });
    receiptStore.close();
    const external = fs.mkdtempSync(path.join(os.tmpdir(), "format-inventory-external-"));
    const kit = path.join(external, "recovery-kit.json");
    createRecoveryKit(root, "format-inventory-passphrase", kit);
    const archive = path.join(external, "catalogue.vbrainbackup");
    createBackup(root, archive, "format-inventory-passphrase");
    assert.equal(fs.existsSync(kit), true, "recovery writer produced an external kit");
    assert.equal(fs.existsSync(archive), true, "backup writer produced an external archive");

    const observedFamilies = new Set(
      fs.readdirSync(root, { recursive: true })
        .filter((file) => fs.statSync(path.join(root, file)).isFile())
        .map((file) => file.replaceAll(path.sep, "/"))
        .map((file) => {
          if (/^[^/]+\.kv\.enc$/u.test(file)) return "kv";
          if (file === "grants.enc") return "grants";
          if (file === "schema.enc") return "catalog";
          if (file === "documents/manifest.json") return "manifest";
          if (file === "documents/index.enc") return "index";
          if (file === "documents/workspace.enc") return "workspace";
          if (file === "documents/views.enc") return "views";
          if (/^documents\/objects\/.+\.note\.enc$/u.test(file)) return "note";
          if (/^documents\/objects\/.+\.canvas\.enc$/u.test(file)) return "canvas";
          if (/^documents\/objects\/.+\.plugin\.enc$/u.test(file)) return "plugin";
          if (/^documents\/objects\/.+\.pluginstore\.enc$/u.test(file)) return "plugin-store";
          if (/^documents\/history\/.+\/\d+\.note\.enc$/u.test(file)) return "note-history";
          if (/^documents\/history\/.+\/\d+\.canvas\.enc$/u.test(file)) return "canvas-history";
          if (/^documents\/attachments\/.+\/manifest\.enc$/u.test(file)) return "attachment-manifest";
          if (/^documents\/attachments\/.+\/\d+\.chunk\.enc$/u.test(file)) return "attachment-chunk";
          if (/^documents\/sync\/changes\/.+\.change\.enc$/u.test(file)) return "sync-change";
          if (file === "documents/sync/devices.enc") return "sync-registry";
          if (file === "documents/sync/applied.enc") return "sync-applied";
          if (file === "documents/sync/pending-local.enc") return "sync-pending";
          if (file === "documents/sync/apply-receipt.enc") return "sync-receipt";
          if (file === "documents/sync/checkpoint.enc") return "sync-checkpoint";
          if (/^documents\/sync\/identity\/authority\.key\.enc$/u.test(file)) return "sync-authority";
          if (/^documents\/sync\/identity\/.+\.x25519\.key\.enc$/u.test(file)) return "sync-agreement";
          if (/^documents\/sync\/identity\/epochs\/\d+\.key\.enc$/u.test(file)) return "sync-epoch";
          if (/^documents\/sync\/identity\/.+\.key\.enc$/u.test(file)) return "sync-device";
          if (/^documents\/sync\/blobs\/[a-f0-9]{64}$/u.test(file)) return "sync-blob";
          if (["keyring.json", "audit.log", "audit.meta.json", "audit.head.json", "documents/plugin-policy.enc", "documents/retention.enc"].includes(file)) return "control";
          throw new Error(`Unclassified writer output: ${file}`);
        })
        .filter((family) => family !== "control"),
    );
    assert.deepEqual(
      [...observedFamilies].sort(),
      ["attachment-chunk", "attachment-manifest", "canvas", "canvas-history", "catalog", "grants", "index", "kv", "manifest", "note", "note-history", "plugin", "plugin-store", "sync-agreement", "sync-applied", "sync-authority", "sync-blob", "sync-change", "sync-checkpoint", "sync-device", "sync-epoch", "sync-pending", "sync-receipt", "sync-registry", "views", "workspace"],
    );
    const planned = new Set(planRekey(root).map((item) => item.path));
    const files = fs.readdirSync(root, { recursive: true }).filter((file) => file.endsWith(".enc"));
    for (const file of files) {
      const relative = file.replaceAll(path.sep, "/");
      const artifact = format.artifactForPath(relative);
      assert.equal(artifact.rekey.normal, "reencrypt", relative);
      assert.ok(planned.has(relative), `Missing rekey classification: ${relative}`);
    }
    assert.throws(() => format.artifactForPath("documents/new-secret.enc"), /Uncatalogued/);
    const omitted = { ...format.FORMAT_COMPATIBILITY };
    delete omitted.documentIndex;
    assert.throws(() => format.artifactForPath("documents/index.enc", omitted), /Uncatalogued/);
    fs.writeFileSync(path.join(root, "documents", "new-secret.enc"), "{}");
    assert.throws(() => planRekey(root), /Uncatalogued|cannot classify/);
  } finally {
    vault?.lock();
    removeTree(root);
  }
});
