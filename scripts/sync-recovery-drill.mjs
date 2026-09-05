import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { startSyncRelay, SyncRelayClient } from "../dist/sync-relay.js";
import { SyncChangeLog, SyncDeviceManager } from "../dist/sync.js";

const passphrase = process.env.VBRAIN_DRILL_PASSPHRASE ?? process.env.SBRAIN_DRILL_PASSPHRASE ?? "throwaway-sync-recovery-drill-passphrase";
const token = process.env.VBRAIN_RELAY_TOKEN ?? process.env.SBRAIN_RELAY_TOKEN ?? "throwaway-sync-recovery-drill-relay-token";
const deviceId = "11111111-1111-4111-8111-111111111111";
const root = fs.mkdtempSync(path.join(os.tmpdir(), "secondbrain-sync-recovery-drill-"));
const sourceDir = path.join(root, "source");
const backupDir = path.join(root, "offline-backup");
const recoveredDir = path.join(root, "recovered");
const relayDir = path.join(root, "relay");

function mutation(revision, baseRevision, body) {
  return {
    objectType: "note",
    objectId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    operation: "put",
    baseRevision,
    revision,
    value: { title: "Recovery drill", body },
  };
}

let relay;
let sourceManager;
let sourceLog;
let recoveredManager;
let recoveredLog;
try {
  sourceManager = new SyncDeviceManager(sourceDir, passphrase);
  sourceManager.initializeOwner("Recovery owner", deviceId, "2026-09-03T12:00:00.000Z");
  sourceLog = new SyncChangeLog(sourceDir, passphrase);
  sourceLog.append(deviceId, mutation(1, null, "present in offline backup"), "2026-09-03T12:01:00.000Z");

  sourceLog.close();
  sourceLog = undefined;
  sourceManager.close();
  sourceManager = undefined;
  fs.cpSync(sourceDir, backupDir, { recursive: true });

  sourceManager = new SyncDeviceManager(sourceDir, passphrase);
  sourceLog = new SyncChangeLog(sourceDir, passphrase);
  sourceLog.append(deviceId, mutation(2, 1, "relay-only update"), "2026-09-03T12:02:00.000Z");
  const checkpoint = sourceManager.createCheckpoint(sourceLog.changes(), "2026-09-03T12:03:00.000Z");
  const vaultId = sourceManager.fingerprint();
  assert.ok(vaultId);

  relay = await startSyncRelay({ storageDir: relayDir, token });
  const sourceClient = new SyncRelayClient(relay.url, token, vaultId);
  await sourceClient.uploadChanges(sourceLog.envelopes());
  await sourceClient.uploadArtifact("registry", sourceManager.exportRegistry());
  await sourceClient.uploadArtifact("checkpoint", sourceManager.exportCheckpoint());

  fs.cpSync(backupDir, recoveredDir, { recursive: true });
  recoveredManager = new SyncDeviceManager(recoveredDir, passphrase);
  recoveredLog = new SyncChangeLog(recoveredDir, passphrase);
  const recoveredClient = new SyncRelayClient(relay.url, token, vaultId);
  const registryBundle = (await recoveredClient.downloadArtifacts("registry"))[0];
  recoveredManager.importRegistry(registryBundle);
  const imported = recoveredLog.import(await recoveredClient.downloadChanges());
  const checkpointBundle = (await recoveredClient.downloadArtifacts("checkpoint"))[0];
  recoveredManager.importCheckpoint(checkpointBundle, recoveredLog.changes(), checkpoint.id);
  const verified = recoveredManager.verifyCheckpoint(recoveredLog.changes());

  assert.deepEqual(imported, { imported: 1, existing: 1 });
  assert.equal(verified.id, checkpoint.id);
  assert.equal(verified.body.changeCount, 2);
  const relayText = fs
    .readdirSync(path.join(relayDir, vaultId, "changes"))
    .map((name) => fs.readFileSync(path.join(relayDir, vaultId, "changes", name), "utf8"))
    .join("\n");
  assert.doesNotMatch(relayText, /present in offline backup|relay-only update/u);

  console.log(
    JSON.stringify(
      {
        ok: true,
        restoredFrom: "offline encrypted vault backup",
        relayCatchup: imported,
        verifiedCheckpoint: verified.id,
        verifiedChanges: verified.body.changeCount,
      },
      null,
      2,
    ),
  );
} finally {
  recoveredLog?.close();
  recoveredManager?.close();
  sourceLog?.close();
  sourceManager?.close();
  await relay?.close();
  fs.rmSync(root, { recursive: true, force: true });
}
