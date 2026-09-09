#!/usr/bin/env node
/**
 * Packaged desktop sync sidecar. Its sole input and output are a single
 * bounded JSON message over private stdio: credentials never enter argv,
 * environment variables, diagnostics, or the webview-visible result.
 */
import fs from "node:fs";
import {
  SyncChangeLog,
  SyncDeviceManager,
  SyncedDocumentVault,
  syncRegistryFingerprint,
  type SyncObjectType,
} from "./sync.js";
import { attachmentBlobIds, SyncRelayClient } from "./sync-relay.js";
import { parseDesktopSyncRequest, syncProgress, type DesktopSyncProgress, type DesktopSyncRequest } from "./desktop-sync-protocol.js";

const MAX_STDIN_BYTES = 256 * 1024;
type DeviceId = `${string}-${string}-${string}-${string}-${string}`;

function readRequest(): DesktopSyncRequest {
  const input = fs.readFileSync(0);
  if (input.byteLength > MAX_STDIN_BYTES) throw new Error("Desktop sync request exceeds the protocol limit.");
  return parseDesktopSyncRequest(JSON.parse(input.toString("utf8")));
}

function result(request: DesktopSyncRequest, value: unknown): DesktopSyncProgress {
  return syncProgress(request.operation, "complete", request, undefined, value);
}

function localDeviceId(manager: SyncDeviceManager, requested?: string): string | undefined {
  if (requested) return requested;
  return manager.state()?.body.devices.find((device) => !device.revokedAt)?.certificate.deviceId;
}

async function run(request: DesktopSyncRequest): Promise<DesktopSyncProgress> {
  switch (request.operation) {
    case "init": {
      const manager = new SyncDeviceManager(request.vaultPath, request.passphrase);
      try {
        const registry = manager.initializeOwner(request.deviceName!, request.deviceId as DeviceId | undefined);
        return result(request, { deviceId: registry.body.devices[0].certificate.deviceId, authorityFingerprint: manager.fingerprint(), registryRevision: registry.body.revision });
      } finally { manager.close(); }
    }
    case "request": {
      const manager = new SyncDeviceManager(request.vaultPath, request.passphrase);
      try { return result(request, { enrollmentRequest: manager.createEnrollmentRequest(request.deviceName!, request.deviceId as DeviceId | undefined) }); }
      finally { manager.close(); }
    }
    case "approve": {
      if (!request.enrollmentRequest) throw new Error("An enrollment request is required.");
      const manager = new SyncDeviceManager(request.vaultPath, request.passphrase);
      try { const registry = manager.enroll(request.enrollmentRequest); return result(request, { registryRevision: registry.body.revision }); }
      finally { manager.close(); }
    }
    case "revoke": {
      const log = new SyncChangeLog(request.vaultPath, request.passphrase);
      let cutoff: number;
      try { cutoff = Math.max(0, ...log.changes().filter((change) => change.deviceId === request.deviceId).map((change) => change.sequence)); }
      finally { log.close(); }
      const manager = new SyncDeviceManager(request.vaultPath, request.passphrase);
      try { const registry = manager.revoke(request.deviceId!, cutoff); return result(request, { registryRevision: registry.body.revision, epoch: registry.body.epoch, revokedAfterSequence: cutoff }); }
      finally { manager.close(); }
    }
    case "apply":
    case "resolve": {
      if (!request.objectType || !request.objectId) throw new Error("An object type and object ID are required.");
      const manager = new SyncDeviceManager(request.vaultPath, request.passphrase);
      const vault = new SyncedDocumentVault(request.vaultPath, request.passphrase, localDeviceId(manager, request.deviceId));
      try {
        const value = request.operation === "apply"
          ? vault.applyResolved(request.objectType as SyncObjectType, request.objectId)
          : vault.resolveConflict(request.objectType as SyncObjectType, request.objectId, request.selectedHeadId);
        return result(request, value);
      } finally { vault.lock(); manager.close(); }
    }
    case "push": {
      const manager = new SyncDeviceManager(request.vaultPath, request.passphrase);
      const vault = new SyncedDocumentVault(request.vaultPath, request.passphrase, localDeviceId(manager, request.deviceId));
      const log = new SyncChangeLog(request.vaultPath, request.passphrase);
      try {
        vault.captureDesktopChanges();
        const vaultId = manager.fingerprint();
        if (!vaultId) throw new Error("Initialize sync device enrollment before using a relay.");
        const client = new SyncRelayClient(request.relayUrl!, request.relayToken!, vaultId, request.vaultPath);
        const changes = await client.uploadChanges(log.envelopes(), log.changes());
        const registryArtifact = await client.uploadArtifact("registry", manager.exportRegistry());
        const checkpoint = manager.checkpoint();
        const checkpointArtifact = checkpoint ? await client.uploadArtifact("checkpoint", manager.exportCheckpoint()) : null;
        return result(request, { changes, registryArtifact, checkpointArtifact });
      } finally { log.close(); vault.lock(); manager.close(); }
    }
    case "pull": {
      const manager = new SyncDeviceManager(request.vaultPath, request.passphrase);
      const vault = new SyncedDocumentVault(request.vaultPath, request.passphrase, localDeviceId(manager, request.deviceId));
      let log: SyncChangeLog | undefined;
      try {
        vault.captureDesktopChanges();
        const currentAuthority = manager.fingerprint();
        const expectedAuthority = currentAuthority ?? request.authorityFingerprint;
        if (!expectedAuthority) throw new Error("A relay pull requires the verified authority fingerprint.");
        const client = new SyncRelayClient(request.relayUrl!, request.relayToken!, expectedAuthority, request.vaultPath);
        const registryBundles = await client.downloadArtifacts("registry");
        const registries = registryBundles
          .map((value) => ({ value, registry: manager.inspectRegistry(value) }))
          .filter(({ registry }) => syncRegistryFingerprint(registry) === expectedAuthority)
          .sort((left, right) => right.registry.body.revision - left.registry.body.revision);
        const newest = registries[0];
        if (!newest) throw new Error("Relay has no registry for the expected enrollment authority.");
        manager.importRegistry(newest.value, currentAuthority ? undefined : expectedAuthority);
        log = new SyncChangeLog(request.vaultPath, request.passphrase);
        const imported = log.import(await client.downloadChanges());
        const changes = log.changes();
        const blobIds = [...new Set(changes.flatMap(attachmentBlobIds))];
        const blobs = await client.pullBlobs(blobIds);
        const checkpointBundles = await client.downloadArtifacts("checkpoint");
        const checkpoints = checkpointBundles
          .map((value) => ({ value, checkpoint: manager.inspectCheckpoint(value) }))
          .sort((left, right) => left.checkpoint.body.sequence - right.checkpoint.body.sequence);
        let pinned = manager.checkpoint();
        if (pinned) {
          while (true) {
            const extensions = checkpoints.filter(({ checkpoint }) => checkpoint.body.sequence === pinned!.body.sequence + 1 && checkpoint.body.previousCheckpoint === pinned!.id);
            if (extensions.length > 1) throw new Error("Relay contains a forked freshness checkpoint sequence.");
            if (extensions.length === 0) break;
            pinned = manager.importCheckpoint(extensions[0].value, changes);
          }
        } else if (request.checkpointId) {
          const expected = checkpoints.find(({ checkpoint }) => checkpoint.id === request.checkpointId);
          if (!expected) throw new Error("Relay does not contain the expected freshness checkpoint.");
          pinned = manager.importCheckpoint(expected.value, changes, request.checkpointId);
        }
        if (pinned) manager.verifyCheckpoint(changes);
        return result(request, { registryRevision: newest.registry.body.revision, changes: imported, blobs, checkpoint: pinned?.id ?? null });
      } finally { log?.close(); vault.lock(); manager.close(); }
    }
    case "conflicts": {
      const log = new SyncChangeLog(request.vaultPath, request.passphrase);
      try {
        const conflicts = log.conflicts().map(({ objectType, objectId, heads }) => ({ objectType, objectId, heads }));
        return result(request, { conflicts });
      } finally { log.close(); }
    }
  }
}

try {
  process.stdout.write(`${JSON.stringify(await run(readRequest()))}\n`);
} catch {
  // Never reflect `error` because lower-level messages can contain paths or a
  // malformed request. The native caller adds its own safe operation context.
  process.stdout.write(`${JSON.stringify({ version: 1, state: "failed", message: "Desktop sync helper rejected the operation." })}\n`);
  process.exitCode = 1;
}
