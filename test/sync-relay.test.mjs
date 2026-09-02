import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { startSyncRelay, SyncRelayClient } from "../dist/sync-relay.js";
import { SyncChangeLog, SyncDeviceManager } from "../dist/sync.js";

const PASSPHRASE = "relay-test-passphrase";
const TOKEN = "relay-test-token-that-is-at-least-thirty-two-bytes";
const DEVICE_ID = "11111111-1111-4111-8111-111111111111";

function tempDir(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `secondbrain-relay-${label}-`));
}

function mutation(revision, baseRevision, body) {
  return {
    objectType: "note",
    objectId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    operation: "put",
    baseRevision,
    revision,
    value: { title: "Relay test", body },
  };
}

test("the self-hosted relay stores only authenticated opaque immutable objects", async () => {
  const vaultDir = tempDir("vault");
  const storageDir = tempDir("storage");
  const manager = new SyncDeviceManager(vaultDir, PASSPHRASE);
  manager.initializeOwner("Owner", DEVICE_ID, "2026-09-03T10:00:00.000Z");
  const vaultId = manager.fingerprint();
  const registry = manager.exportRegistry();
  const log = new SyncChangeLog(vaultDir, PASSPHRASE);
  log.append(DEVICE_ID, mutation(1, null, "first"), "2026-09-03T10:01:00.000Z");
  log.append(DEVICE_ID, mutation(2, 1, "second"), "2026-09-03T10:02:00.000Z");
  const envelopes = log.envelopes();
  const relay = await startSyncRelay({ storageDir, token: TOKEN });

  try {
    assert.throws(
      () => new SyncRelayClient("http://relay.example", TOKEN, vaultId),
      /must use HTTPS/iu,
    );
    assert.throws(
      () => new SyncRelayClient("https://relay.example/unexpected", TOKEN, vaultId),
      /must be an HTTP\(S\) origin/iu,
    );
    const unauthorized = await fetch(`${relay.url}/v1/vaults/${vaultId}/changes`);
    assert.equal(unauthorized.status, 401);

    const client = new SyncRelayClient(relay.url, TOKEN, vaultId);
    assert.deepEqual(await client.uploadChanges(envelopes), { stored: 2, existing: 0 });
    assert.deepEqual(await client.uploadChanges(envelopes), { stored: 0, existing: 2 });
    assert.deepEqual(await client.downloadChanges(), envelopes.slice().sort((a, b) => a.id.localeCompare(b.id)));

    const artifactId = await client.uploadArtifact("registry", registry);
    assert.equal(artifactId, crypto.createHash("sha256").update(JSON.stringify(registry)).digest("hex"));
    assert.deepEqual(await client.downloadArtifacts("registry"), [registry]);

    const storedText = fs
      .readdirSync(path.join(storageDir, vaultId, "changes"))
      .map((name) => fs.readFileSync(path.join(storageDir, vaultId, "changes", name), "utf8"))
      .join("\n");
    assert.doesNotMatch(storedText, /Relay test|first|second/u);

    const wrongId = "0".repeat(64);
    const rejected = await fetch(`${relay.url}/v1/vaults/${vaultId}/changes/${wrongId}`, {
      method: "PUT",
      headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
      body: JSON.stringify(envelopes[0]),
    });
    assert.equal(rejected.status, 400);

    const invalidArtifact = Buffer.from("{}", "utf8");
    const invalidArtifactId = crypto.createHash("sha256").update(invalidArtifact).digest("hex");
    const rejectedArtifact = await fetch(
      `${relay.url}/v1/vaults/${vaultId}/artifacts/checkpoint/${invalidArtifactId}`,
      {
        method: "PUT",
        headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
        body: invalidArtifact,
      },
    );
    assert.equal(rejectedArtifact.status, 400);
  } finally {
    await relay.close();
    log.close();
    manager.close();
    fs.rmSync(vaultDir, { recursive: true, force: true });
    fs.rmSync(storageDir, { recursive: true, force: true });
  }
});

test("relay byte and object quotas reject additional data without partial writes", async () => {
  const vaultDir = tempDir("quota-vault");
  const storageDir = tempDir("quota-storage");
  const manager = new SyncDeviceManager(vaultDir, PASSPHRASE);
  manager.initializeOwner("Owner", DEVICE_ID, "2026-09-03T11:00:00.000Z");
  const log = new SyncChangeLog(vaultDir, PASSPHRASE);
  log.append(DEVICE_ID, mutation(1, null, "one"), "2026-09-03T11:01:00.000Z");
  log.append(DEVICE_ID, mutation(2, 1, "two"), "2026-09-03T11:02:00.000Z");
  const relay = await startSyncRelay({ storageDir, token: TOKEN, maxChanges: 1 });

  try {
    const client = new SyncRelayClient(relay.url, TOKEN, manager.fingerprint());
    await assert.rejects(() => client.uploadChanges(log.envelopes()), /change quota exceeded/iu);
    assert.equal(fs.readdirSync(path.join(storageDir, manager.fingerprint(), "changes")).length, 1);
  } finally {
    await relay.close();
    log.close();
    manager.close();
    fs.rmSync(vaultDir, { recursive: true, force: true });
    fs.rmSync(storageDir, { recursive: true, force: true });
  }
});
