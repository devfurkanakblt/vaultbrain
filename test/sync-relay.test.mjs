import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { SyncBlobStore } from "../dist/sync-blobs.js";
import { attachmentBlobIds, startSyncRelay, SyncRelayClient } from "../dist/sync-relay.js";
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

test("the relay stores blobs only under their own SHA-256 and never lists them", async () => {
  const storageDir = tempDir("blob-relay");
  const vaultId = crypto.randomBytes(32).toString("hex");
  const relay = await startSyncRelay({ storageDir, token: TOKEN });
  const base = `${relay.url}/v1/vaults/${vaultId}`;
  const auth = { Authorization: `Bearer ${TOKEN}` };
  const headers = { ...auth, "Content-Type": "application/octet-stream" };
  const body = crypto.randomBytes(1024);
  const id = crypto.createHash("sha256").update(body).digest("hex");

  try {
    const wrong = await fetch(`${base}/blobs/${"f".repeat(64)}`, { method: "PUT", headers, body });
    assert.equal(wrong.status, 400);

    const first = await fetch(`${base}/blobs/${id}`, { method: "PUT", headers, body });
    assert.equal(first.status, 201);
    const again = await fetch(`${base}/blobs/${id}`, { method: "PUT", headers, body });
    assert.equal(again.status, 200);

    const fetched = await fetch(`${base}/blobs/${id}`, { headers: auth });
    assert.equal(fetched.status, 200);
    assert.equal(fetched.headers.get("content-type"), "application/octet-stream");
    assert.deepEqual(Buffer.from(await fetched.arrayBuffer()), body);

    const probe = await fetch(`${base}/blobs/${id}`, { method: "HEAD", headers: auth });
    assert.equal(probe.status, 200);
    const probeMissing = await fetch(`${base}/blobs/${"a".repeat(64)}`, { method: "HEAD", headers: auth });
    assert.equal(probeMissing.status, 404);

    const missing = await fetch(`${base}/blobs/${"a".repeat(64)}`, { headers: auth });
    assert.equal(missing.status, 404);

    // There is deliberately no list route for blobs.
    const listed = await fetch(`${base}/blobs`, { headers: auth });
    assert.equal(listed.status, 404);
    const shortId = await fetch(`${base}/blobs/not-a-blob-id`, { headers: auth });
    assert.equal(shortId.status, 404);

    const oversize = Buffer.alloc(2 * 1024 * 1024 + 1);
    const oversizeId = crypto.createHash("sha256").update(oversize).digest("hex");
    const rejected = await fetch(`${base}/blobs/${oversizeId}`, { method: "PUT", headers, body: oversize });
    assert.equal(rejected.status, 413);

    const badMethod = await fetch(`${base}/blobs/${id}`, { method: "DELETE", headers: auth });
    assert.equal(badMethod.status, 405);

    const unauthorized = await fetch(`${base}/blobs/${id}`);
    assert.equal(unauthorized.status, 401);

    assert.deepEqual(fs.readdirSync(path.join(storageDir, vaultId, "blobs")), [id]);
  } finally {
    await relay.close();
    fs.rmSync(storageDir, { recursive: true, force: true });
  }
});

test("a push uploads blobs before the change, and an interrupted pull resumes", async () => {
  const vaultDir = tempDir("blob-source");
  const targetDir = tempDir("blob-target");
  const storageDir = tempDir("blob-transport");
  const manager = new SyncDeviceManager(vaultDir, PASSPHRASE);
  manager.initializeOwner("Owner", DEVICE_ID, "2026-09-04T10:00:00.000Z");
  const vaultId = manager.fingerprint();
  const log = new SyncChangeLog(vaultDir, PASSPHRASE);

  // Three sealed chunks staged locally, named by the SHA-256 of their own bytes.
  const bodies = [crypto.randomBytes(4096), crypto.randomBytes(8192), crypto.randomBytes(2048)];
  const blobs = bodies.map((body) => crypto.createHash("sha256").update(body).digest("hex"));
  const sourceStore = new SyncBlobStore(vaultDir);
  bodies.forEach((body, index) => sourceStore.put(blobs[index], body));

  const noteChange = log.append(DEVICE_ID, mutation(1, null, "before"), "2026-09-04T10:01:00.000Z");
  const attachmentChange = log.append(
    DEVICE_ID,
    {
      objectType: "attachment",
      objectId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      operation: "put",
      baseRevision: null,
      revision: 1,
      value: {
        filename: "clip.bin",
        mime: "application/octet-stream",
        size: 2 * 1024 * 1024 + 5,
        chunks: 3,
        blobs,
      },
    },
    "2026-09-04T10:02:00.000Z",
  );
  assert.deepEqual(attachmentBlobIds(attachmentChange), blobs);
  assert.deepEqual(attachmentBlobIds(noteChange), []);

  const relay = await startSyncRelay({ storageDir, token: TOKEN });
  const originalFetch = globalThis.fetch;
  const requests = [];
  globalThis.fetch = (input, init) => {
    const target = typeof input === "string" ? input : input.url;
    requests.push(`${init?.method ?? "GET"} ${new URL(target).pathname}`);
    return originalFetch(input, init);
  };

  try {
    const client = new SyncRelayClient(relay.url, TOKEN, vaultId, vaultDir);
    assert.deepEqual(await client.uploadChanges(log.envelopes(), log.changes()), { stored: 2, existing: 0 });

    // The relay never advertises a change whose bytes it does not already hold.
    const changePut = requests.indexOf(`PUT /v1/vaults/${vaultId}/changes/${attachmentChange.id}`);
    assert.ok(changePut >= 0);
    for (const id of blobs) {
      const blobPut = requests.indexOf(`PUT /v1/vaults/${vaultId}/blobs/${id}`);
      assert.ok(blobPut >= 0 && blobPut < changePut, `blob ${id} must be uploaded before its change`);
      const stored = await fetch(`${relay.url}/v1/vaults/${vaultId}/blobs/${id}`, {
        headers: { Authorization: `Bearer ${TOKEN}` },
      });
      assert.equal(stored.status, 200);
    }

    // Re-running a push re-sends only what is genuinely missing.
    assert.deepEqual(await client.pushBlobs(blobs), { uploaded: 0, skipped: 3 });

    // Simulate an interrupted pull: stage all but the last blob, then resume.
    const targetStore = new SyncBlobStore(targetDir);
    for (const id of blobs.slice(0, -1)) targetStore.put(id, sourceStore.read(id));
    const receiver = new SyncRelayClient(relay.url, TOKEN, vaultId, targetDir);
    assert.deepEqual(await receiver.pullBlobs(blobs), { fetched: 1, skipped: 2 });
    assert.deepEqual(targetStore.missing(blobs), []);
    assert.deepEqual(targetStore.read(blobs[2]), bodies[2]);
    assert.deepEqual(await receiver.pullBlobs(blobs), { fetched: 0, skipped: 3 });

    // A relay that cannot produce the bytes fails closed rather than staging junk.
    await assert.rejects(
      () => receiver.pullBlobs(["c".repeat(64)]),
      /Relay is missing/iu,
    );

    // Blob transport needs a local staging directory.
    await assert.rejects(
      () => new SyncRelayClient(relay.url, TOKEN, vaultId).pullBlobs(blobs),
      /vault directory/iu,
    );
  } finally {
    globalThis.fetch = originalFetch;
    await relay.close();
    log.close();
    manager.close();
    fs.rmSync(vaultDir, { recursive: true, force: true });
    fs.rmSync(targetDir, { recursive: true, force: true });
    fs.rmSync(storageDir, { recursive: true, force: true });
  }
});
