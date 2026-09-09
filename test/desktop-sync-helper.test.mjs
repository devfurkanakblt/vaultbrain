import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import test from "node:test";
import { DocumentVault } from "../dist/documents.js";
import { startSyncRelay, SyncRelayClient } from "../dist/sync-relay.js";

const PASS = "desktop-helper-passphrase";
const TOKEN = "desktop-helper-relay-token-012345678901234567890";
const HELPER = path.resolve("dist/desktop-sync-helper.js");

async function call(request) {
  const child = spawn(process.execPath, [HELPER], { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
  child.stdin.end(`${JSON.stringify(request)}\n`);
  const stdout = []; const stderr = [];
  child.stdout.on("data", (chunk) => stdout.push(chunk));
  child.stderr.on("data", (chunk) => stderr.push(chunk));
  const status = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code) => resolve(code));
  });
  const output = Buffer.concat(stdout).toString("utf8");
  assert.equal(status, 0, Buffer.concat(stderr).toString("utf8") || output);
  assert.equal(Buffer.concat(stderr).toString("utf8"), "");
  return JSON.parse(output);
}

test("packaged helper initializes a device and pushes captured desktop edits", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "desktop-sync-helper-"));
  const vault = path.join(root, "vault");
  const relayDir = path.join(root, "relay");
  let relay;
  let native;
  try {
    native = new DocumentVault(vault, PASS);
    native.put({ path: "Native.md", body: "written by the desktop core" });
    native.lock();
    relay = await startSyncRelay({ storageDir: relayDir, token: TOKEN });
    const initialized = await call({ version: 1, operation: "init", vaultPath: vault, passphrase: PASS, deviceName: "Test desktop" });
    assert.equal(initialized.state, "complete");
    const { deviceId, authorityFingerprint } = initialized.result;
    assert.match(deviceId, /^[0-9a-f-]{36}$/u);
    assert.match(authorityFingerprint, /^[0-9a-f]{64}$/u);
    const pushed = await call({ version: 1, operation: "push", vaultPath: vault, passphrase: PASS, deviceId, relayUrl: relay.url, relayToken: TOKEN });
    assert.equal(pushed.state, "complete");
    assert.equal(pushed.result.changes.stored, 4);
    const conflicts = await call({ version: 1, operation: "conflicts", vaultPath: vault, passphrase: PASS });
    assert.deepEqual(conflicts.result.conflicts, [], "conflict inspection must return IDs only and no bodies");
    const client = new SyncRelayClient(relay.url, TOKEN, authorityFingerprint);
    assert.equal((await client.downloadChanges()).length, 4);
  } finally {
    native?.lock();
    await relay?.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});
