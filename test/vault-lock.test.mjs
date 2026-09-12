import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { inspectVaultLock, recoverVaultLock } from "../dist/vault-lock.js";

function temporaryVault(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `vault-lock-${label}-`));
}

function writeLock(vaultDir, record) {
  fs.writeFileSync(path.join(vaultDir, ".sbrain.lock"), JSON.stringify(record), { mode: 0o600 });
}

function recordFor(pid, overrides = {}) {
  return {
    token: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    pid,
    host: os.hostname(),
    acquiredAt: new Date(Date.now() - 60_000).toISOString(),
    staleMs: 1,
    ...overrides,
  };
}

function startLiveProcess() {
  const child = spawn(process.execPath, ["-e", "setTimeout(() => {}, 30_000)"], { stdio: "ignore" });
  return child;
}

function runCli(args) {
  return execFileSync(process.execPath, ["dist/cli.js", ...args], { encoding: "utf8" });
}

test("a live same-host process is reported and cannot be recovered", () => {
  const vaultDir = temporaryVault("live");
  const child = startLiveProcess();
  try {
    writeLock(vaultDir, recordFor(child.pid));
    assert.equal(inspectVaultLock(vaultDir).state, "live");
    assert.throws(() => recoverVaultLock(vaultDir), /still held by a live local process/u);
  } finally {
    child.kill();
    fs.rmSync(vaultDir, { recursive: true, force: true });
  }
});

test("a proven-dead same-host process is recovered without touching rekey state", () => {
  const vaultDir = temporaryVault("dead");
  fs.mkdirSync(path.join(vaultDir, ".rekey"));
  fs.writeFileSync(path.join(vaultDir, ".rekey", "journal.json"), "{}", "utf8");
  writeLock(vaultDir, recordFor(999_999));

  assert.equal(inspectVaultLock(vaultDir).state, "dead");
  assert.deepEqual(recoverVaultLock(vaultDir), { recovered: true, state: "dead" });
  assert.equal(inspectVaultLock(vaultDir).state, "unlocked");
  assert.equal(fs.existsSync(path.join(vaultDir, ".rekey", "journal.json")), true);
  fs.rmSync(vaultDir, { recursive: true, force: true });
});

test("remote and malformed locks fail closed", () => {
  const vaultDir = temporaryVault("unsafe");
  try {
    writeLock(vaultDir, recordFor(999_999, { host: "another-host" }));
    assert.equal(inspectVaultLock(vaultDir).state, "remote");
    assert.throws(() => recoverVaultLock(vaultDir), /not on this host/u);

    fs.writeFileSync(path.join(vaultDir, ".sbrain.lock"), "not json", "utf8");
    assert.equal(inspectVaultLock(vaultDir).state, "malformed");
    assert.throws(() => recoverVaultLock(vaultDir), /malformed/u);
  } finally {
    fs.rmSync(vaultDir, { recursive: true, force: true });
  }
});

test("a reused live PID is refused even when its recorded acquisition is ancient", () => {
  const vaultDir = temporaryVault("pid-reuse");
  try {
    writeLock(vaultDir, recordFor(process.pid, { acquiredAt: "2000-01-01T00:00:00.000Z" }));
    assert.throws(() => recoverVaultLock(vaultDir), /live local process/);
    assert.equal(inspectVaultLock(vaultDir).holder.pid, process.pid);
  } finally { fs.rmSync(vaultDir, { recursive: true, force: true }); }
});

test("concurrent recovery attempts cannot both remove a dead owner lock", async () => {
  const vaultDir = temporaryVault("concurrent");
  try {
    writeLock(vaultDir, recordFor(999_999));
    const invoke = () => new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ["--input-type=module", "-e", "import {recoverVaultLock} from './dist/vault-lock.js'; console.log(JSON.stringify(recoverVaultLock(process.argv[1])));", vaultDir], { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
      let output = "", error = "";
      child.stdout.on("data", data => { output += data; });
      child.stderr.on("data", data => { error += data; });
      child.on("error", reject);
      child.on("close", code => code === 0 ? resolve(JSON.parse(output)) : reject(new Error(error)));
    });
    const results = await Promise.all([invoke(), invoke()]);
    assert.equal(results.filter(result => result.recovered).length, 1);
    assert.equal(inspectVaultLock(vaultDir).state, "unlocked");
  } finally { fs.rmSync(vaultDir, { recursive: true, force: true }); }
});

test("vault-lock status and recover work while a rekey journal is present", () => {
  const vaultDir = temporaryVault("cli");
  try {
    fs.mkdirSync(path.join(vaultDir, ".rekey"));
    fs.writeFileSync(path.join(vaultDir, ".rekey", "journal.json"), "{}", "utf8");
    writeLock(vaultDir, recordFor(999_999));

    assert.equal(JSON.parse(runCli(["--vault", vaultDir, "vault-lock", "status"])).state, "dead");
    assert.match(runCli(["--vault", vaultDir, "vault-lock", "recover"]), /Recovered dead same-host vault lock/u);
    assert.equal(JSON.parse(runCli(["--vault", vaultDir, "vault-lock", "status"])).state, "unlocked");
    assert.equal(fs.existsSync(path.join(vaultDir, ".rekey", "journal.json")), true);
  } finally {
    fs.rmSync(vaultDir, { recursive: true, force: true });
  }
});
