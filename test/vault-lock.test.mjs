import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { inspectVaultLock, recoverVaultLock, withVaultLock } from "../dist/vault-lock.js";
import { removeTree } from "../scripts/fs-tree.mjs";

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
    removeTree(vaultDir);
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
  removeTree(vaultDir);
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
    removeTree(vaultDir);
  }
});

test("a reused live PID is refused even when its recorded acquisition is ancient", () => {
  const vaultDir = temporaryVault("pid-reuse");
  try {
    writeLock(vaultDir, recordFor(process.pid, { acquiredAt: "2000-01-01T00:00:00.000Z" }));
    assert.throws(() => recoverVaultLock(vaultDir), /live local process/);
    assert.equal(inspectVaultLock(vaultDir).holder.pid, process.pid);
  } finally { removeTree(vaultDir); }
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
  } finally { removeTree(vaultDir); }
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
    removeTree(vaultDir);
  }
});

// Windows reports a file another process is creating, closing or deleting as
// EPERM or EBUSY rather than EEXIST. For a long time these loops treated only
// EEXIST as contention and let everything else abort the command, so a
// concurrent `vbrain add` could fail outright with
// "EPERM: operation not permitted, open '...\.sbrain.lock.transition'" —
// exactly the failure holding the lock exists to prevent. Seen on a Windows CI
// runner; too timing-dependent to reproduce by racing real processes, so these
// drive the decision directly.

test("a transient EPERM while taking the lock is retried, not raised", () => {
  const vault = temporaryVault("eperm-retry");
  try {
    const open = fs.openSync;
    let denials = 2;
    fs.openSync = (target, flags, mode) => {
      if (typeof target === "string" && target.endsWith(".sbrain.lock.transition") && denials > 0) {
        denials -= 1;
        const error = new Error("EPERM: operation not permitted, open");
        error.code = "EPERM";
        throw error;
      }
      return open(target, flags, mode);
    };
    try {
      const answer = withVaultLock(vault, () => "done");
      assert.equal(answer, "done", "the lock was taken once the collision cleared");
      assert.equal(denials, 0, "both transient failures were actually exercised");
    } finally {
      fs.openSync = open;
    }
  } finally {
    removeTree(vault);
  }
});

test("a permission error that never clears is reported as itself, not as a busy vault", () => {
  const vault = temporaryVault("eperm-persistent");
  try {
    const open = fs.openSync;
    fs.openSync = (target, flags, mode) => {
      if (typeof target === "string" && target.endsWith(".sbrain.lock.transition")) {
        const error = new Error("EACCES: permission denied, open");
        error.code = "EACCES";
        throw error;
      }
      return open(target, flags, mode);
    };
    try {
      // This passed before the retry existed too, because the error was simply
      // raised on the spot. It guards the new path rather than the old bug:
      // now that these codes are retried, the deadline must re-raise the real
      // error. "Vault is being written by process ..." would send the reader
      // looking for a process that does not exist.
      assert.throws(() => withVaultLock(vault, () => "done", { waitMs: 60 }), /EACCES/u);
    } finally {
      fs.openSync = open;
    }
  } finally {
    removeTree(vault);
  }
});

test("a lock genuinely held by a live process still reports the holder", () => {
  const vault = temporaryVault("still-busy");
  const live = startLiveProcess();
  try {
    writeLock(vault, recordFor(live.pid, { staleMs: 60_000, acquiredAt: new Date().toISOString() }));
    assert.throws(() => withVaultLock(vault, () => "done", { waitMs: 60 }), (error) => {
      assert.equal(error.name, "VaultBusyError");
      assert.match(String(error.message), new RegExp(`process ${live.pid}`, "u"));
      return true;
    });
  } finally {
    live.kill();
    removeTree(vault);
  }
});
