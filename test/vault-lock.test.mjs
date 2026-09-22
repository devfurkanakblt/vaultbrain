import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";

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

/**
 * Spawns a process that keeps handing the lock on: it rewrites the record with
 * a fresh token every `intervalMs`, as a queue of writers would, and removes
 * it after `holdMs` unless `forever` is set. It stands in for the fan-out this
 * lock is meant to serialise -- eight `vbrain add` calls, each taking its turn.
 */
function startHandOffs(vaultDir, { intervalMs = 60, holdMs = 1_500, forever = false } = {}) {
  const script = `
    const fs = require("node:fs");
    const os = require("node:os");
    const path = require("node:path");
    const lockPath = path.join(${JSON.stringify(vaultDir)}, ".sbrain.lock");
    const started = Date.now();
    const write = () => {
      if (!${forever} && Date.now() - started > ${holdMs}) {
        try { fs.unlinkSync(lockPath); } catch {}
        process.exit(0);
      }
      fs.writeFileSync(lockPath, JSON.stringify({
        token: require("node:crypto").randomUUID(),
        pid: process.pid,
        host: os.hostname(),
        acquiredAt: new Date().toISOString(),
        staleMs: 60_000,
      }), { mode: 0o600 });
      setTimeout(write, ${intervalMs});
    };
    write();
  `;
  return spawn(process.execPath, ["-e", script], { stdio: "ignore" });
}

/** Waits until the hand-off process has actually taken the lock. */
async function untilLocked(vaultDir) {
  const lockPath = path.join(vaultDir, ".sbrain.lock");
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (fs.existsSync(lockPath)) return;
    await delay(25);
  }
  throw new Error("the hand-off process never took the lock");
}

// The defect this covers: the wait budget was spent on the whole queue rather
// than on one holder, so a writer at the back of a fan-out failed with "vault
// is being written by ..." while the lock was in fact being handed on
// normally. A queue that is draining is not a busy vault.
test("a waiter keeps waiting while the lock is being handed on", async () => {
  const vault = temporaryVault("handoff");
  const handing = startHandOffs(vault, { holdMs: 1_200 });
  try {
    await untilLocked(vault);
    const started = Date.now();
    assert.equal(withVaultLock(vault, () => "acquired", { waitMs: 300 }), "acquired");
    assert.ok(Date.now() - started > 300, "it waited past the per-holder budget rather than failing at it");
  } finally {
    handing.kill();
    removeTree(vault);
  }
});

// The other half: patience is for a queue, not for a holder that never moves.
// A stuck holder must still be reported within the budget rather than being
// waited out for as long as the ceiling allows.
test("a waiter still gives up on one holder that never lets go", () => {
  const vault = temporaryVault("stuck");
  const live = startLiveProcess();
  try {
    writeLock(vault, recordFor(live.pid, { staleMs: 60_000, acquiredAt: new Date().toISOString() }));
    const started = Date.now();
    assert.throws(
      () => withVaultLock(vault, () => "done", { waitMs: 300 }),
      (error) => error.name === "VaultBusyError",
    );
    assert.ok(Date.now() - started < 3_000, "it failed on the budget, not on the ceiling");
  } finally {
    live.kill();
    removeTree(vault);
  }
});

// Waiting while the queue moves must still terminate: hand-offs that never end
// are a livelock, and a command that never returns is worse than one that says
// the vault is busy.
test("an endless hand-off chain is bounded by the ceiling", async () => {
  const vault = temporaryVault("ceiling");
  const handing = startHandOffs(vault, { forever: true });
  try {
    await untilLocked(vault);
    const started = Date.now();
    assert.throws(
      () => withVaultLock(vault, () => "done", { waitMs: 200, maxWaitMs: 800 }),
      (error) => error.name === "VaultBusyError",
    );
    const waited = Date.now() - started;
    assert.ok(waited >= 800, `it honoured the ceiling before giving up, waited ${waited}ms`);
    assert.ok(waited < 5_000, `it did not wait past the ceiling, waited ${waited}ms`);
  } finally {
    handing.kill();
    removeTree(vault);
  }
});
