import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const DEVICE_A = "11111111-1111-4111-8111-111111111111";

/** Runs the built CLI and returns stdout. Throws on a non-zero exit. */
function runCli(args, env = {}) {
  return execFileSync(process.execPath, ["dist/cli.js", ...args], {
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
}

function tempVault(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `secondbrain-cli-${label}-`));
}

test("sync devices list reports the active epoch and per-device state", () => {
  const vaultDir = tempVault("epoch");
  const env = { SBRAIN_PASSPHRASE: "cli-epoch-test-passphrase" };
  const flags = ["--vault", vaultDir, "--experimental-trusted-sync"];

  runCli([...flags, "sync", "devices", "init", "Owner laptop", "--device-id", DEVICE_A], env);
  const listed = runCli([...flags, "sync", "devices", "list"], env);

  assert.match(listed, /epoch 1/u, "the header names the active epoch");
  assert.match(listed, new RegExp(`${DEVICE_A}.*epoch=1.*active`, "u"), "each row carries its epoch and state");
});
