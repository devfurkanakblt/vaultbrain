import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile, access } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const packagePath = new URL("../package.json", import.meta.url);
const cliPath = fileURLToPath(new URL("../dist/cli.js", import.meta.url));

test("the build does not retain the retired sync change-log implementation", async () => {
  await assert.rejects(access(new URL("../src/sync/change-log.ts", import.meta.url)), { code: "ENOENT" });
  await assert.rejects(access(new URL("../dist/sync/change-log.js", import.meta.url)), { code: "ENOENT" });
});

test("the vault-brain package exposes the vbrain CLI", async () => {
  const manifest = JSON.parse(await readFile(packagePath, "utf8"));

  assert.equal(manifest.name, "vault-brain");
  assert.deepEqual(manifest.bin, { vbrain: "./dist/cli.js" });

  const result = spawnSync(process.execPath, [cliPath, "--help"], { encoding: "utf8" });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^Usage: vbrain /mu);
});
