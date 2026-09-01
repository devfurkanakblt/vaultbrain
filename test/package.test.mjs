import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const packagePath = new URL("../package.json", import.meta.url);
const cliPath = fileURLToPath(new URL("../dist/cli.js", import.meta.url));

test("the vault-brain package exposes the vbrain CLI", async () => {
  const manifest = JSON.parse(await readFile(packagePath, "utf8"));

  assert.equal(manifest.name, "vault-brain");
  assert.deepEqual(manifest.bin, { vbrain: "./dist/cli.js" });

  const result = spawnSync(process.execPath, [cliPath, "--help"], { encoding: "utf8" });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^Usage: vbrain /mu);
});
