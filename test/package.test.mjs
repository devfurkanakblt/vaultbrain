import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const packagePath = new URL("../package.json", import.meta.url);
const cliPath = fileURLToPath(new URL("../dist/cli.js", import.meta.url));

test("the build does not retain the retired sync change-log implementation", async () => {
  await assert.rejects(fs.promises.access(new URL("../src/sync/change-log.ts", import.meta.url)), { code: "ENOENT" });
  await assert.rejects(fs.promises.access(new URL("../dist/sync/change-log.js", import.meta.url)), { code: "ENOENT" });
});

test("the vault-brain package exposes the vbrain CLI", async () => {
  const manifest = JSON.parse(await fs.promises.readFile(packagePath, "utf8"));

  assert.equal(manifest.name, "vault-brain");
  assert.deepEqual(manifest.bin, { vbrain: "./dist/cli.js" });

  const result = spawnSync(process.execPath, [cliPath, "--help"], { encoding: "utf8" });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^Usage: vbrain /mu);
});

// A package that is only present because something else pulled it in works
// under npm, which installs peer dependencies, and fails under installers that
// do not hoist or auto-install them. `zod` reached the MCP server that way.
test("every package the built code imports is a declared dependency", async () => {
  const manifest = JSON.parse(await fs.promises.readFile(packagePath, "utf8"));
  const declared = new Set(Object.keys(manifest.dependencies ?? {}));
  const distDir = fileURLToPath(new URL("../dist/", import.meta.url));
  const undeclared = new Set();
  for (const entry of await fs.promises.readdir(distDir, { recursive: true })) {
    if (!entry.endsWith(".js")) continue;
    const source = await fs.promises.readFile(path.join(distDir, entry), "utf8");
    const statements = /^\s*(?:import|export)\s[^;]*?from\s*"([^"]+)"|^\s*import\s*"([^"]+)"|\bimport\(\s*"([^"]+)"\s*\)/gmu;
    for (const match of source.matchAll(statements)) {
      const specifier = match[1] ?? match[2] ?? match[3];
      if (specifier.startsWith(".") || specifier.startsWith("node:")) continue;
      const parts = specifier.split("/");
      const name = specifier.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
      if (!declared.has(name)) undeclared.add(`${name} (${entry})`);
    }
  }
  assert.deepEqual([...undeclared], []);
});

test("the MCP server introduces itself with the package version", async () => {
  const manifest = JSON.parse(await fs.promises.readFile(packagePath, "utf8"));
  const { addGrant, normalizeScope } = await import("../dist/grants.js");
  const passphrase = "correct horse battery staple";
  const vault = fs.mkdtempSync(path.join(os.tmpdir(), "vault-brain-mcp-version-"));
  addGrant(
    vault,
    { agent: "probe", scopes: [normalizeScope({ file: "health", keys: ["*"], actions: ["discover"], redact: "full" })] },
    passphrase,
  );

  const initialize = {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "probe", version: "0" } },
  };
  const result = spawnSync(process.execPath, [cliPath, "--vault", vault, "mcp", "--agent", "probe"], {
    input: `${JSON.stringify(initialize)}\n`,
    encoding: "utf8",
    env: { ...process.env, VBRAIN_PASSPHRASE: passphrase },
    timeout: 20_000,
  });

  const response = result.stdout
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line))
    .find((message) => message.id === 1);
  assert.ok(response, `no initialize response; stderr: ${result.stderr}`);
  assert.equal(response.result.serverInfo.version, manifest.version);
});
