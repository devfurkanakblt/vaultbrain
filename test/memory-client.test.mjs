import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { encodeMemoryRequest, decodeMemoryResponse } from "../dist/memory/client.js";
import { installMemoryConfig, removeMemoryConfig } from "../dist/memory/setup.js";
import { formatMemoryMcpResult } from "../dist/memory/mcp.js";
import { parseHookPayload } from "../dist/memory/protocol.js";
import { removeTree } from "../dist/fs-tree.js";
import * as TOML from "@iarna/toml";

// Junctions need no elevated rights on Windows, unlike file symlinks, so tests
// build their own rather than depending on how the host's Node is installed.
function junctionRoot(prefix) {
  return fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), prefix));
}

function buildJunction(root, name) {
  const realDir = path.join(root, `${name}-real`);
  fs.mkdirSync(realDir, { recursive: true });
  const linkDir = path.join(root, `${name}-link`);
  fs.symlinkSync(realDir, linkDir, "junction");
  return { realDir, linkDir };
}

test("memory transport rejects privileged fields and bounds both directions", () => {
  assert.throws(() => encodeMemoryRequest("memory_search", { query: "x", vaultPath: "private" }), /parameters/iu);
  assert.throws(() => encodeMemoryRequest("memory_pair", {}), /method/iu);
  assert.throws(() => encodeMemoryRequest("memory_read", {}), /parameters/iu);
  const serialized = Object.create({ toJSON: () => ({ query: "x", vaultPath: "private" }) });
  serialized.query = "x";
  assert.throws(() => encodeMemoryRequest("memory_search", serialized), /parameters/iu);
  assert.throws(() => encodeMemoryRequest("memory_search", { query: "x".repeat(65536) }), /limit/iu);
  assert.throws(() => decodeMemoryResponse('{"version":2,"ok":true,"result":{}}'), /response/iu);
  assert.throws(() => decodeMemoryResponse('{"version":1,"ok":false,"error":{"code":"DENIED","message":"private-path"}}'), /DENIED/u);
  assert.deepEqual(decodeMemoryResponse('{"version":1,"ok":true,"result":{"paired":false}}'), { paired: false });
});

test("MCP output remains bounded after JSON escaping", () => {
  const rendered = formatMemoryMcpResult({ text: "\u0000".repeat(64 * 1024) });
  assert.ok(Buffer.byteLength(rendered, "utf8") <= 64 * 1024);
  assert.match(rendered, /truncated/u);
});

test("hook records require an offset-bearing ISO timestamp", () => {
  const base = { version: 1, event: "Stop", sessionId: "session", turnId: "turn", transcriptPath: "C:\\session.jsonl" };
  assert.throws(() => parseHookPayload({ ...base, createdAt: "03/04/2026" }), /ISO timestamp/iu);
  assert.equal(parseHookPayload({ ...base, createdAt: "2026-03-04T10:11:12Z" }).createdAt, "2026-03-04T10:11:12.000Z");
});

test("setup preserves unrelated TOML and refuses to overwrite an existing integration", (t) => {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "memory-config-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const configPath = path.join(root, "config.toml");
  const original = '# owner comment\nmodel = "synthetic"\n[mcp_servers.graphify]\ncommand = "graphify"\n';
  fs.writeFileSync(configPath, original);
  const options = { configPath, nativeExecutable: process.execPath, nodeExecutable: process.execPath, cliPath: path.resolve("dist/cli.js") };
  const result = installMemoryConfig(options);
  assert.equal(fs.readFileSync(result.backupPath, "utf8"), original);
  const installed = TOML.parse(fs.readFileSync(configPath, "utf8"));
  assert.equal(installed.mcp_servers.graphify.command, "graphify");
  assert.equal(installed.model, "synthetic");
  assert.equal(installed.mcp_servers.vaultbrain_memory.command, fs.realpathSync(process.execPath));
  assert.throws(() => installMemoryConfig(options), /already/iu);
  removeMemoryConfig(configPath);
  assert.equal(fs.readFileSync(configPath, "utf8"), original);
});

test("setup resolves a node executable reached through a junction", (t) => {
  const root = junctionRoot("memory-link-");
  t.after(() => removeTree(root));
  const { realDir, linkDir } = buildJunction(root, "node");
  fs.writeFileSync(path.join(realDir, "node.exe"), "");
  const linkedNode = path.join(linkDir, "node.exe");
  const resolvedNode = fs.realpathSync(linkedNode);
  assert.notEqual(resolvedNode, linkedNode);
  const configPath = path.join(root, "config.toml");
  const cliPath = path.resolve("dist/cli.js");
  const result = installMemoryConfig({ configPath, nativeExecutable: cliPath, nodeExecutable: linkedNode, cliPath });
  const installed = TOML.parse(fs.readFileSync(configPath, "utf8"));
  assert.equal(installed.mcp_servers.vaultbrain_memory.command, resolvedNode);
  assert.deepEqual(result.resolvedPaths, [{ name: "nodeExecutable", given: linkedNode, resolved: resolvedNode }]);
});

test("setup resolves a native executable and cli entry reached through junctions", (t) => {
  const root = junctionRoot("memory-link-");
  t.after(() => removeTree(root));
  const native = buildJunction(root, "native");
  const cli = buildJunction(root, "cli");
  fs.writeFileSync(path.join(native.realDir, "vaultbrain-native"), "");
  fs.writeFileSync(path.join(cli.realDir, "cli.js"), "");
  const linkedNative = path.join(native.linkDir, "vaultbrain-native");
  const linkedCli = path.join(cli.linkDir, "cli.js");
  const resolvedNative = fs.realpathSync(linkedNative);
  const resolvedCli = fs.realpathSync(linkedCli);
  assert.notEqual(resolvedNative, linkedNative);
  assert.notEqual(resolvedCli, linkedCli);
  const configPath = path.join(root, "config.toml");
  const result = installMemoryConfig({
    configPath,
    nativeExecutable: linkedNative,
    nodeExecutable: path.resolve("dist/cli.js"),
    cliPath: linkedCli,
  });
  const installed = TOML.parse(fs.readFileSync(configPath, "utf8"));
  assert.deepEqual(installed.mcp_servers.vaultbrain_memory.args, [
    resolvedCli,
    "memory",
    "mcp",
    "--native-executable",
    resolvedNative,
  ]);
  assert.deepEqual(result.resolvedPaths, [
    { name: "nativeExecutable", given: linkedNative, resolved: resolvedNative },
    { name: "cliPath", given: linkedCli, resolved: resolvedCli },
  ]);
});

test("setup reports no resolutions when no executable path is linked", (t) => {
  const root = junctionRoot("memory-link-");
  t.after(() => removeTree(root));
  const configPath = path.join(root, "config.toml");
  const cliPath = path.resolve("dist/cli.js");
  const result = installMemoryConfig({ configPath, nativeExecutable: cliPath, nodeExecutable: cliPath, cliPath });
  assert.deepEqual(result.resolvedPaths, []);
  const installed = TOML.parse(fs.readFileSync(configPath, "utf8"));
  assert.equal(installed.mcp_servers.vaultbrain_memory.command, cliPath);
  assert.deepEqual(installed.mcp_servers.vaultbrain_memory.args, [cliPath, "memory", "mcp", "--native-executable", cliPath]);
});

test("setup refuses a dangling junction and leaves the configuration untouched", (t) => {
  const root = junctionRoot("memory-link-");
  t.after(() => removeTree(root));
  const realDir = path.join(root, "dangling-real");
  fs.mkdirSync(realDir, { recursive: true });
  const linkDir = path.join(root, "dangling-link");
  fs.symlinkSync(realDir, linkDir, "junction");
  fs.rmdirSync(realDir);
  const danglingNode = path.join(linkDir, "node.exe");
  const configPath = path.join(root, "config.toml");
  const original = "# owner comment\n";
  fs.writeFileSync(configPath, original);
  assert.throws(
    () =>
      installMemoryConfig({
        configPath,
        nativeExecutable: path.resolve("dist/cli.js"),
        nodeExecutable: danglingNode,
        cliPath: path.resolve("dist/cli.js"),
      }),
    (error) => error instanceof Error && error.message.includes(danglingNode)
  );
  assert.equal(fs.readFileSync(configPath, "utf8"), original);
  const bakFiles = fs.readdirSync(root).filter((name) => /\.vaultbrain-.*\.bak$/u.test(name));
  assert.deepEqual(bakFiles, []);
});

test("setup refuses a configPath reached through a junction", (t) => {
  const root = junctionRoot("memory-link-");
  t.after(() => removeTree(root));
  const { realDir, linkDir } = buildJunction(root, "cfg");
  const configPath = path.join(linkDir, "config.toml");
  const cliPath = path.resolve("dist/cli.js");
  assert.throws(
    () => installMemoryConfig({ configPath, nativeExecutable: cliPath, nodeExecutable: cliPath, cliPath }),
    /symbolic-link/iu
  );
  assert.equal(fs.existsSync(configPath), false);
  assert.deepEqual(fs.readdirSync(realDir), []);
});

test("setup resolves a linked executable under a non-ASCII temporary directory", (t) => {
  const root = junctionRoot("memory-link-ü-é-");
  t.after(() => removeTree(root));
  const { realDir, linkDir } = buildJunction(root, "node");
  fs.writeFileSync(path.join(realDir, "node.exe"), "");
  const linkedNode = path.join(linkDir, "node.exe");
  const resolvedNode = fs.realpathSync(linkedNode);
  assert.notEqual(resolvedNode, linkedNode);
  const configPath = path.join(root, "config.toml");
  const cliPath = path.resolve("dist/cli.js");
  const result = installMemoryConfig({ configPath, nativeExecutable: cliPath, nodeExecutable: linkedNode, cliPath });
  const installed = TOML.parse(fs.readFileSync(configPath, "utf8"));
  assert.equal(installed.mcp_servers.vaultbrain_memory.command, resolvedNode);
  assert.deepEqual(result.resolvedPaths, [{ name: "nodeExecutable", given: linkedNode, resolved: resolvedNode }]);
});

test("disconnect refuses to remove user-modified managed config", (t) => {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "memory-config-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const configPath = path.join(root, "config.toml");
  installMemoryConfig({ configPath, nativeExecutable: process.execPath, nodeExecutable: process.execPath, cliPath: path.resolve("dist/cli.js") });
  fs.appendFileSync(configPath, '\n# later owner edit\n');
  removeMemoryConfig(configPath);
  assert.match(fs.readFileSync(configPath, "utf8"), /later owner edit/u);
});
