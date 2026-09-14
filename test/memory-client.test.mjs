import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { encodeMemoryRequest, decodeMemoryResponse } from "../dist/memory/client.js";
import { formatResolvedPaths, installMemoryConfig, removeMemoryConfig } from "../dist/memory/setup.js";
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
  t.after(() => removeTree(root));
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
  // A regular file in the test's own temp root, so a checkout behind a link
  // cannot add an entry to resolvedPaths.
  const cliPath = path.join(root, "cli.js");
  fs.writeFileSync(cliPath, "");
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
  const regularNode = path.join(root, "node.exe");
  fs.writeFileSync(regularNode, "");
  const result = installMemoryConfig({
    configPath,
    nativeExecutable: linkedNative,
    nodeExecutable: regularNode,
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

test("setup reports the owner-typed path for an already-resolved option via givenPaths", (t) => {
  // The CLI resolves nativeExecutable itself, up front (so the pairing check
  // and the pinned config use the same binary), then passes the already-
  // resolved path as the nativeExecutable option. installMemoryConfig must
  // still report the owner-typed (junction) path as `given` when told about
  // it via givenPaths, not the already-resolved path it was actually given.
  const root = junctionRoot("memory-link-");
  t.after(() => removeTree(root));
  const { realDir, linkDir } = buildJunction(root, "native");
  fs.writeFileSync(path.join(realDir, "vaultbrain-native"), "");
  const nativeGiven = path.join(linkDir, "vaultbrain-native");
  const nativeResolved = fs.realpathSync(nativeGiven);
  assert.notEqual(nativeResolved, nativeGiven);
  const configPath = path.join(root, "config.toml");
  // Regular files created inside the test's own temp root, not paths
  // borrowed from the checkout (e.g. dist/cli.js) — this test must not
  // depend on whether the checkout itself happens to contain a link
  // component.
  const regularFile = path.join(root, "cli.js");
  fs.writeFileSync(regularFile, "");
  const result = installMemoryConfig({
    configPath,
    nativeExecutable: nativeResolved,
    nodeExecutable: regularFile,
    cliPath: regularFile,
    givenPaths: { nativeExecutable: nativeGiven },
  });
  assert.deepEqual(result.resolvedPaths, [{ name: "nativeExecutable", given: nativeGiven, resolved: nativeResolved }]);
  const installed = TOML.parse(fs.readFileSync(configPath, "utf8"));
  assert.equal(installed.mcp_servers.vaultbrain_memory.args[4], nativeResolved);
});

test("setup refuses a pre-resolved path whose component became a link after resolution", (t) => {
  // The CLI resolves the native path, runs the pairing check against it, and
  // only then calls installMemoryConfig. If a component of that resolved path
  // is swapped for a link in between, the install must not re-resolve it to
  // wherever the link now points; it must refuse.
  const root = junctionRoot("memory-link-");
  t.after(() => removeTree(root));
  const realDir = path.join(root, "nat-real");
  fs.mkdirSync(realDir, { recursive: true });
  fs.writeFileSync(path.join(realDir, "native.exe"), "");
  const linkDir = path.join(root, "nat-link");
  fs.symlinkSync(realDir, linkDir, "junction");
  const nativeGiven = path.join(linkDir, "native.exe");
  const nativeResolved = fs.realpathSync(nativeGiven);
  assert.equal(nativeResolved, path.join(realDir, "native.exe"));
  // Substitution: move the real directory away and put a junction to another
  // directory holding a different native.exe in its place.
  fs.renameSync(realDir, path.join(root, "nat-moved"));
  const evilDir = path.join(root, "evil");
  fs.mkdirSync(evilDir, { recursive: true });
  fs.writeFileSync(path.join(evilDir, "native.exe"), "");
  fs.symlinkSync(evilDir, realDir, "junction");
  const regularFile = path.join(root, "cli.js");
  fs.writeFileSync(regularFile, "");
  const configPath = path.join(root, "config.toml");
  const original = "# owner comment\n";
  fs.writeFileSync(configPath, original);
  assert.throws(
    () =>
      installMemoryConfig({
        configPath,
        nativeExecutable: nativeResolved,
        nodeExecutable: regularFile,
        cliPath: regularFile,
        givenPaths: { nativeExecutable: nativeGiven },
      }),
    /symbolic-link/iu
  );
  assert.equal(fs.readFileSync(configPath, "utf8"), original);
  const bakFiles = fs.readdirSync(root).filter((name) => /\.vaultbrain-.*\.bak$/u.test(name));
  assert.deepEqual(bakFiles, []);
});

test("setup reports no entry when givenPaths repeats the path already passed", (t) => {
  const root = junctionRoot("memory-link-");
  t.after(() => removeTree(root));
  const configPath = path.join(root, "config.toml");
  const regularFile = path.join(root, "cli.js");
  fs.writeFileSync(regularFile, "");
  const result = installMemoryConfig({
    configPath,
    nativeExecutable: regularFile,
    nodeExecutable: regularFile,
    cliPath: regularFile,
    givenPaths: { nativeExecutable: regularFile },
  });
  assert.deepEqual(result.resolvedPaths, []);
});

test("setup reports no resolutions when no executable path is linked", (t) => {
  const root = junctionRoot("memory-link-");
  t.after(() => removeTree(root));
  const configPath = path.join(root, "config.toml");
  // A regular file created directly under the test's own temp root, not a
  // path borrowed from the checkout (e.g. dist/cli.js) — this test must not
  // depend on whether the checkout itself happens to contain no link
  // component.
  const regularFile = path.join(root, "cli.js");
  fs.writeFileSync(regularFile, "");
  const result = installMemoryConfig({ configPath, nativeExecutable: regularFile, nodeExecutable: regularFile, cliPath: regularFile });
  assert.deepEqual(result.resolvedPaths, []);
  const installed = TOML.parse(fs.readFileSync(configPath, "utf8"));
  assert.equal(installed.mcp_servers.vaultbrain_memory.command, regularFile);
  assert.deepEqual(installed.mcp_servers.vaultbrain_memory.args, [regularFile, "memory", "mcp", "--native-executable", regularFile]);
});

test("setup does not report a resolution for path normalization without a link", (t) => {
  const root = junctionRoot("memory-link-");
  t.after(() => removeTree(root));
  const subdir = path.join(root, "sub");
  fs.mkdirSync(subdir, { recursive: true });
  const regularFile = path.join(subdir, "node.exe");
  fs.writeFileSync(regularFile, "");
  // Forward slashes and a ".." segment collapse to the same resolved path
  // without following any link; realpathSync only normalizes the string, and
  // that must not be reported as "Resolved symbolic link ...". Built without
  // path.join/path.resolve so the ".." segment survives into the string
  // installMemoryConfig actually receives (path.join would collapse it
  // before the call, making the assertion vacuous).
  const givenWithForwardSlashes = `${root.replace(/\\/gu, "/")}/sub/node.exe`;
  const givenWithDotDot = `${root}${path.sep}sub${path.sep}..${path.sep}sub${path.sep}node.exe`;
  assert.ok(givenWithDotDot.includes(".."), "fixture must actually contain a .. segment");
  const configPath = path.join(root, "config.toml");
  const result = installMemoryConfig({
    configPath,
    nativeExecutable: givenWithForwardSlashes,
    nodeExecutable: givenWithDotDot,
    cliPath: regularFile,
  });
  assert.deepEqual(result.resolvedPaths, []);
  const installed = TOML.parse(fs.readFileSync(configPath, "utf8"));
  assert.equal(installed.mcp_servers.vaultbrain_memory.command, fs.realpathSync(regularFile));
  assert.deepEqual(installed.mcp_servers.vaultbrain_memory.args, [
    fs.realpathSync(regularFile),
    "memory",
    "mcp",
    "--native-executable",
    fs.realpathSync(regularFile),
  ]);
});

test("formatResolvedPaths turns entries into printable lines, or none when empty", () => {
  assert.deepEqual(formatResolvedPaths([]), []);
  assert.deepEqual(
    formatResolvedPaths([
      { name: "nodeExecutable", given: "C:\\nvm4w\\nodejs\\node.exe", resolved: "C:\\Users\\me\\nvm\\v24\\node.exe" },
      { name: "cliPath", given: "C:\\link\\cli.js", resolved: "C:\\real\\cli.js" },
    ]),
    [
      "Resolved symbolic link for nodeExecutable: C:\\nvm4w\\nodejs\\node.exe -> C:\\Users\\me\\nvm\\v24\\node.exe",
      "Resolved symbolic link for cliPath: C:\\link\\cli.js -> C:\\real\\cli.js",
      "The configuration names the resolved binaries and setup must be run again after switching Node versions.",
    ]
  );
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
    (error) =>
      error instanceof Error &&
      error.message.includes(danglingNode) &&
      /Could not resolve installation path/u.test(error.message)
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
  const cliPath = path.join(root, "cli.js");
  fs.writeFileSync(cliPath, "");
  const result = installMemoryConfig({ configPath, nativeExecutable: cliPath, nodeExecutable: linkedNode, cliPath });
  const installed = TOML.parse(fs.readFileSync(configPath, "utf8"));
  assert.equal(installed.mcp_servers.vaultbrain_memory.command, resolvedNode);
  assert.deepEqual(result.resolvedPaths, [{ name: "nodeExecutable", given: linkedNode, resolved: resolvedNode }]);
});

test("disconnect refuses to remove user-modified managed config", (t) => {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "memory-config-"));
  t.after(() => removeTree(root));
  const configPath = path.join(root, "config.toml");
  installMemoryConfig({ configPath, nativeExecutable: process.execPath, nodeExecutable: process.execPath, cliPath: path.resolve("dist/cli.js") });
  fs.appendFileSync(configPath, '\n# later owner edit\n');
  removeMemoryConfig(configPath);
  assert.match(fs.readFileSync(configPath, "utf8"), /later owner edit/u);
});
