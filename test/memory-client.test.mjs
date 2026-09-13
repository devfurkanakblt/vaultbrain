import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { encodeMemoryRequest, decodeMemoryResponse } from "../dist/memory/client.js";
import { installMemoryConfig, removeMemoryConfig } from "../dist/memory/setup.js";
import { formatMemoryMcpResult } from "../dist/memory/mcp.js";
import { parseHookPayload } from "../dist/memory/protocol.js";
import * as TOML from "@iarna/toml";

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
  assert.equal(installed.mcp_servers.vaultbrain_memory.command, process.execPath);
  assert.throws(() => installMemoryConfig(options), /already/iu);
  removeMemoryConfig(configPath);
  assert.equal(fs.readFileSync(configPath, "utf8"), original);
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
