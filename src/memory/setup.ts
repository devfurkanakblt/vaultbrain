import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import * as TOML from "@iarna/toml";
import { assertNoSymlinkComponents, readTextFileLimited, writeFileAtomic } from "../fs-safe.js";

const BEGIN = "# BEGIN vaultbrain-memory managed v1";
const END = "# END vaultbrain-memory managed v1";
const MAX_CONFIG_BYTES = 1024 * 1024;

function checkedPath(file: string): string {
  if (!path.isAbsolute(file) || /[\r\n\0]/u.test(file)) throw new Error("An absolute installation path is required.");
  assertNoSymlinkComponents(path.parse(file).root, file);
  return file;
}

function readConfig(configPath: string): string {
  checkedPath(configPath);
  return fs.existsSync(configPath) ? readTextFileLimited(configPath, MAX_CONFIG_BYTES, "Client configuration") : "";
}

function backup(configPath: string, text: string): string {
  const backupPath = `${configPath}.vaultbrain-${crypto.randomUUID()}.bak`;
  fs.writeFileSync(backupPath, text, { flag: "wx", mode: 0o600 });
  return backupPath;
}

export interface MemorySetupOptions {
  configPath: string;
  nativeExecutable: string;
  nodeExecutable: string;
  cliPath: string;
}

/** Append one parser-validated table, retaining all original bytes and comments. */
export function installMemoryConfig(options: MemorySetupOptions): { backupPath: string } {
  for (const file of [options.nativeExecutable, options.nodeExecutable, options.cliPath]) {
    checkedPath(file);
    if (!fs.statSync(file).isFile()) throw new Error("Installation requires a regular executable or entry file.");
  }
  const original = readConfig(options.configPath);
  const parsed = TOML.parse(original);
  const servers = parsed.mcp_servers as Record<string, unknown> | undefined;
  if (servers?.vaultbrain_memory || original.includes(BEGIN) || original.includes(END)) {
    throw new Error("A memory integration already exists; disconnect it before setup.");
  }
  const table = TOML.stringify({ mcp_servers: { vaultbrain_memory: {
    command: options.nodeExecutable,
    args: [options.cliPath, "memory", "mcp", "--native-executable", options.nativeExecutable],
  } } });
  // Include a digest so removal cannot silently discard owner edits inside the block.
  const digest = crypto.createHash("sha256").update(table).digest("hex");
  const block = `\n${BEGIN}\n# sha256 ${digest}\n${table}${END}\n`;
  const updated = original + block;
  TOML.parse(updated);
  fs.mkdirSync(path.dirname(options.configPath), { recursive: true, mode: 0o700 });
  const backupPath = backup(options.configPath, original);
  if (readConfig(options.configPath) !== original) throw new Error("Client configuration changed during setup.");
  writeFileAtomic(options.configPath, updated);
  return { backupPath };
}

export function removeMemoryConfig(configPath: string): { backupPath?: string } {
  const original = readConfig(configPath);
  TOML.parse(original);
  const start = original.indexOf(`\n${BEGIN}\n`);
  if (start < 0) return {};
  const digestStart = start + `\n${BEGIN}\n`.length;
  const tableStart = original.indexOf("\n", digestStart) + 1;
  const end = original.indexOf(`${END}\n`, tableStart);
  if (!tableStart || end < 0 || original.indexOf(BEGIN, digestStart) !== -1) throw new Error("Managed memory configuration is malformed.");
  const digestLine = original.slice(digestStart, tableStart - 1);
  const table = original.slice(tableStart, end);
  const digest = crypto.createHash("sha256").update(table).digest("hex");
  if (digestLine !== `# sha256 ${digest}`) throw new Error("Managed memory configuration was modified; refusing removal.");
  const updated = original.slice(0, start) + original.slice(end + `${END}\n`.length);
  TOML.parse(updated);
  const backupPath = backup(configPath, original);
  if (readConfig(configPath) !== original) throw new Error("Client configuration changed during disconnect.");
  writeFileAtomic(configPath, updated);
  return { backupPath };
}
