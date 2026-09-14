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

export type ResolvedExecutableName = "nodeExecutable" | "nativeExecutable" | "cliPath";

export interface ResolvedExecutablePath {
  name: ResolvedExecutableName;
  given: string;
  resolved: string;
}

/**
 * Resolve an executable path through any symbolic-link (including directory
 * junction) components before it is validated. A managed `command`/`args`
 * entry must name the binary that will actually run, not a link that someone
 * with write access to the link can retarget without touching the
 * configuration.
 */
export function resolveExecutablePath(file: string): string {
  if (!path.isAbsolute(file) || /[\r\n\0]/u.test(file)) throw new Error("An absolute installation path is required.");
  try {
    return fs.realpathSync(file);
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error ? String(error.code) : "";
    throw new Error(`Could not resolve installation path: ${file}${code ? ` (${code})` : ""}`, { cause: error });
  }
}

/**
 * Format the executable-path resolutions for display. `resolvedPaths` always
 * comes from `installMemoryConfig` — directly, or via a caller's
 * `givenPaths` when it had to resolve a path itself before calling in (see
 * `MemorySetupOptions.givenPaths`) — which alone applies the
 * `resolved !== path.resolve(given)` rule. Only paths whose resolved form
 * differs from what the owner typed are ever present, so every line here
 * reports a real symbolic-link (or junction) resolution, not mere string
 * normalization.
 */
export function formatResolvedPaths(resolvedPaths: readonly ResolvedExecutablePath[]): string[] {
  if (resolvedPaths.length === 0) return [];
  const lines = resolvedPaths.map(
    ({ name, given, resolved }) => `Resolved symbolic link for ${name}: ${given} -> ${resolved}`
  );
  lines.push("The configuration names the resolved binaries and setup must be run again after switching Node versions.");
  return lines;
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
  /**
   * Owner-typed path to report as `given` (and to compare against the
   * resolved path) for a name whose option value here has already been
   * resolved by the caller. A caller that must resolve a path itself before
   * calling `installMemoryConfig` (for example to reuse the resolved path
   * for a check that must run against the same binary that gets installed)
   * supplies the original, owner-typed path here instead of duplicating the
   * "record only when it differs from the resolved path" rule itself. A
   * name absent from `givenPaths` uses its own option value as `given`.
   *
   * Contract: for a name present in `givenPaths`, the option value must
   * already be the resolved path. `installMemoryConfig` does not resolve it
   * again, so it cannot follow a link substituted into that path after the
   * caller resolved it. Instead it requires the option value to be absolute,
   * free of control characters, to have no symbolic-link (or junction)
   * component, to be a regular file, and to resolve to itself; otherwise it
   * refuses. A name absent from `givenPaths` is resolved here, then checked.
   */
  givenPaths?: Partial<Record<ResolvedExecutableName, string>>;
}

/** Append one parser-validated table, retaining all original bytes and comments. */
export function installMemoryConfig(
  options: MemorySetupOptions
): { backupPath: string; resolvedPaths: ResolvedExecutablePath[] } {
  const resolvedPaths: ResolvedExecutablePath[] = [];
  const resolvedByName = {} as Record<ResolvedExecutableName, string>;
  for (const name of ["nodeExecutable", "nativeExecutable", "cliPath"] as const) {
    const optionValue = options[name];
    const preResolved = options.givenPaths?.[name] !== undefined;
    let resolved: string;
    if (preResolved) {
      // The caller already resolved this path (and may have used it, e.g. for
      // a pairing check). Resolving it again would follow a link substituted
      // into it since then to a different binary, so check it as given: the
      // guard refuses any component that is now a link, and it must still
      // resolve to itself.
      resolved = checkedPath(optionValue);
      if (!fs.statSync(resolved).isFile()) throw new Error("Installation requires a regular executable or entry file.");
      if (resolveExecutablePath(resolved) !== path.resolve(resolved)) {
        throw new Error(`Pre-resolved installation path no longer resolves to itself: ${resolved}`);
      }
    } else {
      resolved = resolveExecutablePath(optionValue);
      checkedPath(resolved);
      if (!fs.statSync(resolved).isFile()) throw new Error("Installation requires a regular executable or entry file.");
    }
    resolvedByName[name] = resolved;
    // The reported `given` is the owner-typed path even when the caller had
    // to resolve it before calling us (see `givenPaths`); otherwise it is
    // the option value itself. Compare against the normalized given path,
    // not the raw string: forward slashes, ".." segments, or other
    // normalization-only differences must not be reported as a
    // symbolic-link resolution.
    const given = options.givenPaths?.[name] ?? optionValue;
    if (resolved !== path.resolve(given)) resolvedPaths.push({ name, given, resolved });
  }
  const original = readConfig(options.configPath);
  const parsed = TOML.parse(original);
  const servers = parsed.mcp_servers as Record<string, unknown> | undefined;
  if (servers?.vaultbrain_memory || original.includes(BEGIN) || original.includes(END)) {
    throw new Error("A memory integration already exists; disconnect it before setup.");
  }
  const table = TOML.stringify({ mcp_servers: { vaultbrain_memory: {
    command: resolvedByName.nodeExecutable,
    args: [resolvedByName.cliPath, "memory", "mcp", "--native-executable", resolvedByName.nativeExecutable],
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
  return { backupPath, resolvedPaths };
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
