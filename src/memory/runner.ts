import type { MemoryBatch } from "./protocol.js";

export interface CodexRunnerOptions {
  command?: string;
  model?: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
  version?: string;
}

/** Historical vector for compatibility analysis, not an accepted isolation profile. */
export function buildRunnerArgs(model = "gpt-5.6-luna"): string[] {
  return ["exec", "-", "--ephemeral", "--json", "--ignore-user-config", "--disable", "hooks", "--disable", "web_search", "--sandbox", "read-only", "-m", model];
}

export const MEMORY_WORKER_COMPATIBILITY = {
  supported: false,
  reason: "Automatic memory capture requires an accepted worker compatibility and tool-isolation profile.",
} as const;

/** A caller-provided version string cannot authorize a privileged subprocess.
 * The historical adapter inherited CODEX_HOME, allowed ambient tools, and parsed
 * JSONL as one JSON value. Live capture stays fail-closed until a replacement
 * has native lifecycle, process-boundary and installed-CLI acceptance.
 */
export async function runCodexSummarizer(_input: unknown, _options: CodexRunnerOptions = {}): Promise<MemoryBatch> {
  throw new Error(MEMORY_WORKER_COMPATIBILITY.reason);
}
