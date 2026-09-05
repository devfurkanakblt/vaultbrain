import { spawn } from "node:child_process";
import { once } from "node:events";
import { validateMemoryBatch, type MemoryBatch } from "./protocol.js";

export interface CodexRunnerOptions {
  command?: string;
  model?: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
  version?: string;
}

const SUPPORTED_CLI = "codex-cli0.153.1";

export function buildRunnerArgs(model = "gpt-5.6-luna"): string[] {
  return ["exec", "-", "--ephemeral", "--json", "--ignore-user-config", "--disable", "hooks", "--disable", "web_search", "--sandbox", "read-only", "-m", model];
}

function cleanModel(value: string): string {
  if (!value || value.length > 120 || /[\r\n\u0000]/u.test(value)) throw new Error("Invalid memory worker model.");
  return value;
}

export async function runCodexSummarizer(input: unknown, options: CodexRunnerOptions = {}): Promise<MemoryBatch> {
  if (options.version && options.version !== SUPPORTED_CLI) throw new Error("Unsupported Codex worker version.");
  const timeoutMs = options.timeoutMs ?? 90_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 300_000) throw new Error("Invalid worker timeout.");
  const body = JSON.stringify(input);
  if (!body || Buffer.byteLength(body, "utf8") > 256 * 1024) throw new Error("Worker input exceeds its size limit.");
  const command = options.command ?? "codex";
  const args = buildRunnerArgs(cleanModel(options.model ?? "gpt-5.6-luna"));
  const child = spawn(command, args, { shell: false, windowsHide: true, stdio: ["pipe", "pipe", "pipe"], env: { PATH: process.env.PATH ?? "", HOME: process.env.USERPROFILE ?? process.cwd(), CODEX_HOME: process.env.CODEX_HOME ?? "" } });
  let stdout = "";
  let stderr = "";
  const maxOutput = options.maxOutputBytes ?? 256 * 1024;
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => { stdout += chunk; if (Buffer.byteLength(stdout, "utf8") > maxOutput) child.kill(); });
  child.stderr.on("data", (chunk: string) => { stderr += chunk.slice(0, 512); });
  const timer = setTimeout(() => child.kill(), timeoutMs);
  child.stdin.end(body, "utf8");
  const [result] = await once(child, "close");
  clearTimeout(timer);
  if (result !== 0) throw new Error(`Codex memory worker failed with exit status ${String(result)}${stderr ? "." : ""}`);
  if (Buffer.byteLength(stdout, "utf8") > maxOutput) throw new Error("Codex memory worker output exceeded its size limit.");
  let parsed: unknown;
  try { parsed = JSON.parse(stdout.trim()); } catch { throw new Error("Codex memory worker returned malformed JSON."); }
  return validateMemoryBatch(parsed);
}

