import { mkdtempSync, writeFileSync } from "node:fs";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { removeTree } from "../fs-tree.js";
import {
  MAX_WORKER_INPUT_BYTES,
  MAX_WORKER_OUTPUT_BYTES,
  normalizeWorkerInput,
  parseWorkerOutput,
  renderWorkerPrompt,
} from "./worker.js";
import type { MemoryBatch } from "./protocol.js";

export interface CodexRunnerOptions {
  /** Absolute, owner-approved Codex executable. PATH lookup is not trusted. */
  command?: string;
  model?: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
  /** An expected value only; the executable's --version output remains authoritative. */
  version?: string;
  signal?: AbortSignal;
}

export const SUPPORTED_CODEX_WORKER_VERSION = "codex-cli0.153.1" as const;
const DEFAULT_MODEL = "gpt-5.6-luna";
const DEFAULT_TIMEOUT_MS = 90_000;
const MAX_TIMEOUT_MS = 300_000;
const VERSION_TIMEOUT_MS = 5_000;
const VERSION_OUTPUT_BYTES = 4 * 1024;

/** The accepted adapter is deliberately disabled until a local binary proves this version. */
export const MEMORY_WORKER_COMPATIBILITY = {
  supported: false,
  version: SUPPORTED_CODEX_WORKER_VERSION,
  reason: `Automatic memory capture requires an installed and verified ${SUPPORTED_CODEX_WORKER_VERSION} worker.`,
} as const;

export function buildRunnerArgs(model = DEFAULT_MODEL, schemaPath?: string): string[] {
  const args = ["exec", "-", "--ephemeral", "--json", "--ignore-user-config", "--disable", "hooks", "--disable", "web_search", "--sandbox", "read-only", "-m", model];
  if (schemaPath !== undefined) {
    if (!path.isAbsolute(schemaPath) || /[\u0000\r\n]/u.test(schemaPath)) throw new Error("Invalid worker schema path.");
    args.push("--output-schema", schemaPath, "--strict-config");
    for (const feature of ["shell_tool", "computer_use", "browser_use", "browser_use_external", "browser_use_full_cdp_access", "apps"]) {
      args.push("--disable", feature);
    }
  }
  return args;
}

function compatibilityError(): Error {
  return new Error(`Memory worker compatibility is unavailable: ${MEMORY_WORKER_COMPATIBILITY.reason}`);
}

function cleanModel(value: string): string {
  if (!value || value.length > 120 || /[\r\n\u0000]/u.test(value)) throw new Error("Invalid memory worker model.");
  return value;
}

function isolatedEnvironment(home: string): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {};
  // Keep only process plumbing. Provider keys, config homes and arbitrary
  // overrides are intentionally omitted even when the parent has them set.
  for (const key of ["PATH", "SystemRoot", "WINDIR", "TEMP", "TMP"]) {
    if (process.env[key]) environment[key] = process.env[key];
  }
  environment.HOME = home;
  environment.USERPROFILE = home;
  environment.CODEX_HOME = home;
  environment.NO_COLOR = "1";
  return environment;
}

const WORKER_OUTPUT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["version", "summary", "candidates"],
  properties: {
    version: { const: 1 },
    summary: { type: "string", maxLength: 16_000 },
    candidates: {
      type: "array",
      maxItems: 32,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["kind", "title", "body", "evidence", "sourceKind", "sensitive", "links"],
        properties: {
          kind: { enum: ["preference", "fact", "project", "decision", "goal", "task", "person", "concept"] },
          title: { type: "string", minLength: 1, maxLength: 400 },
          body: { type: "string", minLength: 1, maxLength: 16_000 },
          evidence: {
            type: "array",
            minItems: 1,
            maxItems: 8,
            items: {
              type: "object",
              additionalProperties: false,
              required: ["messageId", "quote"],
              properties: {
                messageId: { type: "string", minLength: 1, maxLength: 240 },
                quote: { type: "string", minLength: 1, maxLength: 2_000 },
              },
            },
          },
          sourceKind: { enum: ["user-stated", "inference"] },
          sensitive: { type: "boolean" },
          links: { type: "array", maxItems: 16, items: { type: "string", maxLength: 240 } },
          targetId: { type: "string", maxLength: 240 },
          baseRevision: { type: "integer", minimum: 1 },
        },
      },
    },
  },
} as const;

function writeWorkerSchema(home: string): string {
  const schemaPath = path.join(home, "memory-output.schema.json");
  writeFileSync(schemaPath, JSON.stringify(WORKER_OUTPUT_SCHEMA), { flag: "wx", mode: 0o600 });
  return schemaPath;
}

interface ChildResult { code: number | null; stdout: string; }

function runBoundedChild(
  command: string,
  args: readonly string[],
  input: string,
  environment: NodeJS.ProcessEnv,
  cwd: string,
  timeoutMs: number,
  maxOutputBytes: number,
  signal?: AbortSignal,
): Promise<ChildResult> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) { reject(new Error("Memory worker cancelled.")); return; }
    let settled = false;
    const chunks: Buffer[] = [];
    let size = 0;
    let child: ChildProcessWithoutNullStreams | undefined;
    const finish = (error?: Error, result?: ChildResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      if (error) {
        try { child?.kill(); } catch { /* The process may already have exited. */ }
        for (const chunk of chunks) chunk.fill(0);
        reject(error);
        return;
      }
      const stdout = Buffer.concat(chunks).toString("utf8");
      for (const chunk of chunks) chunk.fill(0);
      resolve({ code: result?.code ?? null, stdout });
    };
    const abort = (): void => finish(new Error("Memory worker cancelled."));
    try {
      child = spawn(command, args, {
        shell: false,
        windowsHide: true,
        cwd,
        stdio: ["pipe", "pipe", "pipe"],
        env: environment,
      });
    } catch {
      reject(new Error("Memory worker is unavailable."));
      return;
    }
    if (!child) { reject(new Error("Memory worker is unavailable.")); return; }
    const timer = setTimeout(() => finish(new Error("Memory worker timed out.")), timeoutMs);
    signal?.addEventListener("abort", abort, { once: true });
    const process = child;
    process.on("error", () => finish(new Error("Memory worker is unavailable.")));
    process.stdin.on("error", () => finish(new Error("Memory worker is unavailable.")));
    process.stderr.on("data", () => { /* Drain without retaining diagnostics or secrets. */ });
    process.stdout.on("data", (chunk: Buffer) => {
      if (settled) return;
      size += chunk.length;
      if (size > maxOutputBytes) {
        finish(new Error("Memory worker output exceeded its size limit."));
        return;
      }
      chunks.push(Buffer.from(chunk));
    });
    process.on("close", (code) => {
      if (settled) return;
      finish(undefined, { code, stdout: "" });
    });
    process.stdin.end(input, "utf8");
  });
}

export function parseCodexVersion(output: string): string | undefined {
  const match = output.match(/\bcodex(?:-cli)?\s*(?:v|version\s*)?([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)/iu);
  return match ? `codex-cli${match[1]}` : undefined;
}

async function verifyCommand(command: string, environment: NodeJS.ProcessEnv, cwd: string, signal?: AbortSignal): Promise<string> {
  const result = await runBoundedChild(command, ["--version"], "", environment, cwd, VERSION_TIMEOUT_MS, VERSION_OUTPUT_BYTES, signal);
  if (result.code !== 0) throw compatibilityError();
  const version = parseCodexVersion(result.stdout);
  if (version !== SUPPORTED_CODEX_WORKER_VERSION) throw compatibilityError();
  return version;
}

async function runInternal(input: unknown, options: CodexRunnerOptions): Promise<MemoryBatch> {
  const command = options.command;
  if (!command || !path.isAbsolute(command) || /[\u0000\r\n]/u.test(command)) throw compatibilityError();
  const model = cleanModel(options.model ?? DEFAULT_MODEL);
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > MAX_TIMEOUT_MS) throw new Error("Invalid worker timeout.");
  const maxOutputBytes = options.maxOutputBytes ?? MAX_WORKER_OUTPUT_BYTES;
  if (!Number.isInteger(maxOutputBytes) || maxOutputBytes < 1_024 || maxOutputBytes > MAX_WORKER_OUTPUT_BYTES) throw new Error("Invalid worker output limit.");
  if (options.signal?.aborted) throw new Error("Memory worker cancelled.");

  const home = mkdtempSync(path.join(os.tmpdir(), "vaultbrain-memory-worker-"));
  const environment = isolatedEnvironment(home);
  try {
    const verified = await verifyCommand(command, environment, home, options.signal);
    // A caller-supplied value can narrow an already verified binary, never
    // bless one whose executable reported a different version.
    if (options.version !== undefined && options.version !== verified) throw compatibilityError();
    const normalized = normalizeWorkerInput(input);
    const prompt = renderWorkerPrompt(normalized);
    if (Buffer.byteLength(prompt, "utf8") > MAX_WORKER_INPUT_BYTES) throw new Error("Worker input exceeds its size limit.");
    const schemaPath = writeWorkerSchema(home);
    const result = await runBoundedChild(command, buildRunnerArgs(model, schemaPath), prompt, environment, home, timeoutMs, maxOutputBytes, options.signal);
    if (result.code !== 0) throw new Error("Memory worker failed.");
    return parseWorkerOutput(result.stdout);
  } finally {
    removeTree(home);
  }
}

let activeWorker: Promise<MemoryBatch> | undefined;

/** Run at most one local worker. There is no retry, fallback model or shell. */
export function runCodexSummarizer(input: unknown, options: CodexRunnerOptions = {}): Promise<MemoryBatch> {
  if (activeWorker) return Promise.reject(new Error("Memory worker is already running."));
  const current = runInternal(input, options);
  const tracked = current.finally(() => {
    if (activeWorker === tracked) activeWorker = undefined;
  });
  activeWorker = tracked;
  return tracked;
}
