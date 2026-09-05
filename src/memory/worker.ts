import { readFileSync } from "node:fs";
import { validateMemoryBatch } from "./protocol.js";

export function parseWorkerInput(text: string): unknown {
  if (Buffer.byteLength(text, "utf8") > 256 * 1024) throw new Error("Worker input exceeds its size limit.");
  return JSON.parse(text) as unknown;
}

export function workerMain(): void {
  const input = readFileSync(0, "utf8");
  // The worker is a schema boundary. It validates model output supplied by the
  // caller; it never opens a vault or writes a note itself.
  process.stdout.write(JSON.stringify(validateMemoryBatch(parseWorkerInput(input))));
}

if (process.argv[1]?.endsWith("/memory/worker.js") || process.argv[1]?.endsWith("\\memory\\worker.js")) workerMain();

