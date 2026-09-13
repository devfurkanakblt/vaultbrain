import crypto from "node:crypto";
import { containsSecret, parseHookPayload, type HookPayload } from "./protocol.js";

export type MemoryQueueState = "pending" | "processing" | "done" | "failed" | "expired";

export interface MemoryQueueEntry {
  id: string;
  payload: HookPayload;
  expiresAt: string;
  attempts: number;
  state: MemoryQueueState;
  retryAt?: string;
  /** A bounded classification, never the worker's raw error or output. */
  lastError?: "delivery_failed";
}

const MAX_QUEUE = 500;
const MAX_ATTEMPTS = 3;
const TTL_MS = 7 * 24 * 60 * 60 * 1000;
const RETRY_BACKOFF_MS = [1_000, 5_000, 30_000] as const;

const copy = (entry: MemoryQueueEntry): MemoryQueueEntry => ({
  ...entry,
  payload: { ...entry.payload },
});

function validDate(value: Date, name: string): Date {
  if (!Number.isFinite(value.getTime())) throw new Error(`${name} must be a valid date.`);
  return value;
}

/**
 * A process-local reference queue used by the client adapter. The native
 * broker owns the durable encrypted queue; this class mirrors its state
 * machine so a caller cannot deliver the same pointer concurrently.
 */
export class MemoryPointerQueue {
  private readonly entries = new Map<string, MemoryQueueEntry>();

  enqueue(input: unknown, now = new Date()): MemoryQueueEntry {
    const serialized = JSON.stringify(input);
    if (typeof serialized !== "string") throw new Error("Memory queue payload is invalid.");
    if (containsSecret(serialized)) throw new Error("Memory queue payload contains secret-like content.");
    const payload = parseHookPayload(input);
    const id = crypto.createHash("sha256").update(`${payload.sessionId}\0${payload.turnId}`).digest("hex");
    const current = this.entries.get(id);
    if (current) return copy(current);
    validDate(now, "Queue time");
    if (this.entries.size >= MAX_QUEUE) throw new Error("Memory queue is full; unlock the vault to process pending items.");
    const item: MemoryQueueEntry = {
      id,
      payload,
      expiresAt: new Date(now.getTime() + TTL_MS).toISOString(),
      attempts: 0,
      state: "pending",
    };
    this.entries.set(id, item);
    return copy(item);
  }

  claim(now = new Date()): MemoryQueueEntry[] {
    validDate(now, "Queue time");
    const result: MemoryQueueEntry[] = [];
    for (const [id, entry] of this.entries) {
      if (Date.parse(entry.expiresAt) <= now.getTime()) {
        if (entry.state !== "done" && entry.state !== "expired") {
          this.entries.set(id, { ...entry, state: "expired", retryAt: undefined });
        }
        continue;
      }
      if (entry.state !== "pending") continue;
      if (entry.retryAt && Date.parse(entry.retryAt) > now.getTime()) continue;
      const attempts = entry.attempts + 1;
      const next: MemoryQueueEntry = { ...entry, attempts, state: "processing", retryAt: undefined, lastError: undefined };
      this.entries.set(id, next);
      result.push(copy(next));
    }
    return result;
  }

  complete(id: string): void {
    const entry = this.entries.get(id);
    if (!entry) throw new Error("Unknown memory queue item.");
    if (entry.state === "done") return;
    if (entry.state !== "processing") throw new Error("Memory queue item is not being processed.");
    this.entries.set(id, { ...entry, state: "done", retryAt: undefined, lastError: undefined });
  }

  /** Return a failed delivery to the queue with bounded, non-sensitive retry metadata. */
  fail(id: string, now = new Date(), _reason?: unknown): void {
    const entry = this.entries.get(id);
    if (!entry) throw new Error("Unknown memory queue item.");
    if (entry.state === "failed") return;
    if (entry.state !== "processing") throw new Error("Memory queue item is not being processed.");
    validDate(now, "Queue time");
    if (entry.attempts >= MAX_ATTEMPTS) {
      this.entries.set(id, { ...entry, state: "failed", retryAt: undefined, lastError: "delivery_failed" });
      return;
    }
    const delay = RETRY_BACKOFF_MS[Math.min(entry.attempts - 1, RETRY_BACKOFF_MS.length - 1)];
    this.entries.set(id, {
      ...entry,
      state: "pending",
      retryAt: new Date(now.getTime() + delay).toISOString(),
      lastError: "delivery_failed",
    });
  }

  status(): { pending: number; processing: number; done: number; failed: number; expired: number } {
    const values = [...this.entries.values()];
    return {
      pending: values.filter((entry) => entry.state === "pending").length,
      processing: values.filter((entry) => entry.state === "processing").length,
      done: values.filter((entry) => entry.state === "done").length,
      failed: values.filter((entry) => entry.state === "failed").length,
      expired: values.filter((entry) => entry.state === "expired").length,
    };
  }
}
