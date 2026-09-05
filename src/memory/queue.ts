import crypto from "node:crypto";
import { containsSecret, parseHookPayload, type HookPayload } from "./protocol.js";

export interface MemoryQueueEntry { id: string; payload: HookPayload; expiresAt: string; attempts: number; state: "pending" | "done" | "expired"; }

const MAX_QUEUE = 500;
const TTL_MS = 7 * 24 * 60 * 60 * 1000;

export class MemoryPointerQueue {
  private readonly entries = new Map<string, MemoryQueueEntry>();
  enqueue(input: unknown, now = new Date()): MemoryQueueEntry {
    if (containsSecret(JSON.stringify(input))) throw new Error("Memory queue payload contains secret-like content.");
    const payload = parseHookPayload(input);
    const id = crypto.createHash("sha256").update(`${payload.sessionId}\0${payload.turnId}`).digest("hex");
    const current = this.entries.get(id);
    if (current && current.state === "pending") return { ...current };
    if (this.entries.size >= MAX_QUEUE) throw new Error("Memory queue is full; unlock the vault to process pending items.");
    const item: MemoryQueueEntry = { id, payload, expiresAt: new Date(now.getTime() + TTL_MS).toISOString(), attempts: 0, state: "pending" };
    this.entries.set(id, item);
    return { ...item };
  }
  claim(now = new Date()): MemoryQueueEntry[] {
    const result: MemoryQueueEntry[] = [];
    for (const [id, entry] of this.entries) {
      if (Date.parse(entry.expiresAt) <= now.getTime()) { this.entries.set(id, { ...entry, state: "expired" }); continue; }
      if (entry.state === "pending") { const next = { ...entry, attempts: entry.attempts + 1 }; this.entries.set(id, next); result.push(next); }
    }
    return result;
  }
  complete(id: string): void { const entry = this.entries.get(id); if (!entry) throw new Error("Unknown memory queue item."); this.entries.set(id, { ...entry, state: "done" }); }
  status(): { pending: number; done: number; expired: number } { const values = [...this.entries.values()]; return { pending: values.filter((e) => e.state === "pending").length, done: values.filter((e) => e.state === "done").length, expired: values.filter((e) => e.state === "expired").length }; }
}

