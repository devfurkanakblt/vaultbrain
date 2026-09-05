import { boundedString, type MemorySource } from "./protocol.js";

export interface TranscriptOptions { sessionId: string; enrolledAt: string; maxBytes?: number; }

export function parseCodexTranscript(input: string, options: TranscriptOptions): MemorySource[] {
  boundedString(input, "transcript", options.maxBytes ?? 4 * 1024 * 1024);
  const enrolled = Date.parse(options.enrolledAt);
  if (!Number.isFinite(enrolled)) throw new Error("enrolledAt must be an ISO timestamp.");
  const records: MemorySource[] = [];
  for (const [index, line] of input.split(/\r?\n/u).entries()) {
    if (!line.trim()) continue;
    let value: unknown;
    try { value = JSON.parse(line); } catch { throw new Error(`Malformed transcript record at line ${index + 1}.`); }
    if (!value || typeof value !== "object") throw new Error(`Invalid transcript record at line ${index + 1}.`);
    const record = value as Record<string, unknown>;
    if (record.version !== 1) throw new Error("Unsupported transcript version.");
    if (record.type === "tool" || record.type === "compaction" || record.type === "reasoning" || record.type === "subagent" || record.type === "worker") continue;
    if (record.type !== "message") throw new Error(`Unsupported transcript record type at line ${index + 1}.`);
    if (record.sessionKind === "subagent" || record.sessionKind === "worker") continue;
    if (record.role !== "user" && record.role !== "assistant") continue;
    const timestamp = new Date(String(record.createdAt));
    if (!Number.isFinite(timestamp.getTime())) throw new Error(`Invalid transcript timestamp at line ${index + 1}.`);
    if (timestamp.getTime() <= enrolled) continue;
    const messageId = boundedString(record.id, "message id", 240);
    const text = boundedString(record.text, "message text", 64 * 1024);
    records.push({ sessionId: boundedString(options.sessionId, "sessionId", 240), turnId: messageId, messageId, role: record.role, timestamp: timestamp.toISOString(), text });
  }
  return records;
}
