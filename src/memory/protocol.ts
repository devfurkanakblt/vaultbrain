import crypto from "node:crypto";

export const MEMORY_PROTOCOL_VERSION = 1 as const;
export const MAX_TEXT_BYTES = 64 * 1024;
export const MAX_BATCH_BYTES = 256 * 1024;
const SECRET_PATTERNS = [/\b(?:api[_ -]?key|access[_ -]?token|secret|password|passphrase)\s*[:=]/iu, /\bsk-[A-Za-z0-9_-]{12,}/u];

export type MemoryRole = "user" | "assistant";
export type MemoryKind = "preference" | "fact" | "project" | "decision" | "goal" | "task" | "person" | "concept";
export type SourceKind = "user-stated" | "inference";

export interface MemorySource { sessionId: string; turnId: string; messageId: string; role: MemoryRole; timestamp: string; text: string; }
export interface HookPayload { version: 1; event: "Stop" | "PreCompact" | "SessionEnd"; sessionId: string; turnId: string; transcriptPath: string; createdAt: string; }
export interface CandidateEvidence { messageId: string; quote: string; }
export interface MemoryCandidate { kind: MemoryKind; title: string; body: string; evidence: CandidateEvidence[]; sourceKind: SourceKind; sensitive: boolean; links: string[]; targetId?: string; baseRevision?: number; }
export interface MemoryBatch { version: 1; summary: string; candidates: MemoryCandidate[]; }
export interface MemorySummary { id: string; title: string; body: string; source: string; }

export function boundedString(value: unknown, name: string, maxBytes = MAX_TEXT_BYTES): string {
  const allowsNewlines = ["text", "transcript", "body", "summary"].includes(name);
  if (typeof value !== "string" || !value.trim() || (!allowsNewlines && /[\u0000\r\n]/u.test(value))) throw new Error(`${name} must be a non-empty string.`);
  if (Buffer.byteLength(value, "utf8") > maxBytes) throw new Error(`${name} exceeds its size limit.`);
  return value;
}

export function containsSecret(value: string): boolean { return SECRET_PATTERNS.some((pattern) => pattern.test(value)); }

function id(value: unknown, name: string): string { return boundedString(value, name, 240).replace(/[\r\n]/gu, ""); }
function iso(value: unknown, name: string): string { const text = boundedString(value, name, 80); if (!Number.isFinite(Date.parse(text))) throw new Error(`${name} must be an ISO timestamp.`); return new Date(text).toISOString(); }

export function parseHookPayload(input: unknown): HookPayload {
  if (!input || typeof input !== "object") throw new Error("Invalid memory hook payload.");
  if ("command" in input || "text" in input || "title" in input) throw new Error("Memory hook payload cannot contain commands or content.");
  const value = input as Record<string, unknown>;
  if (value.version !== MEMORY_PROTOCOL_VERSION) throw new Error("Unsupported memory hook payload version.");
  if (!["Stop", "PreCompact", "SessionEnd"].includes(String(value.event))) throw new Error("Unsupported memory hook event.");
  return { version: 1, event: value.event as HookPayload["event"], sessionId: id(value.sessionId, "sessionId"), turnId: id(value.turnId, "turnId"), transcriptPath: id(value.transcriptPath, "transcriptPath"), createdAt: iso(value.createdAt, "createdAt") };
}

export function dedupeKey(payload: HookPayload, summarizerVersion: string): string {
  return crypto.createHash("sha256").update(`${payload.sessionId}\0${payload.turnId}\0${summarizerVersion}`).digest("hex");
}

export function validateMemoryBatch(input: unknown): MemoryBatch {
  const raw = JSON.stringify(input);
  if (!raw || Buffer.byteLength(raw, "utf8") > MAX_BATCH_BYTES) throw new Error("Memory batch exceeds its size limit.");
  if (!input || typeof input !== "object") throw new Error("Invalid memory batch.");
  const value = input as Record<string, unknown>;
  if (value.version !== 1 || typeof value.summary !== "string" || !Array.isArray(value.candidates) || value.candidates.length > 32) throw new Error("Invalid memory batch schema.");
  const candidates = value.candidates.map((item) => validateCandidate(item));
  return { version: 1, summary: boundedString(value.summary, "summary", 16_000), candidates };
}

export function validateCandidate(input: unknown): MemoryCandidate {
  if (!input || typeof input !== "object") throw new Error("Invalid memory candidate.");
  const value = input as Record<string, unknown>;
  const kinds: MemoryKind[] = ["preference", "fact", "project", "decision", "goal", "task", "person", "concept"];
  if (!kinds.includes(value.kind as MemoryKind) || !["user-stated", "inference"].includes(String(value.sourceKind))) throw new Error("Invalid memory candidate classification.");
  const title = boundedString(value.title, "title", 400);
  const body = boundedString(value.body, "body", 16_000);
  if (containsSecret(`${title}\n${body}`)) throw new Error("Memory candidate contains secret-like content.");
  if (!Array.isArray(value.evidence) || value.evidence.length < 1 || value.evidence.length > 8) throw new Error("Memory candidate needs bounded evidence.");
  const evidence = value.evidence.map((item) => {
    if (!item || typeof item !== "object") throw new Error("Invalid memory evidence.");
    const e = item as Record<string, unknown>;
    const quote = boundedString(e.quote, "evidence quote", 2_000);
    if (containsSecret(quote)) throw new Error("Memory evidence contains secret-like content.");
    return { messageId: id(e.messageId, "evidence messageId"), quote };
  });
  const links = Array.isArray(value.links) ? value.links.map((link) => id(link, "link")).filter((link) => !/[\\/]/u.test(link) && !link.startsWith(".")) : [];
  if (links.length > 16) throw new Error("Too many memory links.");
  return { kind: value.kind as MemoryKind, title, body, evidence, sourceKind: value.sourceKind as SourceKind, sensitive: value.sensitive === true, links, ...(typeof value.targetId === "string" ? { targetId: id(value.targetId, "targetId") } : {}), ...(typeof value.baseRevision === "number" ? { baseRevision: value.baseRevision } : {}) };
}

export function classifyCandidate(input: unknown): { status: "auto" | "review" | "rejected"; candidate?: MemoryCandidate; reason?: string } {
  try {
    const candidate = validateCandidate(input);
    if (candidate.sensitive) return { status: "rejected", reason: "sensitive" };
    if (candidate.sourceKind === "inference" || candidate.links.length === 0 && candidate.kind === "fact") return { status: "review", candidate, reason: candidate.sourceKind === "inference" ? "inference" : "unresolved" };
    return { status: "auto", candidate };
  } catch (error) { return { status: "rejected", reason: error instanceof Error ? error.message : "invalid" }; }
}
