import crypto from "node:crypto";
import { DocumentVault, type NoteDocument } from "../documents.js";
import { classifyCandidate, type MemoryCandidate, type MemorySummary } from "./protocol.js";

const MEMORY_ROOT = "Memory";

function safeSegment(value: string): string {
  const normalized = value.normalize("NFKC").trim().replace(/[^\p{L}\p{N}._ -]+/gu, "-").replace(/\s+/gu, "-").replace(/-+/gu, "-").replace(/^[.-]+|[.-]+$/gu, "");
  if (!normalized) throw new Error("Memory title cannot become a safe path.");
  return normalized.slice(0, 120);
}

function memoryPath(candidate: MemoryCandidate): string { return `${MEMORY_ROOT}/${candidate.kind}/${safeSegment(candidate.title)}.md`; }

export interface MemoryWriteResult { status: "stored" | "review" | "rejected"; note?: NoteDocument; reason?: string; }

/** A deliberately narrow facade: it can only create/search notes below Memory/. */
export class MemoryLedger {
  private readonly vault: DocumentVault;
  constructor(vaultDir: string, passphrase: string) { this.vault = new DocumentVault(vaultDir, passphrase); }
  remember(input: unknown): MemoryWriteResult {
    const decision = classifyCandidate(input);
    if (decision.status !== "auto") return { status: decision.status, reason: decision.reason };
    const candidate = decision.candidate!;
    const existing = this.vault.search(candidate.title, 10).find((hit) => hit.path === memoryPath(candidate));
    const note = this.vault.put({
      id: existing?.id,
      baseRevision: existing?.revision,
      path: memoryPath(candidate),
      title: candidate.title,
      body: candidate.body + `\n\n_Source: ${candidate.evidence.map((item) => item.messageId).join(", ")}_`,
      tags: ["memory", candidate.kind],
      properties: { memoryKind: candidate.kind, sourceKind: candidate.sourceKind, evidence: candidate.evidence.map((item) => item.messageId), links: candidate.links },
    });
    return { status: "stored", note };
  }
  search(query: string, limit = 20): MemorySummary[] {
    if (!query.trim()) throw new Error("Memory search query cannot be empty.");
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error("Memory search limit must be between 1 and 100.");
    return this.vault.search(query, limit * 2).filter((hit) => hit.path.startsWith(`${MEMORY_ROOT}/`)).slice(0, limit).map((hit) => ({ id: hit.id, title: hit.title, body: hit.excerpt, source: "vaultbrain-memory" }));
  }
  lock(): void { this.vault.lock(); }
}

export function memoryOperationId(sessionId: string, turnId: string): string { return crypto.createHash("sha256").update(`${sessionId}\0${turnId}`).digest("hex"); }

