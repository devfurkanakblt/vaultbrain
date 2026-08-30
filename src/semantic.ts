import { makeExcerpt } from "./markdown.js";
import type { NoteDocument, NoteSummary } from "./documents.js";

const DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_CHARACTERS = 16_000;
const DEFAULT_BATCH_SIZE = 16;
const MAX_RESPONSE_BYTES = 32 * 1024 * 1024;

export interface EmbeddingAdapter {
  /** Stable, non-secret description used only to identify an in-memory cache. */
  readonly id: string;
  embed(input: readonly string[]): Promise<readonly (readonly number[])[]>;
}

export interface LocalGenerationOptions {
  system?: string;
  /** Ollama format name or a JSON schema accepted by the configured model. */
  format?: "json" | Record<string, unknown>;
}

export interface LocalModelAdapter extends EmbeddingAdapter {
  generate(prompt: string, options?: LocalGenerationOptions): Promise<string>;
}

export interface OllamaLocalModelOptions {
  model: string;
  baseUrl?: string;
  timeoutMs?: number;
  dimensions?: number;
  keepAlive?: string | number;
  /** Test/host hook. The URL is still restricted to a literal loopback host. */
  fetch?: typeof globalThis.fetch;
}

export interface SemanticSearchOptions {
  limit?: number;
  minScore?: number;
  /** Bounds how much plaintext from each note is exposed to the local model. */
  maxCharacters?: number;
  batchSize?: number;
}

export interface SemanticSearchHit extends NoteSummary {
  /** Cosine similarity in the inclusive range [-1, 1]. */
  score: number;
  excerpt: string;
}

interface SemanticEntry {
  revision: number;
  maxCharacters: number;
  vector: Float32Array;
}

function positiveInteger(value: number, name: string, maximum: number): number {
  if (!Number.isInteger(value) || value < 1 || value > maximum) {
    throw new Error(`${name} must be an integer between 1 and ${maximum}.`);
  }
  return value;
}

function finiteNumber(value: number, name: string, minimum: number, maximum: number): number {
  if (!Number.isFinite(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be between ${minimum} and ${maximum}.`);
  }
  return value;
}

function loopbackBaseUrl(value: string): URL {
  const url = new URL(value);
  const host = url.hostname.toLocaleLowerCase("en-US");
  if (url.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]"].includes(host)) {
    throw new Error("Local-model URL must use HTTP with a literal loopback host (127.0.0.1, localhost, or [::1]).");
  }
  if (url.username || url.password) throw new Error("Local-model URL must not contain credentials.");
  url.search = "";
  url.hash = "";
  if (!url.pathname.endsWith("/")) url.pathname += "/";
  return url;
}

function modelName(value: string): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > 200 || /[\r\n\u0000]/u.test(normalized)) {
    throw new Error("Local-model name must contain 1 to 200 printable characters.");
  }
  return normalized;
}

async function responseJson(response: Response): Promise<unknown> {
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > MAX_RESPONSE_BYTES) {
    throw new Error("Local-model response exceeded 32 MiB.");
  }
  if (!response.ok) throw new Error(`Local model returned HTTP ${response.status}.`);
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error("Local model returned malformed JSON.");
  }
}

/**
 * Minimal Ollama adapter for zero-network model use. It deliberately accepts
 * only literal loopback URLs and refuses redirects, so note content cannot be
 * redirected to a remote origin by configuration or an HTTP response.
 */
export class OllamaLocalModelAdapter implements LocalModelAdapter {
  readonly id: string;
  private readonly model: string;
  private readonly baseUrl: URL;
  private readonly timeoutMs: number;
  private readonly dimensions?: number;
  private readonly keepAlive?: string | number;
  private readonly fetchImplementation: typeof globalThis.fetch;

  constructor(options: OllamaLocalModelOptions) {
    this.model = modelName(options.model);
    this.baseUrl = loopbackBaseUrl(options.baseUrl ?? DEFAULT_OLLAMA_URL);
    this.timeoutMs = positiveInteger(options.timeoutMs ?? DEFAULT_TIMEOUT_MS, "timeoutMs", 10 * 60_000);
    this.dimensions = options.dimensions === undefined
      ? undefined
      : positiveInteger(options.dimensions, "dimensions", 65_536);
    this.keepAlive = options.keepAlive;
    this.fetchImplementation = options.fetch ?? globalThis.fetch;
    if (!this.fetchImplementation) throw new Error("This runtime does not provide fetch().");
    this.id = `ollama:${this.baseUrl.origin}${this.baseUrl.pathname}:${this.model}:${this.dimensions ?? "native"}`;
  }

  private async post(endpoint: string, body: Record<string, unknown>): Promise<unknown> {
    const response = await this.fetchImplementation(new URL(endpoint, this.baseUrl), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      redirect: "error",
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    return responseJson(response);
  }

  async embed(input: readonly string[]): Promise<readonly (readonly number[])[]> {
    if (input.length === 0) return [];
    const payload = await this.post("api/embed", {
      model: this.model,
      input,
      truncate: true,
      ...(this.dimensions === undefined ? {} : { dimensions: this.dimensions }),
      ...(this.keepAlive === undefined ? {} : { keep_alive: this.keepAlive }),
    });
    if (!payload || typeof payload !== "object" || !Array.isArray((payload as { embeddings?: unknown }).embeddings)) {
      throw new Error("Local model returned an invalid embedding response.");
    }
    return (payload as { embeddings: unknown[] }).embeddings.map((vector) => {
      if (!Array.isArray(vector)) throw new Error("Local model returned an invalid embedding vector.");
      return vector.map((value) => {
        if (typeof value !== "number") throw new Error("Local model returned a non-numeric embedding value.");
        return value;
      });
    });
  }

  async generate(prompt: string, options: LocalGenerationOptions = {}): Promise<string> {
    if (!prompt.trim()) throw new Error("Local-model prompt cannot be empty.");
    const payload = await this.post("api/generate", {
      model: this.model,
      prompt,
      stream: false,
      ...(options.system === undefined ? {} : { system: options.system }),
      ...(options.format === undefined ? {} : { format: options.format }),
      ...(this.keepAlive === undefined ? {} : { keep_alive: this.keepAlive }),
    });
    const response = payload && typeof payload === "object" ? (payload as { response?: unknown }).response : undefined;
    if (typeof response !== "string") throw new Error("Local model returned an invalid generation response.");
    return response;
  }
}

function semanticText(note: NoteDocument, maxCharacters: number): string {
  const metadata = [
    `Title: ${note.title}`,
    `Path: ${note.path}`,
    note.aliases.length ? `Aliases: ${note.aliases.join(", ")}` : "",
    note.tags.length ? `Tags: ${note.tags.join(", ")}` : "",
    Object.keys(note.properties).length ? `Properties: ${JSON.stringify(note.properties)}` : "",
  ].filter(Boolean).join("\n");
  const prefix = `${metadata}\n\n`;
  return `${prefix}${note.body.slice(0, Math.max(0, maxCharacters - prefix.length))}`.slice(0, maxCharacters);
}

function normalizedVector(values: readonly number[], expectedDimensions?: number): Float32Array {
  if (values.length === 0) throw new Error("Local model returned an empty embedding vector.");
  if (expectedDimensions !== undefined && values.length !== expectedDimensions) {
    throw new Error(`Local model changed embedding dimensions from ${expectedDimensions} to ${values.length}.`);
  }
  let squaredMagnitude = 0;
  for (const value of values) {
    if (!Number.isFinite(value)) throw new Error("Local model returned a non-finite embedding value.");
    squaredMagnitude += value * value;
  }
  if (!Number.isFinite(squaredMagnitude) || squaredMagnitude <= 0) {
    throw new Error("Local model returned a zero-magnitude embedding vector.");
  }
  const magnitude = Math.sqrt(squaredMagnitude);
  return Float32Array.from(values, (value) => value / magnitude);
}

function dot(left: Float32Array, right: Float32Array): number {
  if (left.length !== right.length) throw new Error("Local model returned inconsistent embedding dimensions.");
  let score = 0;
  for (let index = 0; index < left.length; index += 1) score += left[index] * right[index];
  return Math.max(-1, Math.min(1, score));
}

/** In-memory, revision-aware semantic index. No vectors are persisted. */
export class SemanticNoteIndex {
  private readonly entries = new Map<string, SemanticEntry>();
  private dimensions?: number;

  clear(): void {
    for (const entry of this.entries.values()) entry.vector.fill(0);
    this.entries.clear();
    this.dimensions = undefined;
  }

  private async refresh(
    notes: readonly NoteDocument[],
    adapter: EmbeddingAdapter,
    maxCharacters: number,
    batchSize: number
  ): Promise<void> {
    const liveIds = new Set(notes.map((note) => note.id));
    for (const [id, entry] of this.entries) {
      if (!liveIds.has(id)) {
        entry.vector.fill(0);
        this.entries.delete(id);
      }
    }

    const stale = notes.filter((note) => {
      const cached = this.entries.get(note.id);
      return !cached || cached.revision !== note.revision || cached.maxCharacters !== maxCharacters;
    });
    for (let offset = 0; offset < stale.length; offset += batchSize) {
      const batch = stale.slice(offset, offset + batchSize);
      const vectors = await adapter.embed(batch.map((note) => semanticText(note, maxCharacters)));
      if (vectors.length !== batch.length) {
        throw new Error(`Local model returned ${vectors.length} embeddings for ${batch.length} inputs.`);
      }
      const batchDimensions = this.dimensions ?? vectors[0]?.length;
      const normalized = vectors.map((vector) => normalizedVector(vector, batchDimensions));
      this.dimensions ??= batchDimensions;
      for (let index = 0; index < batch.length; index += 1) {
        const note = batch[index];
        const previous = this.entries.get(note.id);
        previous?.vector.fill(0);
        this.entries.set(note.id, {
          revision: note.revision,
          maxCharacters,
          vector: normalized[index],
        });
      }
    }
  }

  async search(
    notes: readonly NoteDocument[],
    query: string,
    adapter: EmbeddingAdapter,
    options: SemanticSearchOptions = {}
  ): Promise<SemanticSearchHit[]> {
    const normalizedQuery = query.trim();
    if (!normalizedQuery) throw new Error("Semantic search query cannot be empty.");
    const limit = positiveInteger(options.limit ?? 20, "limit", 100);
    const minScore = finiteNumber(options.minScore ?? -1, "minScore", -1, 1);
    const maxCharacters = positiveInteger(
      options.maxCharacters ?? DEFAULT_MAX_CHARACTERS,
      "maxCharacters",
      1_000_000
    );
    const batchSize = positiveInteger(options.batchSize ?? DEFAULT_BATCH_SIZE, "batchSize", 64);

    await this.refresh(notes, adapter, maxCharacters, batchSize);
    const queryVectors = await adapter.embed([normalizedQuery]);
    if (queryVectors.length !== 1) throw new Error("Local model did not return one query embedding.");
    const queryVector = normalizedVector(queryVectors[0], this.dimensions);
    try {
      return notes
        .map((note) => ({ note, score: dot(this.entries.get(note.id)!.vector, queryVector) }))
        .filter(({ score }) => score >= minScore)
        .sort((left, right) => right.score - left.score || right.note.updatedAt.localeCompare(left.note.updatedAt))
        .slice(0, limit)
        .map(({ note, score }) => ({
          id: note.id,
          path: note.path,
          title: note.title,
          aliases: [...note.aliases],
          tags: [...note.tags],
          updatedAt: note.updatedAt,
          revision: note.revision,
          score,
          excerpt: makeExcerpt(note.body, normalizedQuery),
        }));
    } finally {
      queryVector.fill(0);
    }
  }
}
