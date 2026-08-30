import fs from "node:fs";
import path from "node:path";
import { listVaultFiles, loadVaultFile } from "./store.js";
import { assertNotSymlink, writeFileAtomic } from "./fs-safe.js";
import { resolveInside } from "./safety.js";

export interface SchemaEntry {
  key: string;
  desc: string;
}

export interface Schema {
  generatedAt: string;
  files: Record<string, SchemaEntry[]>;
}

const SCHEMA_FILENAME = "schema.json";

/**
 * Rebuilds schema.json: key names + descriptions only, values stripped.
 * This is the ONLY artifact meant to be read wholesale by an AI agent or
 * fed into an embedding index — it never contains a secret value.
 */
export function buildSchema(vaultDir: string, passphrase: string): Schema {
  const files = listVaultFiles(vaultDir);
  const schema: Schema = { generatedAt: new Date().toISOString(), files: {} };

  for (const name of files) {
    const entries = loadVaultFile(vaultDir, name, passphrase);
    schema.files[name] = entries.map((e) => ({ key: e.key, desc: e.desc }));
  }

  writeFileAtomic(
    resolveInside(vaultDir, SCHEMA_FILENAME),
    JSON.stringify(schema, null, 2),
    { mode: 0o600 }
  );
  return schema;
}

export function readSchema(vaultDir: string): Schema | null {
  const p = resolveInside(vaultDir, SCHEMA_FILENAME);
  if (!fs.existsSync(p)) return null;
  assertNotSymlink(p);
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

/** Very simple fuzzy match over key names + descriptions for MVP "fast find". */
export function searchSchema(schema: Schema, query: string): Array<{ file: string } & SchemaEntry> {
  const q = query.toLowerCase();
  const hits: Array<{ file: string } & SchemaEntry> = [];
  for (const [file, entries] of Object.entries(schema.files)) {
    for (const e of entries) {
      const hay = `${e.key} ${e.desc}`.toLowerCase();
      if (hay.includes(q) || q.split(/\s+/).every((tok) => hay.includes(tok))) {
        hits.push({ file, ...e });
      }
    }
  }
  return hits;
}

const NOTE_KEY_RE = /^NOTE_(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})_/;

function dateFromNoteKey(key: string): Date | null {
  const m = key.match(NOTE_KEY_RE);
  if (!m) return null;
  const [, y, mo, d, h, mi, s] = m;
  const parsed = new Date(Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s)));
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function parseBoundary(value: string | undefined, endOfDay: boolean): Date | null {
  if (!value) return null;
  const dateOnly = /^\d{4}-\d{2}-\d{2}$/.test(value);
  const parsed = new Date(dateOnly ? `${value}T${endOfDay ? "23:59:59.999" : "00:00:00.000"}Z` : value);
  if (Number.isNaN(parsed.getTime())) throw new Error(`Invalid ISO date: ${value}`);
  return parsed;
}

/**
 * Timeline browsing without decrypting anything: auto-generated note keys
 * carry their own timestamp, so date-range filtering runs entirely over
 * schema.json. This is the "daily notes" equivalent — recall by when,
 * not just by what — at zero exposure.
 */
export function filterNotesByDate(
  schema: Schema,
  opts: { file?: string; from?: string; to?: string }
): Array<{ file: string; createdAt: string } & SchemaEntry> {
  const from = parseBoundary(opts.from, false);
  const to = parseBoundary(opts.to, true);
  if (from && to && from > to) throw new Error("The 'from' date must not be after 'to'.");
  const hits: Array<{ file: string; createdAt: string } & SchemaEntry> = [];

  for (const [file, entries] of Object.entries(schema.files)) {
    if (opts.file && file !== opts.file) continue;
    for (const e of entries) {
      const d = dateFromNoteKey(e.key);
      if (!d) continue;
      if (from && d < from) continue;
      if (to && d > to) continue;
      hits.push({ file, createdAt: d.toISOString(), ...e });
    }
  }

  return hits.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}
