import { isMap, parseDocument, stringify } from "yaml";
import type { PropertyValue } from "./documents.js";

const MAX_FRONTMATTER_BYTES = 256 * 1024;
const DANGEROUS_KEYS = new Set(["__proto__", "prototype", "constructor"]);

export interface ParsedFrontmatter {
  attributes: Record<string, PropertyValue>;
  body: string;
  hasFrontmatter: boolean;
  /**
   * The YAML exactly as it was written, comments and all. Keeping it is what
   * lets an export put back the author's file rather than our idea of it.
   */
  source: string;
}

function toSafeValue(value: unknown, depth = 0): PropertyValue {
  if (depth > 8) throw new Error("Frontmatter nesting cannot exceed 8 levels.");
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Frontmatter numbers must be finite.");
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > 10_000) throw new Error("Frontmatter array is too large.");
    return value.map((item) => toSafeValue(item, depth + 1));
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length > 1_000) throw new Error("Frontmatter object is too large.");
    const safe: Record<string, PropertyValue> = {};
    for (const [key, item] of entries) {
      if (!key || key.length > 160 || DANGEROUS_KEYS.has(key) || /[\r\n\u0000]/u.test(key)) {
        throw new Error(`Unsafe frontmatter key: ${key}`);
      }
      safe[key] = toSafeValue(item, depth + 1);
    }
    return safe;
  }
  throw new Error(`Unsupported frontmatter value type: ${typeof value}`);
}

export function parseFrontmatter(markdown: string): ParsedFrontmatter {
  const normalized = markdown.startsWith("\uFEFF") ? markdown.slice(1) : markdown;
  if (!normalized.startsWith("---\n") && !normalized.startsWith("---\r\n")) {
    return { attributes: {}, body: normalized, hasFrontmatter: false, source: "" };
  }
  const lines = normalized.split(/\r?\n/gu);
  let closingLine = -1;
  for (let index = 1; index < lines.length; index += 1) {
    if (lines[index] === "---" || lines[index] === "...") {
      closingLine = index;
      break;
    }
  }
  if (closingLine < 0) throw new Error("Frontmatter starts with '---' but has no closing delimiter.");
  const source = lines.slice(1, closingLine).join("\n");
  if (Buffer.byteLength(source, "utf8") > MAX_FRONTMATTER_BYTES) {
    throw new Error("Frontmatter cannot exceed 256 KiB.");
  }

  const document = parseDocument(source, {
    schema: "core",
    merge: false,
    uniqueKeys: true,
    prettyErrors: true,
  });
  if (document.errors.length > 0) {
    throw new Error(`Invalid YAML frontmatter: ${document.errors.map((error) => error.message).join("; ")}`);
  }
  const parsed = document.toJS({ maxAliasCount: 0 });
  if (parsed === null || parsed === undefined) {
    return { attributes: {}, body: lines.slice(closingLine + 1).join("\n"), hasFrontmatter: true, source };
  }
  if (typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Frontmatter root must be a YAML mapping.");
  }
  return {
    attributes: toSafeValue(parsed) as Record<string, PropertyValue>,
    body: lines.slice(closingLine + 1).join("\n"),
    hasFrontmatter: true,
    source,
  };
}

export function stringifyFrontmatter(
  attributes: Record<string, PropertyValue>,
  body: string
): string {
  const safe = toSafeValue(attributes) as Record<string, PropertyValue>;
  const yaml = stringify(safe, {
    aliasDuplicateObjects: false,
    lineWidth: 0,
    schema: "core",
  }).trimEnd();
  return `---\n${yaml}\n---\n${body}`;
}

/**
 * Re-emits the author's own frontmatter with `attributes` applied to it.
 * Untouched entries keep their comments, key order, quoting and block style;
 * only the entries whose value actually changed are rewritten, and keys that
 * no longer exist are dropped.
 *
 * Round-tripping the source rather than re-serializing a plain object is the
 * difference between a vault that gives a file back and one that reformats it.
 */
export function applyFrontmatter(
  source: string,
  attributes: Record<string, PropertyValue>,
  body: string
): string {
  const safe = toSafeValue(attributes) as Record<string, PropertyValue>;
  const document = parseDocument(source, {
    schema: "core",
    merge: false,
    uniqueKeys: true,
    prettyErrors: true,
  });
  if (document.errors.length > 0 || !isMap(document.contents)) {
    return stringifyFrontmatter(safe, body);
  }

  const current = (document.toJS({ maxAliasCount: 0 }) ?? {}) as Record<string, unknown>;
  for (const item of [...document.contents.items]) {
    const key = String(item.key);
    if (!(key in safe)) document.delete(key);
  }
  for (const [key, value] of Object.entries(safe)) {
    if (!(key in current) || JSON.stringify(current[key]) !== JSON.stringify(value)) {
      document.set(key, value);
    }
  }

  const yaml = document.toString({ lineWidth: 0 }).trimEnd();
  return `---
${yaml}
---
${body}`;
}
