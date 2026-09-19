/**
 * The vault's search query language.
 *
 * It lives in its own module because it is a contract, not an implementation
 * detail: `docs/PRODUCT.md` promises prefix, phrase, boolean, tag, date and
 * property filters, and a parser that silently treats an unrecognized operator
 * as literal text does not refuse the query, it answers a different one. The
 * grammar is written once here, exercised by its own tests, and consumed by
 * the ranked search in `documents.ts`.
 *
 * Grammar, in the order a term is recognized:
 *
 *   "two words"            phrase, matched whole
 *   tag:name   tag:name*   tag, exact or by prefix; a leading '#' is optional
 *   path:part  path:part*  substring of the note's full path
 *   file:part  file:part*  substring of the note's basename
 *   [key]                  the note has this property
 *   [key:value]            the property holds this value
 *   created:2026-01-01     written on that UTC day
 *   created:A..B           written in that inclusive UTC range
 *   created:>=A created:<=B  open-ended bound
 *   updated:...            the same, on the modification time
 *   word                   appears in the note's text
 *   word*                  a word starting with this
 *   -<any of the above>    must NOT match
 *   A OR B                 alternatives; a note matching either is a hit
 *   A AND B                explicit AND, accepted for symmetry; adjacent terms
 *                          already combine this way
 *
 * `-` applies to every filter, not only to bare words: `-tag:red` excludes the
 * notes tagged `red` rather than searching for the literal text `tag:red`.
 */

export type QueryMatcher =
  | { kind: "text"; value: string; prefix: boolean }
  | { kind: "phrase"; value: string }
  | { kind: "tag"; value: string; prefix: boolean }
  | { kind: "path"; value: string; prefix: boolean }
  | { kind: "file"; value: string; prefix: boolean }
  | { kind: "property"; key: string; value?: string; prefix: boolean }
  | { kind: "date"; field: "created" | "updated"; from: number; to: number };

export interface QueryTerm {
  matcher: QueryMatcher;
  negated: boolean;
}

/** One alternative: every term in it has to hold. */
export interface QueryClause {
  terms: QueryTerm[];
}

export interface ParsedQuery {
  /** Alternatives. A note matches the query when it matches any one of them. */
  clauses: QueryClause[];
  /**
   * The positive free-text terms, in the order they were written, repeats
   * included. Ranking and the excerpt use these; filters do not contribute to
   * a score, because a filter is a yes-or-no question rather than a measure of
   * relevance.
   *
   * Repeats are kept deliberately: a term written twice has always counted
   * twice toward a note's score, and that is the ranking contract the search
   * oracle in `test/search-cache.test.mjs` checks. Changing how results are
   * ordered is a separate decision from fixing which results come back.
   */
  scoringTerms: string[];
}

/** The fields a note offers the matcher, all normalized the same way. */
export interface QueryFields {
  title: string;
  aliases: string[];
  tags: string[];
  path: string;
  basename: string;
  propertyKeys: string[];
  propertyPairs: string[];
  head: string;
  body: string;
  createdAt: number;
  updatedAt: number;
}

function normalize(value: string): string {
  return value.normalize("NFKC").toLocaleLowerCase("en-US");
}

/** Bounded like every other parsed input in this codebase. */
const MAX_TERMS = 64;
const MAX_TERM_LENGTH = 512;

const TOKEN = /-?\[[^\]]*\]|-?"[^"]*"|-?\S+/gu;

/**
 * A term ending in `*` matches at a word boundary rather than anywhere: a
 * prefix search for `appl*` is asking about words that start with "appl", and
 * a plain substring test would also answer "grapple". Compiled once per query
 * term, never per note.
 */
const prefixCache = new Map<string, RegExp>();

function prefixPattern(value: string): RegExp {
  let pattern = prefixCache.get(value);
  if (!pattern) {
    const escaped = value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
    pattern = new RegExp(`(?:^|[^\\p{L}\\p{N}])${escaped}`, "u");
    // The cache is per process and query terms repeat across searches; cap it
    // so a long session cannot grow it without limit.
    if (prefixCache.size >= 256) prefixCache.clear();
    prefixCache.set(value, pattern);
  }
  return pattern;
}

function matchesValue(haystack: string, value: string, prefix: boolean): boolean {
  return prefix ? prefixPattern(value).test(haystack) : haystack.includes(value);
}

function matchesAny(haystacks: readonly string[], value: string, prefix: boolean): boolean {
  for (let index = 0; index < haystacks.length; index++) {
    if (prefix ? haystacks[index].startsWith(value) : haystacks[index] === value) return true;
  }
  return false;
}

const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/u;

/** A day boundary in UTC, or NaN when the text is not a date this accepts. */
function boundary(value: string, endOfDay: boolean): number {
  if (!value) return Number.NaN;
  const text = DATE_ONLY.test(value)
    ? `${value}T${endOfDay ? "23:59:59.999" : "00:00:00.000"}Z`
    : value;
  return new Date(text).getTime();
}

function parseDate(field: "created" | "updated", raw: string): QueryMatcher | undefined {
  if (raw.startsWith(">=")) {
    const from = boundary(raw.slice(2), false);
    return Number.isNaN(from) ? undefined : { kind: "date", field, from, to: Number.POSITIVE_INFINITY };
  }
  if (raw.startsWith("<=")) {
    const to = boundary(raw.slice(2), true);
    return Number.isNaN(to) ? undefined : { kind: "date", field, from: Number.NEGATIVE_INFINITY, to };
  }
  const split = raw.indexOf("..");
  if (split >= 0) {
    const from = boundary(raw.slice(0, split), false);
    const to = boundary(raw.slice(split + 2), true);
    if (Number.isNaN(from) || Number.isNaN(to)) return undefined;
    return { kind: "date", field, from, to };
  }
  const from = boundary(raw, false);
  const to = boundary(raw, true);
  return Number.isNaN(from) ? undefined : { kind: "date", field, from, to };
}

/** Splits a trailing `*` off a filter value. */
function withPrefix(value: string): { value: string; prefix: boolean } {
  return value.endsWith("*") ? { value: value.slice(0, -1), prefix: true } : { value, prefix: false };
}

/**
 * Turns one token into a matcher.
 *
 * A token whose operator is recognized but whose argument is unusable — an
 * empty `tag:`, an unparseable date — falls back to plain text rather than
 * throwing. A search box should narrow as the user types, not error halfway
 * through a word.
 */
function parseMatcher(token: string): QueryMatcher | undefined {
  if (token.startsWith("[") && token.endsWith("]")) {
    const inner = normalize(token.slice(1, -1).trim());
    if (!inner) return undefined;
    const split = inner.indexOf(":");
    if (split < 0) return { kind: "property", key: inner, prefix: false };
    const key = inner.slice(0, split).trim();
    const { value, prefix } = withPrefix(inner.slice(split + 1).trim());
    if (!key) return undefined;
    return { kind: "property", key, value, prefix };
  }

  if (token.startsWith('"') && token.endsWith('"') && token.length >= 2) {
    const value = normalize(token.slice(1, -1).trim());
    return value ? { kind: "phrase", value } : undefined;
  }

  const split = token.indexOf(":");
  if (split > 0) {
    const field = normalize(token.slice(0, split));
    const raw = token.slice(split + 1).trim();
    if (raw) {
      if (field === "tag") {
        const { value, prefix } = withPrefix(normalize(raw).replace(/^#/u, ""));
        if (value) return { kind: "tag", value, prefix };
      }
      if (field === "path" || field === "file") {
        const { value, prefix } = withPrefix(normalize(raw));
        if (value) return { kind: field === "path" ? "path" : "file", value, prefix };
      }
      if (field === "created" || field === "updated" || field === "modified") {
        const parsed = parseDate(field === "modified" ? "updated" : field, raw);
        if (parsed) return parsed;
      }
    }
  }

  const { value, prefix } = withPrefix(normalize(token));
  return value ? { kind: "text", value, prefix } : undefined;
}

export function parseQuery(query: string): ParsedQuery {
  const tokens = query.slice(0, 4096).match(TOKEN) ?? [];
  const clauses: QueryClause[] = [];
  const scoringTerms: string[] = [];
  let current: QueryTerm[] = [];
  let parsed = 0;

  for (const token of tokens) {
    // `OR` and `AND` only act as operators when written on their own and in
    // capitals, so a note about the state of Oregon is still searchable.
    // `AND` is accepted for symmetry and reads better in a long query; terms
    // already combine with AND when nothing separates them.
    if (token === "OR") {
      clauses.push({ terms: current });
      current = [];
      continue;
    }
    if (token === "AND") continue;
    if (parsed >= MAX_TERMS || token.length > MAX_TERM_LENGTH) continue;
    const negated = token.startsWith("-") && token.length > 1;
    const matcher = parseMatcher(negated ? token.slice(1) : token);
    if (!matcher) continue;
    parsed += 1;
    current.push({ matcher, negated });
    if (!negated && (matcher.kind === "text" || matcher.kind === "phrase")) {
      scoringTerms.push(matcher.value);
    }
  }
  clauses.push({ terms: current });

  // An `OR` with nothing on one side is a typo, not an instruction to match
  // every note in the vault; an empty clause would do exactly that.
  const usable = clauses.filter((clause) => clause.terms.length > 0);
  return { clauses: usable.length ? usable : [{ terms: [] }], scoringTerms };
}

function matchesTerm(matcher: QueryMatcher, fields: QueryFields): boolean {
  switch (matcher.kind) {
    case "text":
      return (
        matchesValue(fields.head, matcher.value, matcher.prefix) ||
        matchesValue(fields.body, matcher.value, matcher.prefix)
      );
    case "phrase":
      return fields.head.includes(matcher.value) || fields.body.includes(matcher.value);
    case "tag":
      return matchesAny(fields.tags, matcher.value, matcher.prefix);
    case "path":
      return matchesValue(fields.path, matcher.value, matcher.prefix);
    case "file":
      return matchesValue(fields.basename, matcher.value, matcher.prefix);
    case "property":
      return matcher.value === undefined
        ? matchesAny(fields.propertyKeys, matcher.key, false)
        : matchesAny(fields.propertyPairs, `${matcher.key}:${matcher.value}`, matcher.prefix);
    case "date": {
      const at = matcher.field === "created" ? fields.createdAt : fields.updatedAt;
      return at >= matcher.from && at <= matcher.to;
    }
  }
}

/** True when the note satisfies at least one of the query's alternatives. */
export function matchesQuery(query: ParsedQuery, fields: QueryFields): boolean {
  for (let clauseIndex = 0; clauseIndex < query.clauses.length; clauseIndex++) {
    const terms = query.clauses[clauseIndex].terms;
    let satisfied = true;
    for (let termIndex = 0; termIndex < terms.length; termIndex++) {
      const term = terms[termIndex];
      if (matchesTerm(term.matcher, fields) === term.negated) {
        satisfied = false;
        break;
      }
    }
    if (satisfied) return true;
  }
  return false;
}
