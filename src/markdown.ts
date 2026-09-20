export interface WikiLink {
  raw: string;
  target: string;
  heading?: string;
  block?: string;
  alias?: string;
  embed: boolean;
}

export interface MarkdownHeading {
  level: number;
  text: string;
  slug: string;
}

export interface MarkdownAnalysis {
  links: WikiLink[];
  tags: string[];
  headings: MarkdownHeading[];
}

/**
 * The one wikilink grammar. `analyzeMarkdown` reads with it and
 * `rewriteWikiLinks` writes with it, so a link the index counted can never be
 * a link the exporter fails to recognize.
 */
const LINK_SOURCE = String.raw`(!)?\[\[([^\]|#^]+)(?:#([^\]|^]+))?(?:\^([^\]|]+))?(?:\|([^\]]+))?\]\]`;
/** Fenced blocks and inline spans, where a `[[...]]` is text and not a link. */
const CODE_SOURCE = "```[\\s\\S]*?```|~~~[\\s\\S]*?~~~|`[^`\\n]*`";

function withoutCode(markdown: string): string {
  return markdown.replace(new RegExp(CODE_SOURCE, "gu"), " ");
}

/** The source text for a link, with `target` swapped and everything else kept. */
export function formatWikiLink(link: WikiLink, target: string): string {
  const heading = link.heading ? `#${link.heading}` : "";
  const block = link.block ? `^${link.block}` : "";
  const alias = link.alias ? `|${link.alias}` : "";
  return `${link.embed ? "!" : ""}[[${target}${heading}${block}${alias}]]`;
}

/**
 * Rewrites link targets in place, leaving code spans and every link the
 * callback declines untouched.
 *
 * An export that renames a file has to rename the links pointing at it too, or
 * the exported vault is a set of notes with a broken web between them. The
 * callback returns the new target, or undefined to keep the link exactly as
 * the author wrote it.
 */
export function rewriteWikiLinks(
  markdown: string,
  rewrite: (link: WikiLink) => string | undefined,
): string {
  const pattern = new RegExp(`(${CODE_SOURCE})|${LINK_SOURCE}`, "gu");
  return markdown.replace(pattern, (raw: string, code: string | undefined, ...rest: unknown[]) => {
    if (code !== undefined) return raw;
    const [bang, target, heading, block, alias] = rest as Array<string | undefined>;
    const link: WikiLink = {
      raw,
      target: (target ?? "").trim(),
      heading: heading?.trim(),
      block: block?.trim(),
      alias: alias?.trim(),
      embed: Boolean(bang),
    };
    const replacement = rewrite(link);
    return replacement === undefined ? raw : formatWikiLink(link, replacement);
  });
}

/**
 * The one rule for every user-facing path label in the vault. Notes and
 * canvases differ only by extension, so they share this rather than drift:
 * a path is a mutable label, never identity, and it must never be able to
 * escape the logical tree it names.
 */
export function normalizeVaultPath(input: string, extension: string, kind: string): string {
  let value = input.trim().replace(/\\/gu, "/");
  if (!value) throw new Error(`Invalid ${kind.toLowerCase()} path.`);
  if (value.toLowerCase().endsWith(extension)) {
    value = `${value.slice(0, -extension.length)}${extension}`;
  } else {
    value += extension;
  }
  if (
    value === extension ||
    value.length > 512 ||
    value.startsWith("/") ||
    /^[a-z]:\//iu.test(value) ||
    value.includes("\0") ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new Error(`Invalid ${kind.toLowerCase()} path.`);
  }
  const parts = value.split("/");
  if (parts.some((part) => !part || part === "." || part === "..")) {
    throw new Error(`${kind} paths cannot contain empty, '.' or '..' segments.`);
  }
  return parts.join("/");
}

export function normalizeNotePath(input: string): string {
  return normalizeVaultPath(input, ".md", "Note");
}

export function normalizeLinkTarget(input: string): string {
  const target = input.trim().replace(/\\/gu, "/").replace(/\.md$/iu, "");
  return target.normalize("NFKC").toLocaleLowerCase("en-US");
}

function slugifyHeading(value: string): string {
  return value
    .trim()
    .normalize("NFKC")
    .toLocaleLowerCase("en-US")
    .replace(/[^\p{L}\p{N}\s-]/gu, "")
    .replace(/\s+/gu, "-")
    .replace(/-+/gu, "-");
}

export function analyzeMarkdown(markdown: string): MarkdownAnalysis {
  const visible = withoutCode(markdown);
  const links: WikiLink[] = [];
  const linkPattern = new RegExp(LINK_SOURCE, "gu");
  for (const match of visible.matchAll(linkPattern)) {
    links.push({
      raw: match[0],
      target: match[2].trim(),
      heading: match[3]?.trim(),
      block: match[4]?.trim(),
      alias: match[5]?.trim(),
      embed: Boolean(match[1]),
    });
  }

  const tags = new Set<string>();
  const tagPattern = /(^|\s)#([\p{L}\p{N}_-]+(?:\/[\p{L}\p{N}_-]+)*)/gmu;
  for (const match of visible.matchAll(tagPattern)) tags.add(match[2].normalize("NFKC"));

  const headings: MarkdownHeading[] = [];
  for (const line of visible.split(/\r?\n/gu)) {
    const match = /^(#{1,6})\s+(.+?)\s*#*$/u.exec(line);
    if (match) {
      headings.push({ level: match[1].length, text: match[2], slug: slugifyHeading(match[2]) });
    }
  }
  return { links, tags: [...tags].sort(), headings };
}

export function makeExcerpt(body: string, query: string, length = 180): string {
  const plain = withoutCode(body)
    .replace(/[#>*_~\[\]`]/gu, " ")
    .replace(/\s+/gu, " ")
    .trim();
  if (!plain) return "";
  const term = query.match(/[\p{L}\p{N}]{2,}/u)?.[0]?.toLocaleLowerCase("en-US") ?? "";
  const index = term ? plain.toLocaleLowerCase("en-US").indexOf(term) : 0;
  const start = Math.max(0, index - Math.floor(length / 3));
  const excerpt = plain.slice(start, start + length);
  return `${start > 0 ? "…" : ""}${excerpt}${start + length < plain.length ? "…" : ""}`;
}
