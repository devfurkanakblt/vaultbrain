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

function withoutCode(markdown: string): string {
  return markdown
    .replace(/```[\s\S]*?```/gu, " ")
    .replace(/~~~[\s\S]*?~~~/gu, " ")
    .replace(/`[^`\n]*`/gu, " ");
}

export function normalizeNotePath(input: string): string {
  let value = input.trim().replace(/\\/gu, "/");
  if (!value.toLowerCase().endsWith(".md")) value += ".md";
  if (
    !value ||
    value.length > 512 ||
    value.startsWith("/") ||
    /^[a-z]:\//iu.test(value) ||
    value.includes("\0") ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new Error("Invalid note path.");
  }
  const parts = value.split("/");
  if (parts.some((part) => !part || part === "." || part === "..")) {
    throw new Error("Note paths cannot contain empty, '.' or '..' segments.");
  }
  return parts.join("/");
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
  const linkPattern = /(!)?\[\[([^\]|#^]+)(?:#([^\]|^]+))?(?:\^([^\]|]+))?(?:\|([^\]]+))?\]\]/gu;
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
