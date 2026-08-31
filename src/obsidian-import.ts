import fs from "node:fs";
import path from "node:path";
import { parseJsonCanvas } from "./canvas.js";
import {
  DocumentVault,
  parseMarkdownNote,
  type NoteDocument,
  type NoteInput,
} from "./documents.js";
import { assertNoSymlinkComponents } from "./fs-safe.js";
import { normalizeLinkTarget, normalizeNotePath } from "./markdown.js";

export type ImportIssueSeverity = "warning" | "error";

export interface ObsidianImportIssue {
  severity: ImportIssueSeverity;
  code: string;
  path: string;
  message: string;
  reference?: string;
}

export interface ObsidianImportReport {
  version: 1;
  source: string;
  destination: string;
  startedAt: string;
  completedAt: string;
  ok: boolean;
  notes: { discovered: number; imported: number };
  canvases: { discovered: number; imported: number };
  attachments: { discovered: number; imported: number; unique: number };
  ignoredEntries: number;
  issues: ObsidianImportIssue[];
}

export interface ObsidianImportOptions {
  includeHidden?: boolean;
}

interface SourceFile {
  absolute: string;
  relative: string;
  size: number;
}

interface ScannedVault {
  markdown: SourceFile[];
  canvases: SourceFile[];
  attachments: SourceFile[];
  ignoredEntries: number;
  issues: ObsidianImportIssue[];
}

const MIME_TYPES: Record<string, string> = {
  ".avif": "image/avif",
  ".bmp": "image/bmp",
  ".csv": "text/csv",
  ".gif": "image/gif",
  ".jpeg": "image/jpeg",
  ".jpg": "image/jpeg",
  ".json": "application/json",
  ".mp3": "audio/mpeg",
  ".mp4": "video/mp4",
  ".ogg": "audio/ogg",
  ".pdf": "application/pdf",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".txt": "text/plain",
  ".wav": "audio/wav",
  ".webm": "video/webm",
  ".webp": "image/webp",
  ".zip": "application/zip",
};

function toPortablePath(value: string): string {
  return value.split(path.sep).join("/");
}

function normalizedSourcePath(value: string): string {
  return value
    .replace(/\\/gu, "/")
    .replace(/^\.\//u, "")
    .normalize("NFKC")
    .toLocaleLowerCase("en-US");
}

function isInside(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

function scanSource(root: string, includeHidden: boolean): ScannedVault {
  const result: ScannedVault = {
    markdown: [],
    canvases: [],
    attachments: [],
    ignoredEntries: 0,
    issues: [],
  };

  const visit = (directory: string): void => {
    assertNoSymlinkComponents(root, directory);
    const entries = fs.readdirSync(directory, { withFileTypes: true })
      .sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      const relative = toPortablePath(path.relative(root, absolute));
      const stat = fs.lstatSync(absolute);
      if (stat.isSymbolicLink()) {
        result.issues.push({
          severity: "error",
          code: "symbolic-link-skipped",
          path: relative,
          message: "Symbolic links are not followed during a vault import.",
        });
        continue;
      }
      if (!includeHidden && entry.name.startsWith(".")) {
        result.ignoredEntries += 1;
        continue;
      }
      if (stat.isDirectory()) {
        visit(absolute);
        continue;
      }
      if (!stat.isFile()) {
        result.ignoredEntries += 1;
        continue;
      }
      const source = { absolute, relative, size: stat.size };
      const extension = path.extname(entry.name).toLocaleLowerCase("en-US");
      if (extension === ".md") result.markdown.push(source);
      else if (extension === ".canvas") result.canvases.push(source);
      else result.attachments.push(source);
    }
  };

  visit(root);
  return result;
}

function issueFor(error: unknown, code: string, sourcePath: string): ObsidianImportIssue {
  return {
    severity: "error",
    code,
    path: sourcePath,
    message: error instanceof Error ? error.message : String(error),
  };
}

function validateNoteInput(input: NoteInput): void {
  const title = (input.title ?? path.posix.basename(input.path, ".md")).trim();
  if (!title || title.length > 300 || /[\r\n\u0000]/u.test(title)) {
    throw new Error("Invalid note title.");
  }
  if (Buffer.byteLength(input.body, "utf8") > 25 * 1024 * 1024) {
    throw new Error("A note body cannot exceed 25 MiB.");
  }
  for (const [label, values] of [["aliases", input.aliases], ["tags", input.tags]] as const) {
    if ((values?.length ?? 0) > 100) throw new Error(`A note cannot contain more than 100 ${label}.`);
    for (const value of values ?? []) {
      if (!value.trim() || value.length > 160 || /[\r\n\u0000]/u.test(value)) {
        throw new Error(`${label} must be non-empty single-line strings up to 160 characters.`);
      }
    }
  }
}

function decodeReference(value: string): string {
  const trimmed = value.trim().replace(/^<|>$/gu, "");
  try {
    return decodeURIComponent(trimmed);
  } catch {
    return trimmed;
  }
}

function isExternalReference(value: string): boolean {
  return !value || value.startsWith("#") || /^[a-z][a-z0-9+.-]*:/iu.test(value) || value.startsWith("//");
}

function withoutCode(markdown: string): string {
  return markdown
    .replace(/```[\s\S]*?```/gu, " ")
    .replace(/~~~[\s\S]*?~~~/gu, " ")
    .replace(/`[^`\n]*`/gu, " ");
}

function markdownReferences(markdown: string): Array<{ target: string; image: boolean }> {
  const references: Array<{ target: string; image: boolean }> = [];
  const pattern = /(!)?\[[^\]]*\]\((<[^>]+>|[^\s)]+)(?:\s+["'][^"']*["'])?\)/gu;
  for (const match of withoutCode(markdown).matchAll(pattern)) {
    references.push({ target: decodeReference(match[2]), image: Boolean(match[1]) });
  }
  return references;
}

function buildLookup(files: SourceFile[]): { paths: Set<string>; basenames: Map<string, string[]> } {
  const paths = new Set<string>();
  const basenames = new Map<string, string[]>();
  for (const file of files) {
    const normalized = normalizedSourcePath(file.relative);
    paths.add(normalized);
    const basename = normalizedSourcePath(path.posix.basename(file.relative));
    basenames.set(basename, [...(basenames.get(basename) ?? []), file.relative]);
  }
  return { paths, basenames };
}

function resolvesSourceReference(
  reference: string,
  sourceNotePath: string,
  lookup: ReturnType<typeof buildLookup>
): boolean {
  const clean = decodeReference(reference).split(/[?#]/u, 1)[0].replace(/^\//u, "");
  if (isExternalReference(clean)) return true;
  const noteDirectory = path.posix.dirname(sourceNotePath);
  const candidates = [
    normalizedSourcePath(clean),
    normalizedSourcePath(path.posix.normalize(path.posix.join(noteDirectory, clean))),
  ];
  if (candidates.some((candidate) => lookup.paths.has(candidate))) return true;
  const basename = normalizedSourcePath(path.posix.basename(clean));
  return (lookup.basenames.get(basename)?.length ?? 0) === 1;
}

function validateImportedReferences(
  vault: DocumentVault,
  notes: NoteDocument[],
  sourceNotes: SourceFile[],
  sourceAttachments: SourceFile[]
): ObsidianImportIssue[] {
  const issues: ObsidianImportIssue[] = [];
  const noteLookup = buildLookup(sourceNotes);
  const attachmentLookup = buildLookup(sourceAttachments);

  for (const [basename, matches] of attachmentLookup.basenames) {
    if (matches.length > 1) {
      issues.push({
        severity: "warning",
        code: "ambiguous-attachment-name",
        path: matches[0],
        reference: basename,
        message: `Attachment basename is ambiguous across ${matches.length} files: ${matches.join(", ")}`,
      });
    }
  }

  for (const note of notes) {
    const outgoing = vault.outgoing(note.id);
    for (const link of outgoing) {
      if (link.resolvedId) continue;
      if (link.embed && resolvesSourceReference(link.target, note.path, attachmentLookup)) continue;
      const extension = path.posix.extname(link.target).toLocaleLowerCase("en-US");
      const attachmentLike = link.embed && extension !== "" && extension !== ".md";
      issues.push({
        severity: "warning",
        code: attachmentLike ? "missing-attachment" : "unresolved-wikilink",
        path: note.path,
        reference: link.raw,
        message: attachmentLike
          ? `Embedded attachment does not exist in the source vault: ${link.target}`
          : `Wikilink does not resolve to an imported or existing note: ${link.target}`,
      });
    }

    for (const reference of markdownReferences(note.body)) {
      if (isExternalReference(reference.target)) continue;
      const extension = path.posix.extname(reference.target.split(/[?#]/u, 1)[0]).toLocaleLowerCase("en-US");
      const lookup = reference.image || (extension !== "" && extension !== ".md")
        ? attachmentLookup
        : noteLookup;
      if (resolvesSourceReference(reference.target, note.path, lookup)) continue;
      issues.push({
        severity: "warning",
        code: reference.image ? "missing-markdown-attachment" : "missing-markdown-link",
        path: note.path,
        reference: reference.target,
        message: `Local Markdown ${reference.image ? "attachment" : "link"} does not exist in the source vault.`,
      });
    }
  }
  return issues;
}

export function importObsidianVault(
  sourceDirectory: string,
  destinationDirectory: string,
  passphrase: string,
  options: ObsidianImportOptions = {}
): ObsidianImportReport {
  const startedAt = new Date().toISOString();
  const source = path.resolve(sourceDirectory);
  const destination = path.resolve(destinationDirectory);
  if (!fs.existsSync(source) || !fs.lstatSync(source).isDirectory()) {
    throw new Error(`Obsidian vault directory not found: ${source}`);
  }
  if (fs.lstatSync(source).isSymbolicLink()) {
    throw new Error("Refusing a symbolic link as the Obsidian vault root.");
  }
  if (isInside(source, destination)) {
    throw new Error("The encrypted destination vault must be outside the source Obsidian vault.");
  }

  const scanned = scanSource(source, options.includeHidden ?? false);
  const vault = new DocumentVault(destination, passphrase);
  const issues = [...scanned.issues];
  const noteInputs: NoteInput[] = [];
  const validNoteSources: SourceFile[] = [];
  const existingByPath = new Map(
    vault.list().map((note) => [normalizeLinkTarget(note.path), note.id])
  );
  const seenPaths = new Set<string>();
  const seenIds = new Set<string>();
  for (const file of scanned.markdown) {
    try {
      if (file.size > 26 * 1024 * 1024) {
        throw new Error("A Markdown source cannot exceed the note and frontmatter size limits.");
      }
      const input = parseMarkdownNote(normalizeNotePath(file.relative), fs.readFileSync(file.absolute, "utf8"));
      validateNoteInput(input);
      const pathKey = normalizeLinkTarget(input.path);
      if (seenPaths.has(pathKey)) throw new Error(`Two source notes normalize to the same path: ${input.path}`);
      if (input.id && seenIds.has(input.id)) throw new Error(`Duplicate portable note ID: ${input.id}`);
      const existingId = existingByPath.get(pathKey);
      if (existingId && input.id && existingId !== input.id) {
        throw new Error(`The destination path already belongs to another note: ${input.path}`);
      }
      seenPaths.add(pathKey);
      if (input.id) seenIds.add(input.id);
      noteInputs.push(input);
      validNoteSources.push(file);
    } catch (error) {
      issues.push(issueFor(error, "note-import-failed", file.relative));
    }
  }

  let importedNotes: NoteDocument[] = [];
  if (noteInputs.length > 0) {
    try {
      importedNotes = vault.putMany(noteInputs);
    } catch (error) {
      issues.push(issueFor(error, "note-batch-failed", "<notes>"));
    }
  }

  let attachmentImports = 0;
  const uniqueAttachmentIds = new Set<string>();
  const validAttachmentSources: SourceFile[] = [];
  for (const file of scanned.attachments) {
    try {
      if (file.size === 0 || file.size > 250 * 1024 * 1024) {
        throw new Error("Attachments must be between 1 byte and 250 MiB.");
      }
      const mime = MIME_TYPES[path.extname(file.relative).toLocaleLowerCase("en-US")] ?? "application/octet-stream";
      const attachment = vault.putAttachment(fs.readFileSync(file.absolute), path.posix.basename(file.relative), mime);
      attachmentImports += 1;
      uniqueAttachmentIds.add(attachment.id);
      validAttachmentSources.push(file);
    } catch (error) {
      issues.push(issueFor(error, "attachment-import-failed", file.relative));
    }
  }

  let canvasImports = 0;
  for (const file of scanned.canvases) {
    try {
      if (file.size > 8 * 1024 * 1024) throw new Error("A canvas cannot exceed 8 MiB serialized.");
      const text = fs.readFileSync(file.absolute, "utf8");
      parseJsonCanvas(text);
      vault.importCanvas(file.relative, text);
      canvasImports += 1;
    } catch (error) {
      issues.push(issueFor(error, "canvas-import-failed", file.relative));
    }
  }

  if (importedNotes.length > 0) {
    issues.push(...validateImportedReferences(
      vault,
      importedNotes,
      validNoteSources,
      validAttachmentSources
    ));
  }

  return {
    version: 1,
    source,
    destination,
    startedAt,
    completedAt: new Date().toISOString(),
    ok: !issues.some((issue) => issue.severity === "error"),
    notes: { discovered: scanned.markdown.length, imported: importedNotes.length },
    canvases: { discovered: scanned.canvases.length, imported: canvasImports },
    attachments: {
      discovered: scanned.attachments.length,
      imported: attachmentImports,
      unique: uniqueAttachmentIds.size,
    },
    ignoredEntries: scanned.ignoredEntries,
    issues,
  };
}
