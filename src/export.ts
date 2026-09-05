import fs from "node:fs";
import path from "node:path";
import { DEFAULT_ASSETS_DIR } from "./canvas.js";
import { DocumentVault } from "./documents.js";
import { writeFileAtomic } from "./fs-safe.js";

export type VaultExportIssueSeverity = "warning" | "error";

export interface VaultExportIssue {
  severity: VaultExportIssueSeverity;
  code: string;
  path: string;
  message: string;
  reference?: string;
}

export interface VaultExportReport {
  version: 1;
  source: string;
  destination: string;
  startedAt: string;
  completedAt: string;
  ok: boolean;
  notes: { total: number; written: number };
  canvases: { total: number; written: number };
  attachments: { total: number; written: number; bytes: number };
  issues: VaultExportIssue[];
}

export interface VaultExportOptions {
  /** Where attachments are written, relative to the export root. */
  assetsDir?: string;
}

/**
 * Names Windows refuses whatever the extension, so a note legitimately called
 * `aux.md` inside the vault cannot be written to disk under that name.
 */
const RESERVED_DEVICE_NAMES = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/iu;

/**
 * The vault's path rules are stricter than a filesystem's in some ways and
 * looser in others: `Q3: results.md` is a legal note path and an illegal
 * Windows filename. An export that crashed or silently dropped such a note
 * would be a worse answer than one that renames it and says so.
 */
function portableSegment(segment: string): string {
  let value = segment
    .replace(/[<>:"|?*\\/]/gu, "-")
    .replace(/[\u0000-\u001f\u007f]/gu, "-")
    .replace(/[ .]+$/u, "");
  if (!value) value = "_";
  if (RESERVED_DEVICE_NAMES.test(value)) value = `_${value}`;
  return value;
}

function splitExtension(name: string): { stem: string; extension: string } {
  const extension = path.posix.extname(name);
  return extension ? { stem: name.slice(0, -extension.length), extension } : { stem: name, extension: "" };
}

/**
 * Allocates one on-disk path per exported object.
 *
 * Two notes named `Recipe.md` and `recipe.md` coexist in the vault and cannot
 * coexist in an export on Windows or macOS. Comparing case-insensitively costs
 * a suffix on the second note; not comparing costs the second note entirely.
 */
class NameAllocator {
  private readonly used = new Set<string>();

  allocate(desired: string): { relative: string; adjusted: boolean } {
    const segments = desired.split("/");
    const sanitized = segments.map(portableSegment);
    const adjusted = sanitized.some((segment, index) => segment !== segments[index]);
    const directory = sanitized.slice(0, -1);
    const { stem, extension } = splitExtension(sanitized[sanitized.length - 1]);

    for (let attempt = 1; ; attempt += 1) {
      const basename = attempt === 1 ? `${stem}${extension}` : `${stem} (${attempt})${extension}`;
      const relative = [...directory, basename].join("/");
      const key = relative.normalize("NFKC").toLocaleLowerCase("en-US");
      if (!this.used.has(key)) {
        this.used.add(key);
        return { relative, adjusted: adjusted || attempt > 1 };
      }
    }
  }
}

function isInside(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

function assertEmptyDestination(destination: string): void {
  if (!fs.existsSync(destination)) return;
  const stat = fs.lstatSync(destination);
  if (stat.isSymbolicLink()) throw new Error("Refusing a symbolic link as the export destination.");
  if (!stat.isDirectory()) throw new Error(`The export destination is not a directory: ${destination}`);
  if (fs.readdirSync(destination).length > 0) {
    throw new Error(
      `The export destination is not empty: ${destination}. ` +
        "Choose a new directory rather than merging a plaintext export into existing files."
    );
  }
}

function issueFor(error: unknown, code: string, subject: string): VaultExportIssue {
  return {
    severity: "error",
    code,
    path: subject,
    message: error instanceof Error ? error.message : String(error),
  };
}

/**
 * Writes the whole vault out as plain Markdown, JSON Canvas and attachment
 * files - the same shape `importObsidianVault` reads, so export and import
 * describe one format rather than two.
 *
 * The result is plaintext. Everything the vault encrypts is readable by anyone
 * who can read the destination directory, which is the point of the command
 * and the reason it refuses a destination that already holds files.
 */
export function exportVault(
  vaultDir: string,
  destinationDirectory: string,
  passphrase: string,
  options: VaultExportOptions = {}
): VaultExportReport {
  const startedAt = new Date().toISOString();
  const source = path.resolve(vaultDir);
  const destination = path.resolve(destinationDirectory);
  const assetsDir = (options.assetsDir ?? DEFAULT_ASSETS_DIR).trim().replace(/\\/gu, "/");
  if (!assetsDir || assetsDir.split("/").some((part) => !part || part === "." || part === "..")) {
    throw new Error("The export assets directory must be a relative path label.");
  }
  if (isInside(source, destination) || isInside(destination, source)) {
    throw new Error("A plaintext export must be written outside the vault it exports.");
  }
  assertEmptyDestination(destination);

  const vault = new DocumentVault(source, passphrase);
  const issues: VaultExportIssue[] = [];
  const allocator = new NameAllocator();

  // Attachments first: canvases embed them by exported path, and a note's
  // `![[file.png]]` resolves on import by unique basename, so their names have
  // to be settled before anything references them.
  const attachments = vault.listAttachments();
  const attachmentNames = new Map<string, string[]>();
  const exportedAssetPaths = new Map<string, string>();
  let attachmentsWritten = 0;
  let attachmentBytes = 0;
  for (const info of attachments) {
    try {
      const { relative, adjusted } = allocator.allocate(`${assetsDir}/${info.filename}`);
      const { data } = vault.getAttachment(info.id);
      writeFileAtomic(path.join(destination, ...relative.split("/")), data);
      attachmentsWritten += 1;
      attachmentBytes += data.byteLength;
      exportedAssetPaths.set(info.id, relative);
      const basename = path.posix.basename(relative);
      attachmentNames.set(info.filename, [...(attachmentNames.get(info.filename) ?? []), basename]);
      if (adjusted) {
        issues.push({
          severity: "warning",
          code: "attachment-renamed",
          path: relative,
          reference: info.filename,
          message:
            `Attachment was written as '${basename}' because '${info.filename}' is not a portable ` +
            "filename or collides with another attachment.",
        });
      }
    } catch (error) {
      issues.push(issueFor(error, "attachment-export-failed", info.filename));
    }
  }
  for (const [filename, written] of attachmentNames) {
    if (written.length > 1) {
      issues.push({
        severity: "warning",
        code: "ambiguous-attachment-name",
        path: `${assetsDir}/${filename}`,
        reference: filename,
        message:
          `${written.length} attachments share the filename '${filename}'. An embed that names only the ` +
          "basename cannot say which one it meant, in this export or in the vault it came from.",
      });
    }
  }

  const notes = vault.list();
  let notesWritten = 0;
  for (const note of notes) {
    try {
      const { relative, adjusted } = allocator.allocate(note.path);
      writeFileAtomic(path.join(destination, ...relative.split("/")), vault.exportMarkdown(note.id));
      notesWritten += 1;
      if (adjusted) {
        issues.push({
          severity: "warning",
          code: "note-path-adjusted",
          path: relative,
          reference: note.path,
          message: `Note was written as '${relative}' because '${note.path}' is not a portable file path.`,
        });
      }
    } catch (error) {
      issues.push(issueFor(error, "note-export-failed", note.path));
    }
  }

  const canvases = vault.listCanvases();
  let canvasesWritten = 0;
  for (const canvas of canvases) {
    try {
      const { relative, adjusted } = allocator.allocate(canvas.path);
      writeFileAtomic(
        path.join(destination, ...relative.split("/")),
        vault.exportCanvas(canvas.id, assetsDir, exportedAssetPaths)
      );
      canvasesWritten += 1;
      if (adjusted) {
        issues.push({
          severity: "warning",
          code: "canvas-path-adjusted",
          path: relative,
          reference: canvas.path,
          message: `Canvas was written as '${relative}' because '${canvas.path}' is not a portable file path.`,
        });
      }
    } catch (error) {
      issues.push(issueFor(error, "canvas-export-failed", canvas.path));
    }
  }

  return {
    version: 1,
    source,
    destination,
    startedAt,
    completedAt: new Date().toISOString(),
    ok: !issues.some((issue) => issue.severity === "error"),
    notes: { total: notes.length, written: notesWritten },
    canvases: { total: canvases.length, written: canvasesWritten },
    attachments: { total: attachments.length, written: attachmentsWritten, bytes: attachmentBytes },
    issues,
  };
}
