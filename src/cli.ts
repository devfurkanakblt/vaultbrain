#!/usr/bin/env node
import { Command } from "commander";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  DEFAULT_VAULT_DIR,
  listVaultFiles,
  loadVaultFile,
  storeNote,
  upsertEntry,
  vaultFileEnvelopeVersion,
} from "./store.js";
import { buildSchema, readSchema, searchSchema, filterNotesByDate } from "./schema.js";
import { appendAudit, readAudit, verifyAudit } from "./audit.js";
import { getPassphrase, readSecret } from "./passphrase.js";
import {
  forgetPassphrase,
  keychain,
  recallPassphrase,
  rememberPassphrase,
  updateRememberedPassphrase,
} from "./keychain.js";
import { startMcpServer } from "./mcp-server.js";
import { migrateToKeyring } from "./keyring-migrate.js";
import { changeVaultPassphrase, MIN_PASSPHRASE_LENGTH } from "./keyring-passphrase.js";
import { MALFORMED_JOURNAL_MESSAGE, journalPath, rekeyVault, stagingRoot } from "./keyring-rekey.js";
import { detectVaultFormat } from "./keyring.js";
import {
  addGrant,
  approveRequest,
  denyRequest,
  grantsExist,
  listGrants,
  normalizeScope,
  pendingRequests,
  revokeGrant,
  type GrantAction,
  type GrantScope,
} from "./grants.js";
import { isRedactionLevel, REDACTION_LEVELS, type RedactionLevel } from "./redaction.js";
import { describeCapabilities, parsePluginManifest, type PluginCapability } from "./plugins.js";
import { generatePluginSigningKey, signPluginPackage } from "./plugin-signatures.js";
import { DocumentVault, type PropertyValue } from "./documents.js";
import { OllamaLocalModelAdapter } from "./semantic.js";
import { importObsidianVault } from "./obsidian-import.js";
import { writeFileAtomic } from "./fs-safe.js";
import {
  SyncChangeLog,
  SyncedDocumentVault,
  type EncryptedSyncChange,
  type SyncJson,
  type SyncMutation,
  type SyncObjectType,
  type SyncOperation,
} from "./sync.js";
import { createFromTemplate, openDailyNote, parseLocalDate, type TemplateVariables } from "./templates.js";

const program = new Command();

function openDocumentVault(vaultDir: string, passphrase: string): DocumentVault {
  const deviceId = program.opts().syncDevice as string | undefined;
  return deviceId ? new SyncedDocumentVault(vaultDir, passphrase, deviceId) : new DocumentVault(vaultDir, passphrase);
}

program
  .name("vbrain")
  .description("Vault Brain — an .env-style, least-exposure personal data store for the AI age.")
  .option("--vault <dir>", "vault directory", DEFAULT_VAULT_DIR)
  .option("--sync-device <uuid>", "automatically capture document writes for this sync device");

/**
 * The one place every command passes through before its own action runs, so
 * this is the one place the re-key journal is checked — not sprinkled across
 * each command that happens to open the vault.
 *
 * A journal on disk means an earlier `vbrain rekey` crashed somewhere between
 * staging and finishing the install: the keyring may already name a keyset
 * some live objects are not yet sealed under, or the reverse. Nothing but
 * `recoverRekey` — which only `rekeyVault` ever calls — may touch that state,
 * so any other command must refuse outright rather than decrypt (or write)
 * against a vault that might be mid-transition. `rekey` itself is exempt: it
 * is the command that finishes or rolls the interruption back, and `init`
 * needs no vault to exist yet. `lock` is exempt too: it only forgets a
 * remembered passphrase in the OS credential store and never touches the
 * vault directory, so an operator racing a leaked passphrase can still purge
 * it immediately instead of being forced through journal recovery first.
 * `keychain-status` is exempt as well: it only reads `detectVaultFormat` and
 * envelope versions and never decrypts anything.
 */
program.hook("preAction", (_thisCommand, actionCommand) => {
  const name = actionCommand.name();
  if (name === "rekey" || name === "init" || name === "lock" || name === "keychain-status") return;
  const dir = program.opts().vault as string;
  if (fs.existsSync(journalPath(dir))) {
    throw new Error(
      `An interrupted re-key is still journaled for ${dir}. ` +
        "Run 'vbrain rekey' to finish or roll it back before running any other command against this vault.",
    );
  }
});

program
  .command("init")
  .description("create an empty vault directory")
  .action(async () => {
    const dir = program.opts().vault;
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    console.log(`Vault initialized at ${dir}`);
    console.log(`Set VBRAIN_PASSPHRASE before running add/get/index/mcp.`);
  });

program
  .command("add <file> <keyval>")
  .description('add or update a key, e.g. vbrain add health DOCTOR_NEXT_APPOINTMENT="2026-09-15"')
  .requiredOption("--desc <description>", "short, NON-sensitive description of what this key holds")
  .action(async (file, keyval, opts) => {
    const eq = keyval.indexOf("=");
    if (eq === -1) {
      console.error('Expected KEY="value" format.');
      process.exit(1);
    }
    const key = keyval.slice(0, eq).trim();
    let value = keyval.slice(eq + 1).trim();
    if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);

    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    upsertEntry(dir, file, key, value, opts.desc, passphrase);
    appendAudit(dir, { actor: "cli-direct-write", file, key }, passphrase);
    buildSchema(dir, passphrase);
    console.log(`Stored ${key} in ${file}.kv.enc (encrypted).`);
    console.log(`Safe, value-free schema refreshed.`);
  });

program
  .command("note <category> <text>")
  .description(
    "dev/testing helper for the freeform journal path (Mode 2's real entry point is the MCP store_note tool, not this)",
  )
  .requiredOption("--desc <description>", "short, NON-sensitive tag for this note")
  .action(async (category, text, opts) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const key = storeNote(dir, category, text, opts.desc, passphrase);
    appendAudit(dir, { actor: "cli-direct-write", file: category, key }, passphrase);
    buildSchema(dir, passphrase);
    console.log(`Stored note under ${category}.${key} (encrypted, indexed).`);
  });

program
  .command("timeline")
  .description("browse journal notes by date range — safe index only, no decryption")
  .option("--category <file>", "limit to one category")
  .option("--from <iso-date>", "inclusive lower bound")
  .option("--to <iso-date>", "inclusive upper bound")
  .action((opts) => {
    const dir = program.opts().vault;
    const schema = readSchema(dir);
    if (!schema) {
      console.log("No schema.json yet — run 'vbrain index' first.");
      return;
    }
    const hits = filterNotesByDate(schema, { file: opts.category, from: opts.from, to: opts.to });
    if (hits.length === 0) {
      console.log("No notes in range.");
      return;
    }
    for (const h of hits) console.log(`${h.createdAt}  [${h.file}]  ${h.desc}  (${h.key})`);
  });

program
  .command("get <file> <key>")
  .description("MODE 1 — direct: decrypt and print a value straight to stdout. No AI involved, ever.")
  .action(async (file, key) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const entries = loadVaultFile(dir, file, passphrase);
    const entry = entries.find((e) => e.key === key);
    if (!entry) {
      console.error(`Key not found: ${key} in ${file}`);
      process.exit(1);
    }
    appendAudit(dir, { actor: "cli-direct", file, key }, passphrase);
    // Print ONLY the raw value — nothing else — so this is safe to pipe.
    process.stdout.write(entry.value + "\n");
  });

program
  .command("list")
  .description("show all key names + descriptions (no values) — safe to read directly")
  .action(() => {
    const dir = program.opts().vault;
    const schema = readSchema(dir);
    if (!schema) {
      console.log("No schema.json yet — run 'vbrain index' first.");
      return;
    }
    for (const [file, entries] of Object.entries(schema.files)) {
      console.log(`\n${file}.kv.enc`);
      for (const e of entries) console.log(`  ${e.key}  — ${e.desc}`);
    }
  });

program
  .command("search <query>")
  .description("fuzzy-search key names + descriptions (fast path, no decryption needed)")
  .action((query) => {
    const dir = program.opts().vault;
    const schema = readSchema(dir);
    if (!schema) {
      console.log("No schema.json yet — run 'vbrain index' first.");
      return;
    }
    const hits = searchSchema(schema, query);
    if (hits.length === 0) {
      console.log("No matches.");
      return;
    }
    for (const h of hits) console.log(`${h.file}.${h.key}  — ${h.desc}`);
  });

program
  .command("index")
  .description("rebuild schema.json (key names + descriptions only, zero secret values) across the vault")
  .action(async () => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const schema = buildSchema(dir, passphrase);
    const total = Object.values(schema.files).reduce((n, arr) => n + arr.length, 0);
    console.log(`Indexed ${total} keys across ${listVaultFiles(dir).length} files -> ${dir}/schema.json`);
  });

const docs = program.command("docs").description("encrypted Markdown documents, search and knowledge links");

docs
  .command("put <path>")
  .description("create or update an encrypted Markdown note")
  .requiredOption("--body <markdown>", "Markdown body")
  .option("--title <title>", "display title (defaults to filename)")
  .option("--tag <tags...>", "one or more tags")
  .option("--alias <aliases...>", "one or more aliases")
  .option("--properties <json>", "JSON object containing typed properties")
  .action(async (notePath, opts) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    let properties: Record<string, PropertyValue> = {};
    if (opts.properties) {
      const parsed: unknown = JSON.parse(opts.properties);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("--properties must be a JSON object.");
      }
      properties = parsed as Record<string, PropertyValue>;
    }
    const note = openDocumentVault(dir, passphrase).put({
      path: notePath,
      title: opts.title,
      body: opts.body,
      tags: opts.tag,
      aliases: opts.alias,
      properties,
    });
    appendAudit(dir, { actor: "cli-direct-write", file: "documents", key: note.id }, passphrase);
    console.log(`Stored ${note.path} (${note.id}, revision ${note.revision}).`);
  });

docs
  .command("get <reference>")
  .description("decrypt one Markdown note by ID, path, title or unique alias")
  .option("--with-frontmatter", "emit portable Markdown with JSON-compatible YAML frontmatter")
  .action(async (reference, opts) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const vault = new DocumentVault(dir, passphrase);
    const note = vault.get(reference);
    appendAudit(dir, { actor: "cli-direct", file: "documents", key: note.id }, passphrase);
    process.stdout.write((opts.withFrontmatter ? vault.exportMarkdown(note.id) : note.body) + "\n");
  });

docs
  .command("list")
  .description("list encrypted document metadata after unlocking the vault")
  .action(async () => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const vault = new DocumentVault(program.opts().vault, passphrase);
    for (const note of vault.list()) {
      console.log(`${note.path}  — ${note.title}  (${note.id}, r${note.revision})`);
    }
  });

docs
  .command("search <query>")
  .description("search the encrypted in-memory document index")
  .option("--limit <number>", "maximum result count", "20")
  .action(async (query, opts) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const vault = new DocumentVault(program.opts().vault, passphrase);
    const hits = vault.search(query, Number.parseInt(opts.limit, 10));
    for (const hit of hits) {
      console.log(`${hit.score.toFixed(0).padStart(3)}  ${hit.path}  — ${hit.title}`);
      if (hit.excerpt) console.log(`     ${hit.excerpt}`);
    }
  });

docs
  .command("semantic-search <query>")
  .description("opt in to semantic recall through a loopback-only Ollama model")
  .option("--model <name>", "local Ollama embedding model", "nomic-embed-text")
  .option("--url <url>", "loopback Ollama base URL", "http://127.0.0.1:11434")
  .option("--limit <number>", "maximum result count", "20")
  .option("--min-score <number>", "minimum cosine similarity (-1 to 1)", "0")
  .option("--max-characters <number>", "maximum plaintext characters sent per note", "16000")
  .action(async (query, opts) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const vault = new DocumentVault(dir, passphrase);
    const adapter = new OllamaLocalModelAdapter({ model: opts.model, baseUrl: opts.url });
    const hits = await vault.semanticSearch(query, adapter, {
      limit: Number.parseInt(opts.limit, 10),
      minScore: Number.parseFloat(opts.minScore),
      maxCharacters: Number.parseInt(opts.maxCharacters, 10),
    });
    appendAudit(dir, { actor: "cli-direct", file: "documents", key: "semantic-search" }, passphrase);
    for (const hit of hits) {
      console.log(`${hit.score.toFixed(3).padStart(6)}  ${hit.path}  — ${hit.title}`);
      if (hit.excerpt) console.log(`        ${hit.excerpt}`);
    }
  });

docs
  .command("links <reference>")
  .description("show outgoing wikilinks and whether they resolve")
  .action(async (reference) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const vault = new DocumentVault(program.opts().vault, passphrase);
    for (const link of vault.outgoing(reference)) {
      console.log(`${link.target}  ->  ${link.resolvedPath ?? "UNRESOLVED"}`);
    }
  });

docs
  .command("backlinks <reference>")
  .description("show notes linking to the selected note")
  .action(async (reference) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const vault = new DocumentVault(program.opts().vault, passphrase);
    for (const note of vault.backlinks(reference)) console.log(`${note.path}  — ${note.title}`);
  });

docs
  .command("unresolved")
  .description("show unresolved wikilinks from the encrypted link index")
  .action(async () => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const vault = new DocumentVault(program.opts().vault, passphrase);
    for (const item of vault.unresolvedLinks()) {
      for (const link of item.links) console.log(`${item.source.path}  ->  ${link.target}`);
    }
  });

docs
  .command("rename <reference> <new-path>")
  .description("rename/move a note without changing its stable ID")
  .option("--title <title>", "optionally change the display title")
  .action(async (reference, newPath, opts) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const note = openDocumentVault(dir, passphrase).rename(reference, newPath, opts.title);
    appendAudit(dir, { actor: "cli-direct-write", file: "documents", key: note.id }, passphrase);
    console.log(`Renamed to ${note.path} (${note.id}, revision ${note.revision}).`);
  });

docs
  .command("history <reference>")
  .description("list encrypted revisions for an active or deleted note ID")
  .action(async (reference) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const vault = new DocumentVault(program.opts().vault, passphrase);
    for (const revision of vault.revisions(reference)) {
      console.log(`r${revision.revision}  ${revision.updatedAt}${revision.current ? "  CURRENT" : ""}`);
    }
  });

docs
  .command("revision <reference> <number>")
  .description("decrypt and print one historical Markdown revision")
  .action(async (reference, number) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const note = new DocumentVault(dir, passphrase).getRevision(reference, Number.parseInt(number, 10));
    appendAudit(dir, { actor: "cli-direct", file: "documents", key: note.id }, passphrase);
    process.stdout.write(note.body + "\n");
  });

docs
  .command("restore <reference> <number>")
  .description("restore a historical revision as a new current revision")
  .action(async (reference, number) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const note = openDocumentVault(dir, passphrase).restore(reference, Number.parseInt(number, 10));
    appendAudit(dir, { actor: "cli-direct-write", file: "documents", key: note.id }, passphrase);
    console.log(`Restored ${note.path} as revision ${note.revision}.`);
  });

docs
  .command("import <path> <source>")
  .description("import a Markdown file into encrypted document storage")
  .action(async (notePath, source) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const note = openDocumentVault(dir, passphrase).importMarkdown(notePath, fs.readFileSync(source, "utf8"));
    appendAudit(dir, { actor: "cli-direct-write", file: "documents", key: note.id }, passphrase);
    console.log(`Imported ${note.path} (${note.id}).`);
  });

docs
  .command("import-obsidian <source-directory>")
  .description("import an Obsidian vault and validate its note, attachment and canvas references")
  .option("--report <file>", "write the complete integrity report as JSON")
  .option("--include-hidden", "include hidden files and directories (the default skips .obsidian, .git and peers)")
  .action(async (sourceDirectory, opts) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const report = importObsidianVault(sourceDirectory, dir, passphrase, {
      includeHidden: Boolean(opts.includeHidden),
    });
    appendAudit(
      dir,
      {
        actor: "cli-direct-write",
        file: "documents",
        key: `obsidian-import:${report.notes.imported}:${report.attachments.imported}:${report.canvases.imported}`,
      },
      passphrase,
    );
    if (opts.report) {
      writeFileAtomic(path.resolve(opts.report), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
    }

    console.log(`Imported ${report.notes.imported}/${report.notes.discovered} Markdown notes.`);
    console.log(
      `Imported ${report.attachments.imported}/${report.attachments.discovered} attachments ` +
        `(${report.attachments.unique} unique encrypted objects).`,
    );
    console.log(`Imported ${report.canvases.imported}/${report.canvases.discovered} canvases.`);
    const errors = report.issues.filter((issue) => issue.severity === "error");
    const warnings = report.issues.filter((issue) => issue.severity === "warning");
    console.log(`Integrity report: ${errors.length} error(s), ${warnings.length} warning(s).`);
    for (const issue of report.issues.slice(0, 20)) {
      console.log(`  ${issue.severity.toUpperCase()} [${issue.code}] ${issue.path}: ${issue.message}`);
    }
    if (report.issues.length > 20) {
      console.log(`  ... ${report.issues.length - 20} more issue(s); use --report <file> for the complete report.`);
    }
    if (opts.report) console.log(`Full report written to ${path.resolve(opts.report)}.`);
    if (!report.ok) process.exitCode = 2;
  });

docs
  .command("rebuild-index")
  .description("rebuild the encrypted search/link index from encrypted note objects")
  .action(async () => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const vault = new DocumentVault(program.opts().vault, passphrase);
    const count = Object.keys(vault.rebuildIndex().notes).length;
    console.log(`Rebuilt encrypted document index for ${count} notes.`);
  });

docs
  .command("remove <reference>")
  .description("delete one encrypted note")
  .action(async (reference) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const removed = openDocumentVault(dir, passphrase).remove(reference);
    appendAudit(dir, { actor: "cli-direct-write", file: "documents", key: removed.id }, passphrase);
    console.log(`Removed ${removed.path} (${removed.id}).`);
  });

docs
  .command("attach <source>")
  .description("store a file as a chunked encrypted attachment")
  .option("--name <filename>", "portable filename (defaults to source basename)")
  .option("--mime <type>", "MIME type", "application/octet-stream")
  .action(async (source, opts) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const info = openDocumentVault(dir, passphrase).putAttachment(
      fs.readFileSync(source),
      opts.name ?? path.basename(source),
      opts.mime,
    );
    appendAudit(dir, { actor: "cli-direct-write", file: "attachments", key: info.id }, passphrase);
    console.log(`Stored ${info.filename} (${info.id}, ${info.size} bytes, ${info.chunks} chunks).`);
  });

docs
  .command("attachments")
  .description("list encrypted attachment metadata after unlocking")
  .action(async () => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const vault = new DocumentVault(program.opts().vault, passphrase);
    for (const info of vault.listAttachments()) {
      console.log(`${info.id}  ${info.size} bytes  ${info.mime}  ${info.filename}`);
    }
  });

docs
  .command("attachment-get <id> <destination>")
  .description("decrypt one attachment to an explicit destination")
  .action(async (id, destination) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const attachment = new DocumentVault(dir, passphrase).getAttachment(id);
    writeFileAtomic(path.resolve(destination), attachment.data, { mode: 0o600 });
    appendAudit(dir, { actor: "cli-direct", file: "attachments", key: id }, passphrase);
    console.log(`Wrote ${attachment.info.filename} to ${path.resolve(destination)}.`);
  });

docs
  .command("attachment-remove <id>")
  .description("remove one encrypted attachment")
  .action(async (id) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const info = openDocumentVault(dir, passphrase).removeAttachment(id);
    appendAudit(dir, { actor: "cli-direct-write", file: "attachments", key: id }, passphrase);
    console.log(`Removed ${info.filename} (${id}).`);
  });

docs
  .command("canvas-import <path> <source.canvas>")
  .description("import a JSON Canvas file into encrypted canvas storage")
  .action(async (canvasPath, source) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const canvas = openDocumentVault(dir, passphrase).importCanvas(canvasPath, fs.readFileSync(source, "utf8"));
    appendAudit(dir, { actor: "cli-direct-write", file: "canvases", key: canvas.id }, passphrase);
    console.log(`Imported ${canvas.path} (${canvas.id}, revision ${canvas.revision}).`);
  });

docs
  .command("canvases")
  .description("list encrypted canvas metadata after unlocking")
  .action(async () => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const vault = new DocumentVault(program.opts().vault, passphrase);
    for (const canvas of vault.listCanvases()) {
      console.log(
        `${canvas.path}  — ${canvas.title}  (${canvas.id}, r${canvas.revision}, ${canvas.nodeCount} nodes, ${canvas.edgeCount} edges)`,
      );
    }
  });

docs
  .command("canvas-get <reference>")
  .description("decrypt one canvas by ID, path or title")
  .action(async (reference) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const canvas = new DocumentVault(dir, passphrase).getCanvas(reference);
    appendAudit(dir, { actor: "cli-direct", file: "canvases", key: canvas.id }, passphrase);
    process.stdout.write(`${JSON.stringify(canvas, null, 2)}\n`);
  });

docs
  .command("canvas-export <reference> <destination>")
  .description("export one canvas as portable JSON Canvas")
  .option("--assets <dir>", "explicitly decrypt referenced attachment bytes into this directory")
  .action(async (reference, destination, opts) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const vault = new DocumentVault(dir, passphrase);
    const canvas = vault.getCanvas(reference);
    const assetsLabel = opts.assets ? path.basename(path.resolve(opts.assets)) : "assets";
    writeFileAtomic(path.resolve(destination), vault.exportCanvas(canvas.id, assetsLabel), { mode: 0o600 });

    if (opts.assets) {
      const assetsDir = path.resolve(opts.assets);
      const filenames = new Set<string>();
      for (const node of canvas.nodes) {
        if (node.type !== "file" || !node.attachmentId) continue;
        const attachment = vault.getAttachment(node.attachmentId);
        const filename = path.basename(attachment.info.filename);
        if (filenames.has(filename)) {
          throw new Error(`Two canvas attachments export as the same filename: ${filename}`);
        }
        filenames.add(filename);
        writeFileAtomic(path.join(assetsDir, filename), attachment.data, { mode: 0o600 });
      }
    }
    appendAudit(dir, { actor: "cli-direct", file: "canvases", key: canvas.id }, passphrase);
    console.log(`Exported ${canvas.path} to ${path.resolve(destination)}.`);
  });

docs
  .command("canvas-remove <reference>")
  .description("delete one encrypted canvas without cascading to notes or attachments")
  .action(async (reference) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const canvas = openDocumentVault(dir, passphrase).removeCanvas(reference);
    appendAudit(dir, { actor: "cli-direct-write", file: "canvases", key: canvas.id }, passphrase);
    console.log(`Removed ${canvas.path} (${canvas.id}).`);
  });

docs
  .command("canvas-rename <reference> <new-path>")
  .description("rename or move a canvas without changing its stable ID")
  .action(async (reference, newPath) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const canvas = openDocumentVault(dir, passphrase).renameCanvas(reference, newPath);
    appendAudit(dir, { actor: "cli-direct-write", file: "canvases", key: canvas.id }, passphrase);
    console.log(`Renamed to ${canvas.path} (${canvas.id}, revision ${canvas.revision}).`);
  });

docs
  .command("canvas-history <reference>")
  .description("list encrypted revisions for an active or deleted canvas ID")
  .action(async (reference) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const vault = new DocumentVault(program.opts().vault, passphrase);
    for (const revision of vault.canvasRevisions(reference)) {
      console.log(`r${revision.revision}  ${revision.updatedAt}${revision.current ? "  CURRENT" : ""}`);
    }
  });

docs
  .command("canvas-revision <reference> <number>")
  .description("decrypt and print one historical canvas revision")
  .action(async (reference, number) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const canvas = new DocumentVault(dir, passphrase).getCanvasRevision(reference, Number.parseInt(number, 10));
    appendAudit(dir, { actor: "cli-direct", file: "canvases", key: canvas.id }, passphrase);
    process.stdout.write(`${JSON.stringify(canvas, null, 2)}\n`);
  });

docs
  .command("canvas-restore <reference> <number>")
  .description("restore a historical canvas as a new current revision")
  .action(async (reference, number) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const canvas = openDocumentVault(dir, passphrase).restoreCanvas(reference, Number.parseInt(number, 10));
    appendAudit(dir, { actor: "cli-direct-write", file: "canvases", key: canvas.id }, passphrase);
    console.log(`Restored ${canvas.path} as revision ${canvas.revision}.`);
  });

docs
  .command("canvas-refs <note-reference>")
  .description("list canvases that reference a note")
  .action(async (noteReference) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const vault = new DocumentVault(program.opts().vault, passphrase);
    for (const canvas of vault.canvasesReferencing(noteReference)) {
      console.log(`${canvas.path}  — ${canvas.title}  (${canvas.id})`);
    }
  });

docs
  .command("attachments-unreferenced")
  .description("report attachments not referenced by notes or canvases; never deletes them")
  .action(async () => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const vault = new DocumentVault(program.opts().vault, passphrase);
    for (const info of vault.unreferencedAttachments()) {
      console.log(`${info.id}  ${info.size} bytes  ${info.mime}  ${info.filename}`);
    }
  });

docs
  .command("from-template <template> <path>")
  .description("create an encrypted note from another note used as a safe template")
  .option("--title <title>", "target note title")
  .option("--date <yyyy-mm-dd>", "date used by template variables")
  .option("--var <pairs...>", "template variables as name=value")
  .option("--tag <tags...>", "additional tags")
  .action(async (template, notePath, opts) => {
    const variables: TemplateVariables = {};
    for (const pair of opts.var ?? []) {
      const separator = pair.indexOf("=");
      if (separator < 1) throw new Error(`Expected template variable name=value, received: ${pair}`);
      variables[pair.slice(0, separator)] = pair.slice(separator + 1);
    }
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const note = createFromTemplate(openDocumentVault(dir, passphrase), template, notePath, {
      title: opts.title,
      date: opts.date ? parseLocalDate(opts.date) : new Date(),
      variables,
      tags: opts.tag,
    });
    appendAudit(dir, { actor: "cli-direct-write", file: "documents", key: note.id }, passphrase);
    console.log(`Created ${note.path} from template ${template} (${note.id}).`);
  });

docs
  .command("daily [date]")
  .description("open or create an idempotent encrypted daily note")
  .option("--folder <path>", "daily note folder", "Daily")
  .option("--format <tokens>", "filename format using YYYY MM DD", "YYYY-MM-DD")
  .option("--template <reference>", "optional template note")
  .option("--tag <tags...>", "additional tags")
  .action(async (date, opts) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const result = openDailyNote(openDocumentVault(dir, passphrase), parseLocalDate(date), {
      folder: opts.folder,
      filenameFormat: opts.format,
      template: opts.template,
      tags: opts.tag,
    });
    if (result.created) {
      appendAudit(dir, { actor: "cli-direct-write", file: "documents", key: result.note.id }, passphrase);
    }
    console.log(`${result.created ? "Created" : "Opened"} ${result.note.path} (${result.note.id}).`);
  });

const sync = program
  .command("sync")
  .description("encrypted immutable change log and deterministic conflict inspection");

sync
  .command("device-id")
  .description("generate a new local device identity (enrollment is added in the next slice)")
  .action(() => console.log(crypto.randomUUID()));

sync
  .command("append <device-id> <object-type> <object-id> <operation>")
  .description("append one encrypted causal change to the local immutable log")
  .requiredOption("--revision <number>", "new logical object revision")
  .option("--base <number>", "base logical revision; omit when creating revision 1")
  .option("--value <json>", "JSON snapshot for a put; omit for delete")
  .action(async (deviceId, objectType, objectId, operation, opts) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const revision = Number(opts.revision);
    const baseRevision = opts.base === undefined ? null : Number(opts.base);
    let value: SyncJson = null;
    if (opts.value !== undefined) value = JSON.parse(opts.value) as SyncJson;
    const mutation: SyncMutation = {
      objectType: objectType as SyncObjectType,
      objectId,
      operation: operation as SyncOperation,
      baseRevision,
      revision,
      value,
    };
    const log = new SyncChangeLog(dir, passphrase);
    try {
      const change = log.append(deviceId, mutation);
      console.log(`${change.id}  ${change.deviceId}#${change.sequence}  ${objectType}:${objectId}@${revision}`);
    } finally {
      log.close();
    }
  });

sync
  .command("list")
  .description("list decrypted change metadata without printing snapshot values")
  .action(async () => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const log = new SyncChangeLog(dir, passphrase);
    try {
      for (const change of log.changes()) {
        const mutation = change.mutation;
        console.log(
          `${change.id}  ${change.deviceId}#${change.sequence}  ${mutation.operation} ${mutation.objectType}:${mutation.objectId}@${mutation.revision}`,
        );
      }
    } finally {
      log.close();
    }
  });

sync
  .command("export")
  .description("write relay-safe opaque encrypted envelopes as JSON to stdout")
  .action(async () => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const log = new SyncChangeLog(dir, passphrase);
    try {
      process.stdout.write(`${JSON.stringify(log.envelopes(), null, 2)}\n`);
    } finally {
      log.close();
    }
  });

sync
  .command("import <source>")
  .description("verify a complete batch, then idempotently admit encrypted envelopes from another device")
  .action(async (source) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const parsed: unknown = JSON.parse(fs.readFileSync(path.resolve(source), "utf8"));
    if (!Array.isArray(parsed)) throw new Error("Sync import must contain a JSON array of envelopes.");
    const log = new SyncChangeLog(dir, passphrase);
    try {
      const result = log.import(parsed as EncryptedSyncChange[]);
      console.log(`Imported ${result.imported}; already present ${result.existing}.`);
    } finally {
      log.close();
    }
  });

sync
  .command("verify")
  .description("verify encryption, content IDs, device chains, causal parents and object revisions")
  .action(async () => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const log = new SyncChangeLog(dir, passphrase);
    try {
      const report = log.verify();
      console.log(
        `Verified ${report.changes} changes from ${report.devices} devices; ${report.heads.length} causal heads.`,
      );
    } finally {
      log.close();
    }
  });

sync
  .command("resolve <object-type> <object-id>")
  .description("show the deterministic winner and every preserved concurrent branch")
  .action(async (objectType, objectId) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const log = new SyncChangeLog(dir, passphrase);
    try {
      console.log(JSON.stringify(log.resolve(objectType as SyncObjectType, objectId), null, 2));
    } finally {
      log.close();
    }
  });

sync
  .command("apply <object-type> <object-id>")
  .description("apply one conflict-free note, canvas or attachment history to live vault storage")
  .action(async (objectType, objectId) => {
    if (objectType !== "note" && objectType !== "canvas" && objectType !== "attachment") {
      throw new Error("Sync apply supports note, canvas and attachment objects only.");
    }
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const vault = new SyncedDocumentVault(dir, passphrase);
    try {
      const result = vault.applyResolved(objectType, objectId);
      console.log(
        result.conflict
          ? `Cannot apply ${objectType}:${objectId}; ${result.heads!.length} unresolved sync heads remain.`
          : result.alreadyApplied
            ? `Already applied ${objectType}:${objectId}@${result.revision}.`
            : `Applied ${result.applied} change(s); ${objectType}:${objectId}@${result.revision} is current.`,
      );
    } finally {
      vault.lock();
    }
  });

/**
 * `--scope health:IBAN,CARD*:resolve:partial`
 *
 * Written positionally on purpose: a grant is short enough to read in one line
 * in a terminal, and a person approving access should be able to see the whole
 * of what they are granting without opening an editor.
 */
function parseScope(input: string): GrantScope {
  const [file, keys, actions, redact = "none"] = input.split(":");
  if (!file || !keys || !actions) {
    throw new Error(
      `Invalid scope: ${input}. Use file:keys:actions[:redaction], e.g. health:*:discover,resolve:partial`,
    );
  }
  if (!isRedactionLevel(redact)) {
    throw new Error(`Invalid redaction level: ${redact}. Use one of ${REDACTION_LEVELS.join(", ")}.`);
  }
  return normalizeScope({
    file,
    keys: keys
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean),
    actions: actions
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean) as GrantAction[],
    redact: redact as RedactionLevel,
  });
}

/** `7d`, `12h`, `30m`, or an absolute ISO timestamp. */
function parseExpiry(input?: string): string | null {
  if (!input) return null;
  const relative = /^(\d+)([mhd])$/u.exec(input.trim());
  if (relative) {
    const amount = Number(relative[1]);
    const unit = { m: 60_000, h: 3_600_000, d: 86_400_000 }[relative[2] as "m" | "h" | "d"];
    return new Date(Date.now() + amount * unit).toISOString();
  }
  const absolute = new Date(input);
  if (Number.isNaN(absolute.getTime())) {
    throw new Error(`Invalid expiry: ${input}. Use 30m, 12h, 7d or an ISO timestamp.`);
  }
  return absolute.toISOString();
}

const grant = program
  .command("grant")
  .description("per-agent scoped grants: who may discover, resolve or store what, and how masked");

grant
  .command("add <agent>")
  .description("grant one agent identity a narrow, optionally expiring slice of the vault")
  .requiredOption("--scope <scope...>", "file:keys:actions[:redaction], e.g. health:*:discover,resolve:partial")
  .option("--expires <when>", "30m, 12h, 7d or an ISO timestamp; omit for no expiry")
  .option("--confirm", "hold every resolution for your approval before it is answered")
  .option("--note <text>", "why this grant exists, for your own review later")
  .action(async (agentName, opts) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const first = !grantsExist(dir);
    const created = addGrant(
      dir,
      {
        agent: agentName,
        scopes: opts.scope.map(parseScope),
        expiresAt: parseExpiry(opts.expires),
        confirm: opts.confirm ? "always" : "never",
        note: opts.note,
      },
      passphrase,
    );
    if (first) {
      console.log("This vault is now GOVERNED: agents without a grant can no longer read it.");
    }
    console.log(`Granted ${created.id.slice(0, 8)} to "${created.agent}".`);
    for (const scope of created.scopes) {
      console.log(`  ${scope.file} · ${scope.keys.join(",")} · ${scope.actions.join(",")} · redaction ${scope.redact}`);
    }
    console.log(`  expires ${created.expiresAt ?? "never"} · confirmation ${created.confirm}`);
  });

grant
  .command("list")
  .description("show every grant, active or not, with no secret values")
  .option("--json", "emit machine-readable JSON")
  .action(async (opts) => {
    const dir = program.opts().vault;
    if (!grantsExist(dir)) {
      console.log("This vault has no grant policy; any agent with the passphrase sees everything.");
      return;
    }
    const passphrase = await getPassphrase({ vaultDir: dir });
    const grants = listGrants(dir, passphrase);
    if (opts.json) {
      console.log(JSON.stringify(grants, null, 2));
      return;
    }
    const now = Date.now();
    for (const entry of grants) {
      const state = entry.revokedAt
        ? "revoked"
        : entry.expiresAt && new Date(entry.expiresAt).getTime() <= now
          ? "expired"
          : "active";
      console.log(`${entry.id.slice(0, 8)}  ${entry.agent}  [${state}]`);
      for (const scope of entry.scopes) {
        console.log(
          `    ${scope.file} · ${scope.keys.join(",")} · ${scope.actions.join(",")} · redaction ${scope.redact}`,
        );
      }
      console.log(`    expires ${entry.expiresAt ?? "never"} · confirmation ${entry.confirm}`);
      if (entry.note) console.log(`    note: ${entry.note}`);
    }
    if (!grants.length) console.log("No grants recorded yet.");
  });

grant
  .command("revoke <id>")
  .description("revoke a grant immediately, by full ID or unique prefix")
  .action(async (id) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const revoked = revokeGrant(dir, id, passphrase);
    console.log(`Revoked ${revoked.id.slice(0, 8)} for "${revoked.agent}" at ${revoked.revokedAt}.`);
  });

grant
  .command("requests")
  .description("list resolutions waiting for your approval")
  .action(async () => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const requests = pendingRequests(dir, passphrase);
    if (!requests.length) {
      console.log("Nothing is waiting for approval.");
      return;
    }
    for (const request of requests) {
      console.log(
        `${request.id.slice(0, 8)}  ${request.agent} wants ${request.file}.${request.key}  (expires ${request.expiresAt})`,
      );
    }
  });

grant
  .command("approve <id>")
  .description("approve one held resolution; the approval is single-use and expires shortly")
  .action(async (id) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const approved = approveRequest(dir, id, passphrase);
    console.log(`Approved ${approved.file}.${approved.key} for "${approved.agent}" until ${approved.expiresAt}.`);
  });

grant
  .command("deny <id>")
  .description("drop one held resolution without approving it")
  .action(async (id) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    denyRequest(dir, id, passphrase);
    console.log(`Denied ${id}.`);
  });

const plugins = program
  .command("plugins")
  .description("sandboxed extensions: what is installed, what it may reach, and whether it runs");

plugins
  .command("list")
  .description("list installed plugins and the capabilities each one declared")
  .option("--json", "emit machine-readable JSON")
  .action(async (opts) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const installed = new DocumentVault(dir, passphrase).listPlugins();
    if (opts.json) {
      console.log(JSON.stringify(installed, null, 2));
      return;
    }
    if (!installed.length) {
      console.log("No plugins installed.");
      return;
    }
    for (const plugin of installed) {
      console.log(
        `${plugin.name} v${plugin.version}  [${plugin.enabled ? "on" : "off"}]  [${plugin.signatureStatus}]  ${plugin.manifestId}`,
      );
      for (const line of describeCapabilities(plugin.capabilities as PluginCapability[])) {
        console.log(`    - ${line}`);
      }
      if (!plugin.capabilities.length) console.log("    - asks for nothing at all");
    }
  });

plugins
  .command("keygen <private-key>")
  .description("create an Ed25519 private key for signing plugin packages")
  .action((privateKeyPath) => {
    if (fs.existsSync(privateKeyPath)) throw new Error(`Refusing to overwrite: ${privateKeyPath}`);
    const generated = generatePluginSigningKey();
    writeFileAtomic(privateKeyPath, generated.privateKeyPem, { mode: 0o600 });
    console.log(`Created plugin signing key: ${privateKeyPath}`);
    console.log(`Signer key ID: ${generated.keyId}`);
    console.log(`Public key (base64url): ${generated.publicKey}`);
  });

plugins
  .command("sign <manifest> <source>")
  .description("sign a plugin manifest and its exact JavaScript source")
  .requiredOption("--key <private-key>", "Ed25519 private key created by plugins keygen")
  .requiredOption("--out <manifest>", "write the signed manifest here")
  .action((manifestPath, sourcePath, opts) => {
    if (fs.existsSync(opts.out)) throw new Error(`Refusing to overwrite: ${opts.out}`);
    const raw = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
    delete raw.signature;
    const manifest = parsePluginManifest(raw);
    const source = fs.readFileSync(sourcePath, "utf8");
    const signature = signPluginPackage(manifest, source, fs.readFileSync(opts.key, "utf8"));
    writeFileAtomic(opts.out, `${JSON.stringify({ ...manifest, signature }, null, 2)}\n`, { mode: 0o600 });
    console.log(`Signed manifest written to ${opts.out}.`);
  });

plugins
  .command("policy")
  .description("show restricted mode and locally revoked plugin signers")
  .option("--json", "emit machine-readable JSON")
  .action(async (opts) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const policy = new DocumentVault(dir, passphrase).pluginSecurityPolicy();
    if (opts.json) console.log(JSON.stringify(policy, null, 2));
    else {
      console.log(`Restricted mode: ${policy.restrictedMode ? "on" : "off"}`);
      console.log(`Revoked signers: ${policy.revokedSigners.length}`);
      for (const keyId of policy.revokedSigners) console.log(`  ${keyId}`);
    }
  });

plugins
  .command("restricted <mode>")
  .description("turn signed-only plugin mode on or off")
  .action(async (mode) => {
    if (mode !== "on" && mode !== "off") throw new Error("Restricted mode must be 'on' or 'off'.");
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    new DocumentVault(dir, passphrase).setPluginRestrictedMode(mode === "on");
    console.log(`Restricted mode is ${mode}.`);
  });

plugins
  .command("revoke-signer <reference>")
  .description("locally block the signer of an installed plugin")
  .action(async (reference) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const policy = new DocumentVault(dir, passphrase).revokePluginSigner(reference);
    console.log(`Signer revoked. ${policy.revokedSigners.length} signer(s) are now blocked.`);
  });

plugins
  .command("restore-signer <key-id>")
  .description("remove a signer key ID from this vault's local revocation list")
  .action(async (keyId) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const policy = new DocumentVault(dir, passphrase).restorePluginSigner(keyId);
    console.log(`Signer restored. ${policy.revokedSigners.length} signer(s) remain blocked.`);
  });

plugins
  .command("install <manifest> <source>")
  .description("install a plugin from its manifest (.json) and source (.js); it stays off until enabled")
  .option("--enable", "turn it on immediately")
  .action(async (manifestPath, sourcePath, opts) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const installed = new DocumentVault(dir, passphrase).installPlugin({
      manifest: JSON.parse(fs.readFileSync(manifestPath, "utf8")),
      source: fs.readFileSync(sourcePath, "utf8"),
      enabled: opts.enable === true,
    });
    console.log(`Installed ${installed.manifest.name} v${installed.manifest.version}.`);
    console.log(`It may:`);
    for (const line of describeCapabilities(installed.manifest.capabilities)) {
      console.log(`  - ${line}`);
    }
    if (!installed.manifest.capabilities.length) console.log("  - nothing at all");
    console.log(installed.enabled ? "It is enabled." : "It is installed but not enabled.");
  });

plugins
  .command("enable <reference>")
  .description("turn one installed plugin on")
  .action(async (reference) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const changed = new DocumentVault(dir, passphrase).setPluginEnabled(reference, true);
    console.log(`${changed.name} is enabled.`);
  });

plugins
  .command("disable <reference>")
  .description("turn one installed plugin off")
  .action(async (reference) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const changed = new DocumentVault(dir, passphrase).setPluginEnabled(reference, false);
    console.log(`${changed.name} is disabled.`);
  });

plugins
  .command("remove <reference>")
  .description("remove one plugin and the settings it owns")
  .action(async (reference) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const removed = new DocumentVault(dir, passphrase).removePlugin(reference);
    console.log(`Removed ${removed.name}.`);
  });

program
  .command("audit")
  .description("verify and print the value-free, passphrase-authenticated audit trail")
  .option("--json", "emit machine-readable JSON")
  .action(async (opts) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const verification = verifyAudit(dir, passphrase);
    const entries = readAudit(dir);
    if (opts.json) {
      console.log(JSON.stringify({ verification, entries }, null, 2));
      return;
    }
    console.log(
      `Audit integrity: ${verification.valid ? "VALID" : "INVALID"} ` +
        `(${verification.signedEntries} signed, ${verification.legacyEntries} legacy)`,
    );
    if (verification.error) console.log(`  ${verification.error}`);
    for (const entry of entries) {
      const governed = [
        entry.agent && `agent ${entry.agent}`,
        entry.outcome && entry.outcome,
        entry.redaction && entry.redaction !== "none" && `redacted ${entry.redaction}`,
      ].filter(Boolean);
      console.log(
        `${entry.timestamp}  ${entry.actor}  ${entry.file}.${entry.key}` +
          (governed.length ? `  (${governed.join(", ")})` : ""),
      );
    }
    if (!verification.valid) process.exitCode = 2;
  });

program
  .command("mcp")
  .description("MODE 2 — start the MCP server for AI-agent-assisted, scoped, audited access")
  .action(async () => {
    const dir = program.opts().vault;
    if (!grantsExist(dir)) {
      console.error(
        "Note: this vault has no grant policy, so any agent that starts this server sees every key. " +
          "Run 'vbrain grant add <agent> --scope ...' to govern it.",
      );
    }
    await startMcpServer(dir);
  });

program
  .command("migrate")
  .description("upgrade this vault to the encrypted keyring format and rewrite key-value files")
  .action(async () => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const report = migrateToKeyring(dir, passphrase);

    if (report.created) {
      console.log(`Wrote ${path.join(dir, "keyring.json")}.`);
      if (report.adopted.length > 0) {
        console.log(`Adopted existing keys: ${report.adopted.join(", ")}.`);
        console.log(`Attachment identities, sync change IDs and the audit chain are unchanged.`);
      }
      console.log(`Generated new keys: ${report.generated.join(", ")}.`);
    } else {
      console.log("This vault already has a keyring.");
    }

    if (report.kvFilesRewritten.length > 0) {
      console.log(`Rewrote ${report.kvFilesRewritten.length} key-value file(s): ${report.kvFilesRewritten.join(", ")}.`);
    }
    if (report.grantsRewritten) console.log("Rewrote grants.enc in the keyed envelope.");
    if (report.manifestTombstoned) {
      console.log("Replaced documents/manifest.json with a version marker; its passphrase verifier is gone.");
    }
    console.log("Desktop builds older than this release cannot open a migrated vault.");
  });

const passphraseCommand = program.command("passphrase").description("manage the passphrase that wraps this vault's keys");

passphraseCommand
  .command("change")
  .description("change the vault passphrase and re-wrap the keyring at the current KDF cost")
  .option("--allow-same-passphrase", "re-wrap the keyring at the current cost without changing the passphrase")
  .action(async (opts) => {
    const dir = program.opts().vault;
    // Never taken from the OS credential store: a stale or attacker-primed
    // credential must not be able to authorize a passphrase change on its
    // own, the way `unlock` resolves its passphrase.
    const current = process.env.VBRAIN_PASSPHRASE ?? (await readSecret("Current vault passphrase: "));
    if (!current) {
      console.error("A passphrase is required.");
      process.exit(1);
    }
    const next = process.env.VBRAIN_NEW_PASSPHRASE ?? (await readNewPassphrase());

    const report = changeVaultPassphrase(dir, current, next, {
      allowSamePassphrase: Boolean(opts.allowSamePassphrase),
    });

    console.log(`Passphrase changed for ${dir}.`);
    console.log(`Re-wrapped ${report.slotsRewritten} keyring slot(s) at scrypt N=${report.newN}.`);
    if (report.previousN !== report.newN) {
      console.log(`Key-derivation cost raised from N=${report.previousN}.`);
    }
    if (report.slotsPreserved > 0) {
      console.log(`Left ${report.slotsPreserved} slot(s) this passphrase does not open untouched:`);
      for (const slot of report.preserved) {
        console.log(`  ${slot.id} (${slot.label}), created ${slot.createdAt}, scrypt N=${slot.n}.`);
      }
    }

    const keychainResult = updateRememberedPassphrase(dir, next);
    if (keychainResult.updated) {
      console.log(`Updated the remembered passphrase in the OS credential store (${keychainResult.backend}).`);
    } else if (keychainResult.error) {
      const credentialState = keychainResult.cleared
        ? "The remembered credential was removed. Run 'vbrain unlock --remember' to store the new passphrase."
        : "The remembered credential could not be removed either. Run 'vbrain lock' to clear it.";
      console.error(
        `Warning: the passphrase changed, but the OS credential store (${keychainResult.backend}) could not be updated (${keychainResult.error}). ` +
          credentialState,
      );
    }

    console.log("This does not re-encrypt anything: every note, attachment and sync change keeps its key.");
    console.log("If the old passphrase leaked, run 'vbrain rekey' instead: it replaces the keys as well.");
  });

/** Two masked entries that have to agree, so a typo cannot become the new passphrase. */
async function readNewPassphrase(): Promise<string> {
  const first = await readSecret("New vault passphrase: ");
  if (first.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(`The new passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters.`);
  }
  const second = await readSecret("Repeat new vault passphrase: ");
  if (first !== second) throw new Error("The two entries did not match; nothing was changed.");
  return first;
}

program
  .command("rekey")
  .description("replace the vault keyset and re-encrypt every object under it")
  .option("--keep-passphrase", "rotate the keys but keep wrapping them under the current passphrase")
  .action(async (opts) => {
    const dir = program.opts().vault;
    const keepPassphrase = Boolean(opts.keepPassphrase);
    // Never taken from the OS credential store, for the same reason
    // `passphrase change` does not: a stale or attacker-primed credential
    // must not be able to authorize a re-key on its own.
    const current = process.env.VBRAIN_PASSPHRASE ?? (await readSecret("Current vault passphrase: "));
    if (!current) {
      console.error("A passphrase is required.");
      process.exit(1);
    }
    const next = keepPassphrase
      ? ""
      : (process.env.VBRAIN_NEW_PASSPHRASE ?? (await readNewPassphrase()));

    let report;
    try {
      report = rekeyVault(dir, current, next, { keepPassphrase });
    } catch (error) {
      // `readJournal` (via `recoverRekey`) and `stageRekey` both refuse a
      // malformed journal rather than guess at it, which otherwise leaves the
      // operator with nowhere to go: recovery refuses for the same reason a
      // fresh re-key does. The one thing that actually clears this is exactly
      // what recovery already does automatically for a staging area that
      // carries no journal at all — discard it, since nothing live is ever
      // touched before the journal is written.
      if (error instanceof Error && error.message === MALFORMED_JOURNAL_MESSAGE) {
        console.error(
          `${error.message} This cannot be repaired automatically. Back up ${stagingRoot(dir)} if you want a copy, ` +
            `then delete that directory by hand — nothing live has been touched — and run 'vbrain rekey' again.`,
        );
        process.exit(1);
      }
      throw error;
    }

    if (report.resumed) {
      console.log(`Finished an interrupted re-key of ${dir}.`);
      return;
    }

    console.log(`Re-keyed ${dir}.`);
    console.log(
      `Rotated ${report.rotated.join(", ")} and re-encrypted ${report.reencrypted.total} file(s): ` +
        `${report.reencrypted.documents} document object(s), ${report.reencrypted.kv} key-value file(s), ` +
        `${report.reencrypted.syncChanges} sync change(s).`,
    );
    if (report.droppedSlots.length > 0) {
      console.log(`Dropped ${report.droppedSlots.length} slot(s) this passphrase does not open:`);
      for (const slot of report.droppedSlots) {
        console.log(`  ${slot.id} (${slot.label}), created ${slot.createdAt}.`);
      }
    }

    if (report.passphraseChanged) {
      const keychainResult = updateRememberedPassphrase(dir, next);
      if (keychainResult.updated) {
        console.log(`Updated the remembered passphrase in the OS credential store (${keychainResult.backend}).`);
      } else if (keychainResult.error) {
        const credentialState = keychainResult.cleared
          ? "The remembered credential was removed. Run 'vbrain unlock --remember' to store the new passphrase."
          : "The remembered credential could not be removed either. Run 'vbrain lock' to clear it.";
        console.error(
          `Warning: the vault was re-keyed, but the OS credential store (${keychainResult.backend}) could not be updated (${keychainResult.error}). ` +
            credentialState,
        );
      }
    }

    console.log("Attachment identities, sync change IDs and the audit chain are unchanged by design:");
    for (const pinned of report.pinned) {
      console.log(`  ${pinned.name} is pinned because ${pinned.reason}.`);
    }
    console.log(
      "Someone who kept the old keyset can still confirm a guessed file is in this vault, though they cannot read it.",
    );
  });

program
  .command("unlock")
  .description("verify the passphrase for this vault, optionally remembering it in the OS credential store")
  .option("--remember", "store the passphrase in the OS credential store for this vault")
  .action(async (opts) => {
    const dir = program.opts().vault;
    const passphrase = process.env.VBRAIN_PASSPHRASE ?? (await readSecret("Vault passphrase: "));
    if (!passphrase) {
      console.error("A passphrase is required.");
      process.exit(1);
    }
    // Proves the passphrase against the real vault before anything is stored.
    new DocumentVault(dir, passphrase).list();
    console.log(`Unlocked ${dir}.`);
    if (opts.remember) {
      const backend = rememberPassphrase(dir, passphrase);
      console.log(`Passphrase remembered in the OS credential store (${backend}). Run 'vbrain lock' to forget it.`);
    }
  });

program
  .command("lock")
  .description("forget this vault's remembered passphrase (explicit end of the unlocked session)")
  .action(async () => {
    const dir = program.opts().vault;
    console.log(
      forgetPassphrase(dir)
        ? `Locked: the remembered passphrase for ${dir} was removed from the OS credential store.`
        : `Nothing to forget: no remembered passphrase for ${dir}.`,
    );
  });

program
  .command("keychain-status")
  .description("show which OS credential store is available and whether this vault has a remembered passphrase")
  .action(async () => {
    const dir = program.opts().vault;
    const backend = keychain();
    console.log(`Credential store: ${backend.name}${backend.available() ? "" : " (unavailable)"}`);
    console.log(`Vault format: ${detectVaultFormat(dir)}`);
    console.log(`Remembered for ${dir}: ${recallPassphrase(dir) ? "yes" : "no"}`);
    for (const name of listVaultFiles(dir)) {
      console.log(`  ${name}.kv.enc: envelope v${vaultFileEnvelopeVersion(dir, name)}`);
    }
  });

program.parseAsync(process.argv).catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Error: ${message}`);
  process.exitCode = 1;
});
