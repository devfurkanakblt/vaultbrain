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
import { readTextFileLimited, writeFileAtomic } from "./fs-safe.js";
import {
  SyncChangeLog,
  SyncDeviceManager,
  SyncedDocumentVault,
  syncRegistryFingerprint,
  type EncryptedSyncChange,
  type EncryptedSyncDeviceRegistry,
  type EncryptedSyncFreshnessCheckpoint,
  type SyncJson,
  type SyncMutation,
  type SyncObjectType,
  type SyncOperation,
} from "./sync.js";
import { startSyncRelay, SyncRelayClient } from "./sync-relay.js";
import {
  createFromTemplate,
  openDailyNote,
  parseLocalDate,
  type TemplateVariables,
} from "./templates.js";
import { FORMAT_COMPATIBILITY, VAULT_FORMAT_VERSION } from "./format-version.js";

const program = new Command();

function openDocumentVault(vaultDir: string, passphrase: string): DocumentVault {
  const deviceId = program.opts().syncDevice as string | undefined;
  if (deviceId && !program.opts().experimentalTrustedSync) {
    throw new Error(
      "Sync is experimental and trusted-device/local-transport only. Re-run with --experimental-trusted-sync to acknowledge this boundary."
    );
  }
  return deviceId
    ? new SyncedDocumentVault(vaultDir, passphrase, deviceId)
    : new DocumentVault(vaultDir, passphrase);
}

program
  .name("vbrain")
  .description("Vault Brain — an .env-style, least-exposure personal data store for the AI age.")
  .option("--vault <dir>", "vault directory", DEFAULT_VAULT_DIR)
  .option("--sync-device <uuid>", "automatically capture document writes for this sync device")
  .option(
    "--experimental-trusted-sync",
    "acknowledge the experimental sync format and trusted-device boundary"
  );

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
    console.log(`Encrypted, value-free schema refreshed.`);
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
  .description("browse journal notes by date range after unlocking the encrypted catalog")
  .option("--category <file>", "limit to one category")
  .option("--from <iso-date>", "inclusive lower bound")
  .option("--to <iso-date>", "inclusive upper bound")
  .action(async (opts) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const schema = readSchema(dir, passphrase);
    if (!schema) {
      console.log("No encrypted schema yet — run 'sbrain index' first.");
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
  .action(async () => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const schema = readSchema(dir, passphrase);
    if (!schema) {
      console.log("No encrypted schema yet — run 'sbrain index' first.");
      return;
    }
    for (const [file, entries] of Object.entries(schema.files)) {
      console.log(`\n${file}.kv.enc`);
      for (const e of entries) console.log(`  ${e.key}  — ${e.desc}`);
    }
  });

program
  .command("search <query>")
  .description("fuzzy-search key names + descriptions in the encrypted fast-path catalog")
  .action(async (query) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const schema = readSchema(dir, passphrase);
    if (!schema) {
      console.log("No encrypted schema yet — run 'sbrain index' first.");
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
  .description("rebuild the encrypted key-name and description catalog across the vault")
  .action(async () => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const schema = buildSchema(dir, passphrase);
    const total = Object.values(schema.files).reduce((n, arr) => n + arr.length, 0);
    console.log(`Indexed ${total} keys across ${listVaultFiles(dir).length} files -> ${dir}/schema.enc`);
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

function relayToken(): string {
  const token = process.env.SBRAIN_RELAY_TOKEN;
  if (!token) throw new Error("Set SBRAIN_RELAY_TOKEN to a random secret containing at least 32 bytes.");
  if (Buffer.byteLength(token, "utf8") < 32) {
    throw new Error("SBRAIN_RELAY_TOKEN must contain at least 32 bytes.");
  }
  return token;
}

sync.hook("preAction", () => {
  if (!program.opts().experimentalTrustedSync) {
    throw new Error(
      "Sync format compatibility is experimental and enrolled devices remain trusted. Re-run with --experimental-trusted-sync to acknowledge this boundary."
    );
  }
});

sync
  .command("device-id")
  .description("generate a UUID for legacy trusted-device sync")
  .action(() => console.log(crypto.randomUUID()));

const syncDevices = sync
  .command("devices")
  .description("owner-signed device enrollment, registry exchange and revocation");

syncDevices
  .command("init <name>")
  .description("create the enrollment authority and enroll this first device")
  .option("--device-id <uuid>", "use an existing local device UUID")
  .action(async (name, opts) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const manager = new SyncDeviceManager(dir, passphrase);
    try {
      const registry = manager.initializeOwner(name, opts.deviceId);
      console.log(
        JSON.stringify(
          {
            deviceId: registry.body.devices[0].certificate.deviceId,
            authorityFingerprint: manager.fingerprint(),
            registryRevision: registry.body.revision,
            legacyChanges: registry.body.legacyChangeIds.length,
          },
          null,
          2,
        ),
      );
    } finally {
      manager.close();
    }
  });

syncDevices
  .command("request <name>")
  .description("create a proof-of-possession enrollment request and retain its private key locally")
  .option("--device-id <uuid>", "use an existing local device UUID")
  .action(async (name, opts) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const manager = new SyncDeviceManager(dir, passphrase);
    try {
      process.stdout.write(`${JSON.stringify(manager.createEnrollmentRequest(name, opts.deviceId), null, 2)}\n`);
    } finally {
      manager.close();
    }
  });

syncDevices
  .command("enroll <request>")
  .description("verify and owner-sign a device enrollment request")
  .action(async (source) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const parsed: unknown = JSON.parse(
      readTextFileLimited(path.resolve(source), 64 * 1024, "Sync enrollment request"),
    );
    const manager = new SyncDeviceManager(dir, passphrase);
    try {
      const registry = manager.enroll(parsed);
      const requestId = (parsed as { deviceId?: unknown }).deviceId;
      const enrolled = registry.body.devices.find(
        (record) => record.certificate.deviceId === requestId,
      );
      if (!enrolled) throw new Error("Enrolled device is missing from the updated registry.");
      console.log(
        `Enrolled ${enrolled.certificate.name} (${enrolled.certificate.deviceId}); registry revision ${registry.body.revision}.`,
      );
    } finally {
      manager.close();
    }
  });

syncDevices
  .command("list")
  .description("list enrolled and revoked device certificates")
  .action(async () => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const manager = new SyncDeviceManager(dir, passphrase);
    try {
      const registry = manager.state();
      if (!registry) throw new Error("Sync device enrollment is not initialized.");
      console.log(
        `Authority ${manager.fingerprint()} — registry revision ${registry.body.revision}, epoch ${registry.body.epoch}`,
      );
      for (const record of registry.body.devices) {
        const state = record.revokedAt ? `revoked-after=${record.revokedAfterSequence}` : "active";
        console.log(
          `${record.certificate.deviceId}  ${record.certificate.name}  serial=${record.certificate.serial}  epoch=${record.certificate.epoch}  ${state}`,
        );
      }
    } finally {
      manager.close();
    }
  });

syncDevices
  .command("export")
  .description("write the encrypted owner-signed device registry bundle to stdout")
  .action(async () => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const manager = new SyncDeviceManager(dir, passphrase);
    try {
      process.stdout.write(`${JSON.stringify(manager.exportRegistry(), null, 2)}\n`);
    } finally {
      manager.close();
    }
  });

syncDevices
  .command("import <source>")
  .description("verify and install a newer owner-signed device registry")
  .option("--authority <sha256>", "expected authority fingerprint for the first import")
  .action(async (source, opts) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const parsed: unknown = JSON.parse(
      readTextFileLimited(path.resolve(source), 12 * 1024 * 1024, "Sync device registry bundle"),
    );
    const manager = new SyncDeviceManager(dir, passphrase);
    try {
      const registry = manager.importRegistry(
        parsed as EncryptedSyncDeviceRegistry,
        opts.authority,
      );
      console.log(`Installed device registry revision ${registry.body.revision}.`);
    } finally {
      manager.close();
    }
  });

syncDevices
  .command("revoke <device-id>")
  .description("owner-sign a revocation at the last observed device sequence")
  .action(async (deviceId) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const log = new SyncChangeLog(dir, passphrase);
    let cutoff: number;
    try {
      cutoff = Math.max(
        0,
        ...log.changes().filter((change) => change.deviceId === deviceId).map((change) => change.sequence),
      );
    } finally {
      log.close();
    }
    const manager = new SyncDeviceManager(dir, passphrase);
    try {
      const registry = manager.revoke(deviceId, cutoff);
      console.log(
        `Revoked ${deviceId} after sequence ${cutoff}; registry revision ${registry.body.revision}, rotated to epoch ${registry.body.epoch}.`,
      );
      console.log(
        "Export the registry to every remaining device so they adopt the new epoch key; changes written before this rotation stay readable to the revoked device.",
      );
    } finally {
      manager.close();
    }
  });

const syncCheckpoint = sync
  .command("checkpoint")
  .description("owner-signed freshness checkpoints for relay rollback detection");

syncCheckpoint
  .command("create")
  .description("sign and pin the complete currently verified sync history")
  .action(async () => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const log = new SyncChangeLog(dir, passphrase);
    let changes;
    try {
      changes = log.changes();
    } finally {
      log.close();
    }
    const manager = new SyncDeviceManager(dir, passphrase);
    try {
      const checkpoint = manager.createCheckpoint(changes);
      console.log(
        `Created checkpoint ${checkpoint.id} at sequence ${checkpoint.body.sequence} for ${checkpoint.body.changeCount} changes.`,
      );
    } finally {
      manager.close();
    }
  });

syncCheckpoint
  .command("export")
  .description("write the encrypted signed checkpoint bundle to stdout")
  .action(async () => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const manager = new SyncDeviceManager(dir, passphrase);
    try {
      process.stdout.write(`${JSON.stringify(manager.exportCheckpoint(), null, 2)}\n`);
    } finally {
      manager.close();
    }
  });

syncCheckpoint
  .command("import <source>")
  .description("verify and pin a checkpoint against the complete local sync history")
  .option("--expected <sha256>", "expected checkpoint ID for the first import")
  .action(async (source, opts) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const parsed: unknown = JSON.parse(
      readTextFileLimited(path.resolve(source), 2 * 1024 * 1024, "Sync freshness checkpoint bundle"),
    );
    const log = new SyncChangeLog(dir, passphrase);
    let changes;
    try {
      changes = log.changes();
    } finally {
      log.close();
    }
    const manager = new SyncDeviceManager(dir, passphrase);
    try {
      const checkpoint = manager.importCheckpoint(
        parsed as EncryptedSyncFreshnessCheckpoint,
        changes,
        opts.expected,
      );
      console.log(`Pinned freshness checkpoint ${checkpoint.id} at sequence ${checkpoint.body.sequence}.`);
    } finally {
      manager.close();
    }
  });

syncCheckpoint
  .command("verify")
  .description("prove the pinned checkpoint is present in the local causal history")
  .action(async () => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const log = new SyncChangeLog(dir, passphrase);
    let changes;
    try {
      changes = log.changes();
    } finally {
      log.close();
    }
    const manager = new SyncDeviceManager(dir, passphrase);
    try {
      const checkpoint = manager.verifyCheckpoint(changes);
      console.log(
        `Verified checkpoint ${checkpoint.id}: ${checkpoint.body.changeCount} committed changes are present.`,
      );
    } finally {
      manager.close();
    }
  });

const syncRelay = sync
  .command("relay")
  .description("authenticated opaque relay transport for encrypted sync objects");

syncRelay
  .command("serve <storage>")
  .description("run a self-hosted relay; the bearer token is read from SBRAIN_RELAY_TOKEN")
  .option("--host <address>", "listen address", "127.0.0.1")
  .option("--port <number>", "listen port", "8787")
  .action(async (storage, opts) => {
    const port = Number(opts.port);
    if (!Number.isSafeInteger(port) || port < 0 || port > 65_535) {
      throw new Error("Relay port must be an integer between 0 and 65535.");
    }
    const relay = await startSyncRelay({
      storageDir: path.resolve(storage),
      token: relayToken(),
      host: opts.host,
      port,
    });
    console.log(`Sync relay listening at ${relay.url}.`);
    console.log("The relay stores opaque encrypted objects and cannot recover a lost vault key.");
    await new Promise<void>((resolve, reject) => {
      let closing = false;
      const stop = (): void => {
        if (closing) return;
        closing = true;
        void relay.close().then(resolve, reject);
      };
      process.once("SIGINT", stop);
      process.once("SIGTERM", stop);
    });
  });

syncRelay
  .command("push <url>")
  .description("upload encrypted changes, device registry and pinned checkpoint")
  .action(async (url) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const manager = new SyncDeviceManager(dir, passphrase);
    const log = new SyncChangeLog(dir, passphrase);
    try {
      const vaultId = manager.fingerprint();
      if (!vaultId) throw new Error("Initialize sync device enrollment before using a relay.");
      const client = new SyncRelayClient(url, relayToken(), vaultId);
      const changes = await client.uploadChanges(log.envelopes());
      const registryArtifact = await client.uploadArtifact("registry", manager.exportRegistry());
      let checkpointArtifact: string | null = null;
      if (manager.checkpoint()) {
        checkpointArtifact = await client.uploadArtifact("checkpoint", manager.exportCheckpoint());
      }
      console.log(JSON.stringify({ changes, registryArtifact, checkpointArtifact }, null, 2));
    } finally {
      log.close();
      manager.close();
    }
  });

syncRelay
  .command("pull <url>")
  .description("verify and import encrypted relay state without trusting the relay")
  .option("--authority <sha256>", "expected enrollment authority on the first pull")
  .option("--checkpoint <sha256>", "expected freshness checkpoint on the first pull")
  .action(async (url, opts) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const manager = new SyncDeviceManager(dir, passphrase);
    let log: SyncChangeLog | undefined;
    try {
      const currentAuthority = manager.fingerprint();
      const expectedAuthority = currentAuthority ?? opts.authority;
      if (!expectedAuthority || !/^[a-f0-9]{64}$/u.test(expectedAuthority)) {
        throw new Error("First relay pull requires --authority with the expected 64-character fingerprint.");
      }
      const client = new SyncRelayClient(url, relayToken(), expectedAuthority);
      const registryBundles = await client.downloadArtifacts("registry");
      const registries = registryBundles
        .map((value) => ({ value, registry: manager.inspectRegistry(value) }))
        .filter(({ registry }) => syncRegistryFingerprint(registry) === expectedAuthority)
        .sort((left, right) => right.registry.body.revision - left.registry.body.revision);
      const newest = registries[0];
      if (!newest) throw new Error("Relay has no registry for the expected enrollment authority.");
      manager.importRegistry(newest.value, currentAuthority ? undefined : expectedAuthority);

      log = new SyncChangeLog(dir, passphrase);
      const imported = log.import(await client.downloadChanges());
      const changes = log.changes();

      const checkpointBundles = await client.downloadArtifacts("checkpoint");
      const checkpoints = checkpointBundles
        .map((value) => ({ value, checkpoint: manager.inspectCheckpoint(value) }))
        .sort((left, right) => left.checkpoint.body.sequence - right.checkpoint.body.sequence);
      let pinned = manager.checkpoint();
      if (!pinned && opts.checkpoint) {
        if (!/^[a-f0-9]{64}$/u.test(opts.checkpoint)) {
          throw new Error("Expected checkpoint must be a 64-character lowercase hexadecimal ID.");
        }
        const expected = checkpoints.find(({ checkpoint }) => checkpoint.id === opts.checkpoint);
        if (!expected) throw new Error("Relay does not contain the expected freshness checkpoint.");
        pinned = manager.importCheckpoint(expected.value, changes, opts.checkpoint);
      } else if (pinned) {
        while (true) {
          const extensions = checkpoints.filter(
            ({ checkpoint }) =>
              checkpoint.body.sequence === pinned!.body.sequence + 1 &&
              checkpoint.body.previousCheckpoint === pinned!.id,
          );
          if (extensions.length > 1) throw new Error("Relay contains a forked freshness checkpoint sequence.");
          if (extensions.length === 0) break;
          pinned = manager.importCheckpoint(extensions[0].value, changes);
        }
      }
      if (pinned) manager.verifyCheckpoint(changes);
      console.log(
        JSON.stringify(
          {
            registryRevision: newest.registry.body.revision,
            changes: imported,
            checkpoint: pinned?.id ?? null,
            checkpointWarning: pinned ? null : "No checkpoint was pinned; use --checkpoint on the first pull.",
          },
          null,
          2,
        ),
      );
    } finally {
      log?.close();
      manager.close();
    }
  });

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
  .description("apply one conflict-free supported object history to live vault storage")
  .action(async (objectType, objectId) => {
    if (!["note", "canvas", "attachment", "plugin", "vault"].includes(objectType)) {
      throw new Error("Unsupported sync object type.");
    }
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const vault = new SyncedDocumentVault(dir, passphrase);
    try {
      const result = vault.applyResolved(objectType as SyncObjectType, objectId);
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
    openDocumentVault(dir, passphrase).setPluginRestrictedMode(mode === "on");
    console.log(`Restricted mode is ${mode}.`);
  });

plugins
  .command("revoke-signer <reference>")
  .description("locally block the signer of an installed plugin")
  .action(async (reference) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const policy = openDocumentVault(dir, passphrase).revokePluginSigner(reference);
    console.log(`Signer revoked. ${policy.revokedSigners.length} signer(s) are now blocked.`);
  });

plugins
  .command("restore-signer <key-id>")
  .description("remove a signer key ID from this vault's local revocation list")
  .action(async (keyId) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const policy = openDocumentVault(dir, passphrase).restorePluginSigner(keyId);
    console.log(`Signer restored. ${policy.revokedSigners.length} signer(s) remain blocked.`);
  });

plugins
  .command("install <manifest> <source>")
  .description("install a plugin from its manifest (.json) and source (.js); it stays off until enabled")
  .option("--enable", "turn it on immediately")
  .action(async (manifestPath, sourcePath, opts) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const installed = openDocumentVault(dir, passphrase).installPlugin({
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
    const changed = openDocumentVault(dir, passphrase).setPluginEnabled(reference, true);
    console.log(`${changed.name} is enabled.`);
  });

plugins
  .command("disable <reference>")
  .description("turn one installed plugin off")
  .action(async (reference) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const changed = openDocumentVault(dir, passphrase).setPluginEnabled(reference, false);
    console.log(`${changed.name} is disabled.`);
  });

plugins
  .command("remove <reference>")
  .description("remove one plugin and the settings it owns")
  .action(async (reference) => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const removed = openDocumentVault(dir, passphrase).removePlugin(reference);
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
  .requiredOption("--agent <name>", "owner-configured grant identity for this MCP process")
  .action(async (opts) => {
    const dir = program.opts().vault;
    if (!grantsExist(dir)) {
      throw new Error(
        "MCP access is disabled until you create a policy with 'sbrain grant add <agent> --scope ...'."
      );
    }
    await startMcpServer(dir, opts.agent);
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
    console.log("If the old passphrase leaked, run 'vbrain rekey' once it ships.");
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

program
  .command("format")
  .description("print the on-disk format version and the artifact version matrix")
  .action(() => {
    console.log(
      JSON.stringify({ formatVersion: VAULT_FORMAT_VERSION, artifacts: FORMAT_COMPATIBILITY }, null, 2),
    );
  });

program.parseAsync(process.argv).catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Error: ${message}`);
  process.exitCode = 1;
});
