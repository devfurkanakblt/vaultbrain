#!/usr/bin/env node
import { Command } from "commander";
import fs from "node:fs";
import path from "node:path";
import {
  DEFAULT_VAULT_DIR,
  listVaultFiles,
  loadVaultFile,
  migrateVault,
  storeNote,
  upsertEntry,
  vaultFileEnvelopeVersion,
} from "./store.js";
import { buildSchema, readSchema, searchSchema, filterNotesByDate } from "./schema.js";
import { appendAudit, readAudit, verifyAudit } from "./audit.js";
import { getPassphrase, readSecret } from "./passphrase.js";
import { forgetPassphrase, keychain, recallPassphrase, rememberPassphrase } from "./keychain.js";
import { startMcpServer } from "./mcp-server.js";
import { DocumentVault, type PropertyValue } from "./documents.js";
import { writeFileAtomic } from "./fs-safe.js";
import {
  createFromTemplate,
  openDailyNote,
  parseLocalDate,
  type TemplateVariables,
} from "./templates.js";

const program = new Command();

program
  .name("sbrain")
  .description(
    "secondbrain-vault — an .env-style, least-exposure personal data store for the AI age."
  )
  .option("--vault <dir>", "vault directory", DEFAULT_VAULT_DIR);

program
  .command("init")
  .description("create an empty vault directory")
  .action(async () => {
    const dir = program.opts().vault;
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    console.log(`Vault initialized at ${dir}`);
    console.log(`Set SBRAIN_PASSPHRASE before running add/get/index/mcp.`);
  });

program
  .command("add <file> <keyval>")
  .description('add or update a key, e.g. sbrain add health DOCTOR_NEXT_APPOINTMENT="2026-09-15"')
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
    "dev/testing helper for the freeform journal path (Mode 2's real entry point is the MCP store_note tool, not this)"
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
      console.log("No schema.json yet — run 'sbrain index' first.");
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
      console.log("No schema.json yet — run 'sbrain index' first.");
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
      console.log("No schema.json yet — run 'sbrain index' first.");
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

const docs = program
  .command("docs")
  .description("encrypted Markdown documents, search and knowledge links");

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
    const note = new DocumentVault(dir, passphrase).put({
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
    const note = new DocumentVault(dir, passphrase).rename(reference, newPath, opts.title);
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
    const note = new DocumentVault(dir, passphrase).getRevision(
      reference,
      Number.parseInt(number, 10)
    );
    appendAudit(dir, { actor: "cli-direct", file: "documents", key: note.id }, passphrase);
    process.stdout.write(note.body + "\n");
  });

docs
  .command("restore <reference> <number>")
  .description("restore a historical revision as a new current revision")
  .action(async (reference, number) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const note = new DocumentVault(dir, passphrase).restore(
      reference,
      Number.parseInt(number, 10)
    );
    appendAudit(dir, { actor: "cli-direct-write", file: "documents", key: note.id }, passphrase);
    console.log(`Restored ${note.path} as revision ${note.revision}.`);
  });

docs
  .command("import <path> <source>")
  .description("import a Markdown file into encrypted document storage")
  .action(async (notePath, source) => {
    const passphrase = await getPassphrase({ vaultDir: program.opts().vault });
    const dir = program.opts().vault;
    const note = new DocumentVault(dir, passphrase).importMarkdown(
      notePath,
      fs.readFileSync(source, "utf8")
    );
    appendAudit(dir, { actor: "cli-direct-write", file: "documents", key: note.id }, passphrase);
    console.log(`Imported ${note.path} (${note.id}).`);
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
    const removed = new DocumentVault(dir, passphrase).remove(reference);
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
    const info = new DocumentVault(dir, passphrase).putAttachment(
      fs.readFileSync(source),
      opts.name ?? path.basename(source),
      opts.mime
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
    const info = new DocumentVault(dir, passphrase).removeAttachment(id);
    appendAudit(dir, { actor: "cli-direct-write", file: "attachments", key: id }, passphrase);
    console.log(`Removed ${info.filename} (${id}).`);
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
    const note = createFromTemplate(new DocumentVault(dir, passphrase), template, notePath, {
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
    const result = openDailyNote(new DocumentVault(dir, passphrase), parseLocalDate(date), {
      folder: opts.folder,
      filenameFormat: opts.format,
      template: opts.template,
      tags: opts.tag,
    });
    if (result.created) {
      appendAudit(
        dir,
        { actor: "cli-direct-write", file: "documents", key: result.note.id },
        passphrase
      );
    }
    console.log(`${result.created ? "Created" : "Opened"} ${result.note.path} (${result.note.id}).`);
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
        `(${verification.signedEntries} signed, ${verification.legacyEntries} legacy)`
    );
    if (verification.error) console.log(`  ${verification.error}`);
    for (const entry of entries) {
      console.log(`${entry.timestamp}  ${entry.actor}  ${entry.file}.${entry.key}`);
    }
    if (!verification.valid) process.exitCode = 2;
  });

program
  .command("mcp")
  .description("MODE 2 — start the MCP server for AI-agent-assisted, scoped, audited access")
  .action(async () => {
    const dir = program.opts().vault;
    await startMcpServer(dir);
  });

program
  .command("migrate")
  .description("rewrite key-value vault files in the current encrypted envelope format")
  .action(async () => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const reports = migrateVault(dir, passphrase);
    if (reports.length === 0) {
      console.log("No key-value files found; nothing to migrate.");
      return;
    }
    for (const report of reports) {
      console.log(
        report.migrated
          ? `${report.name}: envelope v${report.from} -> v${report.to}`
          : `${report.name}: already envelope v${report.to}`
      );
    }
    console.log(`${reports.filter((report) => report.migrated).length} of ${reports.length} file(s) migrated.`);
  });

program
  .command("unlock")
  .description("verify the passphrase for this vault, optionally remembering it in the OS credential store")
  .option("--remember", "store the passphrase in the OS credential store for this vault")
  .action(async (opts) => {
    const dir = program.opts().vault;
    const passphrase = process.env.SBRAIN_PASSPHRASE ?? (await readSecret("Vault passphrase: "));
    if (!passphrase) {
      console.error("A passphrase is required.");
      process.exit(1);
    }
    // Proves the passphrase against the real vault before anything is stored.
    new DocumentVault(dir, passphrase).list();
    console.log(`Unlocked ${dir}.`);
    if (opts.remember) {
      const backend = rememberPassphrase(dir, passphrase);
      console.log(`Passphrase remembered in the OS credential store (${backend}). Run 'sbrain lock' to forget it.`);
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
        : `Nothing to forget: no remembered passphrase for ${dir}.`
    );
  });

program
  .command("keychain-status")
  .description("show which OS credential store is available and whether this vault has a remembered passphrase")
  .action(async () => {
    const dir = program.opts().vault;
    const backend = keychain();
    console.log(`Credential store: ${backend.name}${backend.available() ? "" : " (unavailable)"}`);
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
