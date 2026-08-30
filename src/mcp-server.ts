import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { buildSchema, readSchema, searchSchema, filterNotesByDate } from "./schema.js";
import { loadVaultFile, storeNote } from "./store.js";
import { appendAudit } from "./audit.js";

/**
 * IMPORTANT (read before wiring this into an agent):
 * Under the current MCP spec, whatever `resolve_key` returns DOES flow back
 * into the calling model's context — that's how MCP tool results work. This
 * server does not (and cannot, as a standard MCP server) prevent the model
 * from "seeing" the resolved value.
 *
 * What it DOES give you, compared to dropping a whole Obsidian vault into
 * context:
 *   1. The agent only ever requests the exact scalar it needs — never the
 *      surrounding document, never the rest of the vault.
 *   2. The agent's *discovery* step (list_keys / find_key) only ever touches
 *      key names + descriptions — never values — so browsing/searching is
 *      zero-exposure by construction.
 *   3. Every resolution is appended to an audit log the user can review.
 *
 * If you need a true zero-exposure path, use `sbrain get` (Mode 1) instead —
 * that command never invokes an LLM at all.
 */
export async function startMcpServer(vaultDir: string): Promise<void> {
  const passphrase = process.env.SBRAIN_PASSPHRASE;
  if (!passphrase) {
    console.error("SBRAIN_PASSPHRASE must be set to run the MCP server (no interactive prompt in agent contexts).");
    process.exit(1);
  }

  const server = new McpServer({ name: "secondbrain-vault", version: "0.2.0" });

  server.tool(
    "list_keys",
    "List every available key name and its non-sensitive description across the vault. Contains NO values. Always call this before resolve_key.",
    {},
    async () => {
      const schema = readSchema(vaultDir);
      if (!schema) {
        return { content: [{ type: "text", text: "No schema found. Ask the user to run 'sbrain index'." }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(schema.files, null, 2) }] };
    }
  );

  server.tool(
    "find_key",
    "Fuzzy-search key names and descriptions for a query. Contains NO values. Use this to locate the right key before resolve_key.",
    { query: z.string().describe("what you're looking for, e.g. 'next doctor appointment'") },
    async ({ query }) => {
      const schema = readSchema(vaultDir);
      if (!schema) {
        return { content: [{ type: "text", text: "No schema found. Ask the user to run 'sbrain index'." }] };
      }
      const hits = searchSchema(schema, query);
      return { content: [{ type: "text", text: JSON.stringify(hits, null, 2) }] };
    }
  );

  server.tool(
    "resolve_key",
    "Decrypt and return the value for exactly one key in one file. This call is logged to the vault's audit trail. Only call this for a key you already identified via list_keys/find_key — never guess a key name.",
    {
      file: z.string().describe("vault file name without extension, e.g. 'health'"),
      key: z.string().describe("exact key name, e.g. 'DOCTOR_NEXT_APPOINTMENT'"),
    },
    async ({ file, key }) => {
      const entries = loadVaultFile(vaultDir, file, passphrase);
      const entry = entries.find((e) => e.key === key);
      if (!entry) {
        return { content: [{ type: "text", text: `Not found: ${key} in ${file}` }], isError: true };
      }
      appendAudit(vaultDir, { actor: "mcp-agent", file, key }, passphrase);
      return { content: [{ type: "text", text: entry.value }] };
    }
  );

  server.tool(
    "store_note",
    [
      "Save a fact or a freeform journal note to the vault, encrypted at rest.",
      "This is the PRIMARY way notes get captured: call it automatically whenever the user",
      "shares something worth remembering during conversation. Do NOT ask the user to type",
      "CLI commands themselves — you call this tool on their behalf.",
      "",
      "Two shapes:",
      "  - Fact: pass `key` explicitly (e.g. key='IBAN') to set/overwrite a named value.",
      "  - Journal note: omit `key` — a timestamp-based key is generated automatically,",
      "    so free-text notes (e.g. a doctor visit summary) get their own dated entry",
      "    instead of overwriting each other.",
      "",
      "`desc` must stay short and NON-sensitive (a category tag like 'doktor ziyareti'),",
      "because it is the one thing that ends up in the unencrypted, browsable index.",
      "Never put the sensitive content itself in `desc`.",
    ].join("\n"),
    {
      category: z.string().describe("vault file/category, e.g. 'health', 'finance', 'work'"),
      value: z.string().describe("the actual content to store, encrypted at rest"),
      desc: z.string().describe("short, non-sensitive tag/description for the safe index"),
      key: z
        .string()
        .optional()
        .describe("explicit key for a fact (e.g. 'IBAN'); omit for a freeform journal note"),
    },
    async ({ category, value, desc, key }) => {
      const usedKey = storeNote(vaultDir, category, value, desc, passphrase, key);
      buildSchema(vaultDir, passphrase); // keep the safe index current
      appendAudit(vaultDir, { actor: "mcp-agent-write", file: category, key: usedKey }, passphrase);
      return {
        content: [
          { type: "text", text: `Stored under ${category}.${usedKey} (encrypted, indexed, audited).` },
        ],
      };
    }
  );

  server.tool(
    "find_notes_in_range",
    "Browse freeform journal notes by date range using only the safe, value-free index — no decryption. Returns keys + tags + timestamps, not content. Follow up with resolve_key for any entry you actually need to read.",
    {
      category: z.string().optional().describe("limit to one category/file, e.g. 'health'"),
      from: z.string().optional().describe("ISO date, inclusive lower bound"),
      to: z.string().optional().describe("ISO date, inclusive upper bound"),
    },
    async ({ category, from, to }) => {
      const schema = readSchema(vaultDir);
      if (!schema) {
        return { content: [{ type: "text", text: "No schema found. Call store_note first, or run 'sbrain index'." }] };
      }
      const hits = filterNotesByDate(schema, { file: category, from, to });
      return { content: [{ type: "text", text: JSON.stringify(hits, null, 2) }] };
    }
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
}
