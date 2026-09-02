import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { buildSchema, readSchema, searchSchema, filterNotesByDate } from "./schema.js";
import { loadVaultFile, storeNote } from "./store.js";
import { appendAudit, clearAuditKeyCache } from "./audit.js";
import {
  consumeApproval,
  decide,
  filterDiscoverable,
  grantsExist,
  loadGrants,
  normalizeAgent,
  requestConfirmation,
  type GrantAction,
  type GrantFile,
} from "./grants.js";
import { redactValue, type RedactionLevel } from "./redaction.js";

/**
 * What a governed resolution produced. Split out from the tool handler so the
 * enforcement path — deny, hold for approval, mask — can be exercised directly
 * in tests rather than only through a live MCP client.
 */
export type ResolveOutcome =
  | { kind: "denied"; message: string }
  | { kind: "pending"; message: string; requestId: string }
  | { kind: "missing"; message: string }
  | { kind: "value"; message: string; redaction: RedactionLevel };

export function resolveForAgent(
  vaultDir: string,
  agent: string,
  file: string,
  key: string,
  passphrase: string
): ResolveOutcome {
  const decision = decide(loadGrants(vaultDir, passphrase), { agent, action: "resolve", file, key });
  if (!decision.allowed) {
    appendAudit(vaultDir, { actor: "mcp-agent", file, key, agent, outcome: "denied" }, passphrase);
    return { kind: "denied", message: decision.reason };
  }
  if (decision.requiresConfirmation && !consumeApproval(vaultDir, { agent, file, key }, passphrase)) {
    const request = requestConfirmation(vaultDir, { agent, file, key }, passphrase);
    appendAudit(
      vaultDir,
      { actor: "mcp-agent", file, key, agent, grant: decision.grantId, outcome: "pending" },
      passphrase
    );
    return {
      kind: "pending",
      requestId: request.id,
      message: [
        "This grant holds each resolution for the vault owner's approval.",
        `Ask them to run:  sbrain grant approve ${request.id.slice(0, 8)}`,
        "Then call resolve_key again. The approval is single-use and expires shortly.",
      ].join("\n"),
    };
  }
  const entry = loadVaultFile(vaultDir, file, passphrase).find((candidate) => candidate.key === key);
  if (!entry) {
    return { kind: "missing", message: `Not found: ${key} in ${file}` };
  }
  appendAudit(
    vaultDir,
    {
      actor: "mcp-agent",
      file,
      key,
      agent,
      grant: decision.grantId,
      redaction: decision.redact,
      outcome: "allowed",
    },
    passphrase
  );
  const value = redactValue(entry.value, decision.redact);
  return {
    kind: "value",
    redaction: decision.redact,
    message:
      decision.redact === "none"
        ? value
        : `${value}\n\n[This value was masked by the vault's grant policy (${decision.redact}). Ask the person directly if you need the whole thing.]`,
  };
}

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
 *   4. When the vault carries a grant policy, the agent's identity decides
 *      which keys it can even see, whether each resolution needs the owner's
 *      approval, and how much of a value comes back — see `grants.ts`.
 *
 * Redaction narrows exposure; it does not create a boundary. If you need a
 * true zero-exposure path, use `sbrain get` (Mode 1) instead — that command
 * never invokes an LLM at all.
 */
export async function startMcpServer(vaultDir: string, configuredAgent: string): Promise<void> {
  const passphrase = process.env.SBRAIN_PASSPHRASE;
  if (!passphrase) {
    console.error("SBRAIN_PASSPHRASE must be set to run the MCP server (no interactive prompt in agent contexts).");
    process.exit(1);
  }

  if (!grantsExist(vaultDir)) {
    throw new Error(
      "MCP access is disabled until the vault owner creates a grant with 'sbrain grant add'."
    );
  }

  // The owner pins this label in the MCP process command line. It is not read
  // from client-controlled request data or a freely inherited environment tag.
  let agent: string;
  try {
    agent = normalizeAgent(configuredAgent);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  }

  const initialPolicy = loadGrants(vaultDir, passphrase);
  if (!initialPolicy?.grants.some((grant) => grant.agent === agent)) {
    throw new Error(`No grant is configured for MCP agent "${agent}".`);
  }

  // Reloaded per call rather than cached, so `sbrain grant revoke` takes effect
  // on the agent's very next request instead of at its next restart.
  const policy = (): GrantFile | null => loadGrants(vaultDir, passphrase);

  function permit(action: GrantAction, file?: string, key?: string) {
    return decide(policy(), { agent, action, file, key });
  }

  function text(body: string, isError = false) {
    return { content: [{ type: "text" as const, text: body }], ...(isError ? { isError: true } : {}) };
  }

  const server = new McpServer({ name: "secondbrain-vault", version: "0.2.0" });

  server.tool(
    "list_keys",
    "List every available key name and its non-sensitive description across the vault. Contains NO values. Always call this before resolve_key.",
    {},
    async () => {
      const schema = readSchema(vaultDir, passphrase);
      if (!schema) {
        return text("No schema found. Ask the user to run 'sbrain index'.");
      }
      const grants = policy();
      const visible: Record<string, unknown[]> = {};
      for (const [file, entries] of Object.entries(schema.files)) {
        const allowed = filterDiscoverable(grants, agent, file, entries);
        if (allowed.length) visible[file] = allowed;
      }
      if (grants && !Object.keys(visible).length) {
        return text(
          `No key in this vault is discoverable by "${agent}". Ask the vault owner to run: sbrain grant add.`,
          true
        );
      }
      return text(JSON.stringify(visible, null, 2));
    }
  );

  server.tool(
    "find_key",
    "Fuzzy-search key names and descriptions for a query. Contains NO values. Use this to locate the right key before resolve_key.",
    { query: z.string().describe("what you're looking for, e.g. 'next doctor appointment'") },
    async ({ query }) => {
      const schema = readSchema(vaultDir, passphrase);
      if (!schema) {
        return text("No schema found. Ask the user to run 'sbrain index'.");
      }
      const grants = policy();
      const hits = searchSchema(schema, query).filter(
        (hit) => decide(grants, { agent, action: "discover", file: hit.file, key: hit.key }).allowed
      );
      return text(JSON.stringify(hits, null, 2));
    }
  );

  server.tool(
    "resolve_key",
    "Decrypt and return the value for exactly one key in one file. This call is logged to the vault's audit trail, and a grant policy may narrow or mask what comes back. Only call this for a key you already identified via list_keys/find_key — never guess a key name.",
    {
      file: z.string().describe("vault file name without extension, e.g. 'health'"),
      key: z.string().describe("exact key name, e.g. 'DOCTOR_NEXT_APPOINTMENT'"),
    },
    async ({ file, key }) => {
      const outcome = resolveForAgent(vaultDir, agent, file, key, passphrase);
      return text(outcome.message, outcome.kind !== "value");
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
      "because agents may discover it after the encrypted catalog is unlocked.",
      "Never put the sensitive content itself in `desc`.",
    ].join("\n"),
    {
      category: z.string().describe("vault file/category, e.g. 'health', 'finance', 'work'"),
      value: z.string().describe("the actual content to store, encrypted at rest"),
      desc: z.string().describe("short, non-sensitive tag/description for the encrypted catalog"),
      key: z
        .string()
        .optional()
        .describe("explicit key for a fact (e.g. 'IBAN'); omit for a freeform journal note"),
    },
    async ({ category, value, desc, key }) => {
      const decision = permit("store", category, key);
      if (!decision.allowed) {
        appendAudit(
          vaultDir,
          { actor: "mcp-agent-write", file: category, key: key ?? "", agent, outcome: "denied" },
          passphrase
        );
        return text(decision.reason, true);
      }
      const usedKey = storeNote(vaultDir, category, value, desc, passphrase, key);
      buildSchema(vaultDir, passphrase); // keep the encrypted catalog current
      appendAudit(
        vaultDir,
        {
          actor: "mcp-agent-write",
          file: category,
          key: usedKey,
          agent,
          grant: decision.grantId,
          outcome: "allowed",
        },
        passphrase
      );
      return text(`Stored under ${category}.${usedKey} (encrypted, indexed, audited).`);
    }
  );

  server.tool(
    "find_notes_in_range",
    "Browse freeform journal notes by date range after unlocking the encrypted, value-free catalog. Returns keys + tags + timestamps, not content. Follow up with resolve_key for any entry you actually need to read.",
    {
      category: z.string().optional().describe("limit to one category/file, e.g. 'health'"),
      from: z.string().optional().describe("ISO date, inclusive lower bound"),
      to: z.string().optional().describe("ISO date, inclusive upper bound"),
    },
    async ({ category, from, to }) => {
      const schema = readSchema(vaultDir, passphrase);
      if (!schema) {
        return text("No schema found. Call store_note first, or run 'sbrain index'.");
      }
      const grants = policy();
      const hits = filterNotesByDate(schema, { file: category, from, to }).filter(
        (hit) => decide(grants, { agent, action: "discover", file: hit.file, key: hit.key }).allowed
      );
      return text(JSON.stringify(hits, null, 2));
    }
  );

  const transport = new StdioServerTransport();
  try {
    await server.connect(transport);
  } finally {
    clearAuditKeyCache(vaultDir);
  }
}
