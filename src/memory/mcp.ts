import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { callMemoryNative } from "./client.js";

const MAX_MCP_RESPONSE_BYTES = 64 * 1024;

/** Keep MCP output bounded even when JSON escaping expands a native reply. */
export function formatMemoryMcpResult(result: unknown): string {
  let rendered: string;
  try { rendered = JSON.stringify({ untrusted: true, result }) ?? ""; }
  catch { return JSON.stringify({ untrusted: true, message: "Memory result could not be rendered." }); }
  if (Buffer.byteLength(rendered, "utf8") > MAX_MCP_RESPONSE_BYTES) {
    return JSON.stringify({ untrusted: true, truncated: true, message: "Memory result exceeded the MCP output limit." });
  }
  return rendered;
}

export function createMemoryMcpServer(executable: string): McpServer {
  const server = new McpServer({ name: "vaultbrain-memory", version: "1.0.0" });
  const invoke = async (method: string, params: Record<string, unknown>) => {
    try {
      const result = await callMemoryNative(executable, method, params);
      return { content: [{ type: "text" as const, text: formatMemoryMcpResult(result) }] };
    } catch {
      return { isError: true, content: [{ type: "text" as const, text: "Memory unavailable or access refused. Open the desktop to inspect pairing and grants." }] };
    }
  };
  server.tool("memory_bootstrap", "Bounded untrusted memory context from the paired unlocked vault.", {}, () => invoke("memory_bootstrap", {}));
  server.tool("memory_status", "Memory connection and queue status; no vault credentials.", {}, () => invoke("memory_status", {}));
  server.tool("memory_search", "Search permitted memory notes.", { query: z.string().min(1).max(256), limit: z.number().int().min(1).max(100).optional() }, (params) => invoke("memory_search", params));
  server.tool("memory_read", "Read a permitted memory note.", { id: z.string().uuid() }, (params) => invoke("memory_read", params));
  server.tool("memory_remember", "Submit a memory candidate for owner review; model assertions are untrusted.", {
    candidate: z.object({
      kind: z.enum(["preference", "fact", "project", "decision", "goal", "task", "person", "concept"]),
      title: z.string().min(1).max(400), body: z.string().min(1).max(16000),
      evidence: z.array(z.object({ messageId: z.string().min(1).max(240), quote: z.string().min(1).max(2000) }).strict()).min(1).max(8),
      sourceKind: z.enum(["user-stated", "inference"]), sensitive: z.boolean(), links: z.array(z.string().max(240)).max(16),
      targetId: z.string().uuid().optional(), baseRevision: z.number().int().positive().optional(),
    }).strict(),
  }, (params) => invoke("memory_remember", params));
  server.tool("memory_forget", "Request forgetting a memory; owner policy determines approval.", { id: z.string().uuid() }, (params) => invoke("memory_forget", params));
  return server;
}

export async function startMemoryMcpServer(executable: string): Promise<void> {
  await createMemoryMcpServer(executable).connect(new StdioServerTransport());
}
