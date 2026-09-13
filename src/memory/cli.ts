import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Command } from "commander";
import { callMemoryNative } from "./client.js";
import { startMemoryMcpServer } from "./mcp.js";
import { installMemoryConfig, removeMemoryConfig } from "./setup.js";
import { parseHookPayload } from "./protocol.js";

export function registerMemoryCommands(program: Command): void {
  const memory = program.command("memory").description("Explicitly paired, unlocked desktop memory (experimental)");
  const configDefault = path.join(process.env.CODEX_HOME ?? path.join(os.homedir(), ".codex"), "config.toml");
  memory.command("setup").requiredOption("--client <client>", "supported client: codex")
    .requiredOption("--native-executable <path>", "owner-selected desktop executable")
    .option("--config <path>", "client configuration", configDefault)
    .action(async (options) => {
      if (options.client !== "codex") throw new Error("Unsupported memory client.");
      const status = await callMemoryNative(options.nativeExecutable, "memory_status") as { paired?: boolean };
      if (!status.paired) throw new Error("Pair this client in the unlocked desktop Memory panel before setup.");
      installMemoryConfig({ configPath: path.resolve(options.config), nativeExecutable: options.nativeExecutable,
        nodeExecutable: process.execPath, cliPath: fileURLToPath(new URL("../cli.js", import.meta.url)) });
      console.log("Memory MCP registered. Automatic capture remains disabled until worker and hook compatibility is accepted.");
    });
  for (const name of ["status", "doctor"] as const) {
    memory.command(name).requiredOption("--native-executable <path>", "owner-selected desktop executable").option("--json", "JSON output")
      .action(async (options) => {
        const result = await callMemoryNative(options.nativeExecutable, "memory_status");
        console.log(JSON.stringify(name === "doctor" ? { native: result, capture: "disabled", reason: "Live worker/hook compatibility has not been accepted." } : result));
      });
  }
  memory.command("disconnect").requiredOption("--native-executable <path>", "owner-selected desktop executable")
    .option("--config <path>", "client configuration", configDefault).action(async (options) => {
      // Revoke first. A config conflict must never leave a supposedly disconnected credential active.
      await callMemoryNative(options.nativeExecutable, "memory_disconnect");
      removeMemoryConfig(path.resolve(options.config));
      console.log("Memory disconnected.");
    });
  memory.command("mcp").requiredOption("--native-executable <path>", "paired desktop executable")
    .action(async (options) => startMemoryMcpServer(options.nativeExecutable));
  memory.command("hook").requiredOption("--native-executable <path>", "paired desktop executable")
    .action(async (options) => {
      const chunks: Buffer[] = [];
      let bytes = 0;
      try {
        for await (const chunk of process.stdin) {
          const buffer = Buffer.from(chunk);
          bytes += buffer.length;
          if (bytes > 64 * 1024) throw new Error("Memory hook exceeds its input limit.");
          chunks.push(buffer);
        }
        const payload = parseHookPayload(JSON.parse(Buffer.concat(chunks).toString("utf8")));
        const result = await callMemoryNative(options.nativeExecutable, "memory_enqueue", { ...payload }) as { accepted?: unknown };
        // A hook caller may advance its own cursor only after native storage
        // confirms the encrypted reference was accepted. A stale
        // pre-enrollment pointer is deliberately not acknowledged.
        if (result.accepted !== true) throw new Error("Memory source was not durably accepted.");
      } catch {
        process.exitCode = 1;
        fs.writeSync(2, "Memory capture was not queued; inspect desktop status.\n");
      } finally { for (const chunk of chunks) chunk.fill(0); }
    });
}
