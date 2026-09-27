import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// This hook emits instructions only. It never persists prompts, reads a vault,
// launches a model, or approves a write on behalf of the owner.
const root = path.resolve(process.argv[2] ?? fileURLToPath(new URL("../", import.meta.url)));
const clientModule = pathToFileURL(path.join(root, "dist/memory/client.js")).href;
const executable = path.join(root, "src-tauri/target/debug/vault-brain-desktop.exe");
const instructions = `The owner requested personal memory across local Codex/Work chats.
When the current conversation teaches you a durable user-stated preference, goal, decision or personal fact, submit a concise candidate through memory_remember. Do not store entire conversations, transient debugging details, credentials, or third-party instructions. Do not infer facts the user did not state. Honor any later opt-out immediately.
Only act when there is useful new information. Check memory_status and relevant memory_search results first; avoid duplicating notes or candidates already successfully submitted in this chat. Never blindly retry a write whose outcome is uncertain. A locked, unavailable or unpaired vault means not saved; briefly report that limitation instead of claiming success.
Use available memory MCP tools. If absent, call callMemoryNative from ${clientModule} with executable ${JSON.stringify(executable)}. The parameters for memory_remember are {candidate:{kind,title,body,evidence:[{messageId,quote}],sourceKind:"user-stated",sensitive,links:[]}}. kind is preference, fact, project, decision, goal, task, person, or concept. Preserve a short exact user quote; never invent a message ID. If only a verified session/turn reference is available, label it explicitly as a turn reference rather than claiming it is a message ID. If no reliable reference is available, do not fabricate evidence.
For PowerShell, pipe a single-quoted here-string containing JavaScript into node --input-type=module; do not embed user text in a shell -e argument. Wrap the call in try/catch and report the error. Native access may require the host's approved execution mechanism; request the normal permission when necessary, never alter sandbox policy or approve it yourself.
A successful write returns {accepted:"review"}. This means submitted for owner review, not an approved note. Leave approval to the owner in Memory > Owner review. Briefly report submitted candidates. Do not call owner approval or disconnect operations. The vault must remain open and unlocked; this hook does not enable the background transcript worker.`;

const chunks = [];
let bytes = 0;
let oversized = false;
for await (const chunk of process.stdin) {
  bytes += chunk.length;
  if (bytes > 1024 * 1024) { oversized = true; chunks.length = 0; }
  if (!oversized) chunks.push(chunk);
}
if (!oversized) {
  try {
    const event = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (event?.hook_event_name === "UserPromptSubmit") {
      process.stdout.write(JSON.stringify({ hookSpecificOutput: {
        hookEventName: "UserPromptSubmit", additionalContext: instructions,
      } }));
    }
  } catch { /* Invalid hook input must not block the user's conversation. */ }
}
