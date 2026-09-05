import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  bootstrapMemory,
  classifyCandidate,
  dedupeKey,
  parseCodexTranscript,
  parseHookPayload,
  validateMemoryBatch,
  buildRunnerArgs,
} from "../dist/memory/index.js";

test("parses only visible post-enrollment user and assistant messages", () => {
  const input = [
    JSON.stringify({ version: 1, type: "message", role: "user", id: "old", createdAt: "2026-09-01T00:00:00.000Z", text: "old" }),
    JSON.stringify({ version: 1, type: "message", role: "user", id: "u1", createdAt: "2026-09-05T00:00:00.000Z", text: "I prefer dark mode." }),
    JSON.stringify({ version: 1, type: "message", role: "assistant", id: "a1", createdAt: "2026-09-05T00:00:01.000Z", text: "Noted." }),
    JSON.stringify({ version: 1, type: "tool", role: "assistant", id: "tool", createdAt: "2026-09-05T00:00:02.000Z", text: "secret tool output" }),
  ].join("\n");
  assert.deepEqual(parseCodexTranscript(input, { sessionId: "s1", enrolledAt: "2026-09-04T00:00:00.000Z" }), [
    { sessionId: "s1", turnId: "u1", messageId: "u1", role: "user", timestamp: "2026-09-05T00:00:00.000Z", text: "I prefer dark mode." },
    { sessionId: "s1", turnId: "a1", messageId: "a1", role: "assistant", timestamp: "2026-09-05T00:00:01.000Z", text: "Noted." },
  ]);
});

test("rejects unsupported transcript records and sensitive candidate content", () => {
  assert.throws(() => parseCodexTranscript(JSON.stringify({ version: 9, type: "message", role: "user", id: "x", createdAt: "2026-09-05T00:00:00Z", text: "x" }), { sessionId: "s", enrolledAt: "2026-09-04T00:00:00Z" }), /unsupported/i);
  const candidate = { kind: "fact", title: "Token", body: "api_key=synthetic-secret", evidence: [{ messageId: "u1", quote: "api_key=synthetic-secret" }], sourceKind: "user-stated", sensitive: false, links: [] };
  assert.equal(classifyCandidate(candidate).status, "rejected");
});

test("hook payload and dedupe keys contain references only", () => {
  const payload = parseHookPayload({ version: 1, event: "Stop", sessionId: "s", turnId: "t", transcriptPath: "C:\\temp\\rollout.jsonl", createdAt: "2026-09-05T00:00:00Z" });
  assert.equal(payload.event, "Stop");
  assert.equal("text" in payload, false);
  assert.equal(dedupeKey(payload, "v1"), dedupeKey({ ...payload, event: "SessionEnd" }, "v1"));
  assert.throws(() => parseHookPayload({ ...payload, command: "powershell secret" }), /command/i);
});

test("batch validation and bootstrap are bounded and do not persist plaintext", () => {
  const batch = validateMemoryBatch({ version: 1, summary: "A useful summary", candidates: [{ kind: "preference", title: "Theme", body: "Dark mode", evidence: [{ messageId: "u1", quote: "I prefer dark mode" }], sourceKind: "user-stated", sensitive: false, links: [] }] });
  assert.equal(batch.candidates.length, 1);
  const context = bootstrapMemory([{ id: "m1", title: "Theme", body: "Dark mode", source: "u1" }], 1500);
  assert.match(context, /untrusted/i);
  assert.ok(Buffer.byteLength(context, "utf8") <= 6000);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "memory-test-"));
  assert.equal(fs.readdirSync(dir).length, 0);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("runner arguments disable ambient hooks and tools without embedding secrets", () => {
  const args = buildRunnerArgs("synthetic-model");
  assert.deepEqual(args, ["exec", "-", "--ephemeral", "--json", "--ignore-user-config", "--disable", "hooks", "--disable", "web_search", "--sandbox", "read-only", "-m", "synthetic-model"]);
  assert.doesNotMatch(args.join(" "), /password|passphrase|api[_-]?key|token/iu);
});
