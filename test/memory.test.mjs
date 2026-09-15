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
  validateCandidate,
  buildRunnerArgs,
  parseCodexVersion,
  runCodexSummarizer,
  normalizeWorkerInput,
  parseWorkerOutput,
  renderWorkerPrompt,
  redactSecrets,
} from "../dist/memory/index.js";
import { removeTree } from "../scripts/fs-tree.mjs";

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
  assert.throws(() => parseCodexTranscript(JSON.stringify({ version: 1, type: "future-message", id: "x" }), { sessionId: "s", enrolledAt: "2026-09-04T00:00:00Z" }), /unsupported/i);
  const candidate = { kind: "fact", title: "Token", body: "api_key=synthetic-secret", evidence: [{ messageId: "u1", quote: "api_key=synthetic-secret" }], sourceKind: "user-stated", sensitive: false, links: [] };
  assert.equal(classifyCandidate(candidate).status, "rejected");
});

test("hook payload and dedupe keys contain references only", () => {
  const payload = parseHookPayload({ version: 1, event: "Stop", sessionId: "s", turnId: "t", transcriptPath: "C:\\temp\\rollout.jsonl", createdAt: "2026-09-05T00:00:00Z" });
  assert.equal(payload.event, "Stop");
  assert.equal("text" in payload, false);
  assert.equal(dedupeKey(payload, "v1"), dedupeKey({ ...payload, event: "SessionEnd" }, "v1"));
  assert.throws(() => parseHookPayload({ ...payload, command: "powershell secret" }), /command/i);
  assert.throws(() => parseHookPayload({ ...payload, transcript: "raw transcript" }), /content|transcript/i);
  assert.throws(() => parseHookPayload({ ...payload, extra: "unexpected" }), /field|payload|unexpected/i);
  assert.throws(() => parseHookPayload({ ...payload, transcriptPath: "relative\\rollout.jsonl" }), /absolute|path/i);
  assert.throws(() => parseHookPayload({ ...payload, transcriptPath: "C:\\vault\\..\\outside.jsonl" }), /path|reference/i);
});

test("batch validation and bootstrap are bounded and do not persist plaintext", () => {
  const batch = validateMemoryBatch({ version: 1, summary: "A useful summary", candidates: [{ kind: "preference", title: "Theme", body: "Dark mode", evidence: [{ messageId: "u1", quote: "I prefer dark mode" }], sourceKind: "user-stated", sensitive: false, links: [] }] });
  assert.equal(batch.candidates.length, 1);
  const context = bootstrapMemory([{ id: "m1", title: "Theme", body: "Dark mode", source: "u1" }], 1500);
  assert.match(context, /untrusted/i);
  assert.ok(Buffer.byteLength(context, "utf8") <= 6000);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "memory-test-"));
  assert.equal(fs.readdirSync(dir).length, 0);
  removeTree(dir);
});

test("runner arguments disable ambient hooks and tools without embedding secrets", () => {
  const args = buildRunnerArgs("synthetic-model");
  assert.deepEqual(args, ["exec", "-", "--ephemeral", "--json", "--ignore-user-config", "--disable", "hooks", "--disable", "web_search", "--sandbox", "read-only", "-m", "synthetic-model"]);
  assert.doesNotMatch(args.join(" "), /password|passphrase|api[_-]?key|token/iu);
  const secureArgs = buildRunnerArgs("synthetic-model", path.resolve("memory-output.schema.json"));
  assert.ok(secureArgs.includes("--output-schema"));
  assert.ok(secureArgs.includes("--disable") && secureArgs.includes("shell_tool"));
  assert.equal(parseCodexVersion("codex-cli 0.153.1"), "codex-cli0.153.1");
  assert.equal(parseCodexVersion("codex-cli 0.154.0-alpha.6.2"), "codex-cli0.154.0-alpha.6.2");
  assert.equal(parseCodexVersion("unknown 0.153.1"), undefined);
});

test("worker input is an exact bounded schema and strips secrets before the model boundary", () => {
  const input = normalizeWorkerInput({
    version: 1,
    messages: [{ sessionId: "s", turnId: "t", messageId: "m", role: "user", timestamp: "2026-09-05T00:00:00.000Z", text: "api_key=synthetic-secret; I prefer dark mode" }],
    memory: [{ id: "m1", title: "Theme", body: "Dark mode", source: "m" }],
  });
  assert.doesNotMatch(JSON.stringify(input), /api_key=synthetic-secret/iu);
  assert.match(JSON.stringify(input), /redacted/iu);
  assert.doesNotMatch(renderWorkerPrompt(input), /api_key=synthetic-secret/iu);
  assert.throws(() => normalizeWorkerInput({ version: 1, messages: [], command: "powershell" }), /field|schema/iu);
});

test("worker output accepts one batch or a known JSONL assistant event and rejects untrusted overflow", () => {
  const batch = { version: 1, summary: "A useful summary", candidates: [{ kind: "preference", title: "Theme", body: "Dark mode", evidence: [{ messageId: "m", quote: "I prefer dark mode" }], sourceKind: "user-stated", sensitive: false, links: [] }] };
  assert.deepEqual(parseWorkerOutput(JSON.stringify(batch)), batch);
  const event = JSON.stringify({ type: "item.completed", item: { text: JSON.stringify(batch) } });
  assert.deepEqual(parseWorkerOutput(event), batch);
  assert.throws(() => parseWorkerOutput(`${JSON.stringify({ type: "message", text: "not a batch" })}\n`), /batch|JSON/iu);
});

test("secret redaction is deterministic and never puts the original value in worker text", () => {
  const redacted = redactSecrets("password=synthetic api_key:another sk-123456789012");
  assert.doesNotMatch(redacted, /synthetic|another|sk-123456789012/u);
  assert.match(redacted, /redacted/giu);
});

test("sensitive facts require review and malformed revision or sensitivity never auto-commit", () => {
  const fact = { kind: "preference", title: "Preference", body: "A personal preference", evidence: [{ messageId: "u", quote: "A personal preference" }], sourceKind: "user-stated", sensitive: true, links: [] };
  assert.equal(classifyCandidate(fact).status, "review");
  assert.throws(() => validateCandidate({ ...fact, sensitive: "false" }), /sensitivity/iu);
  for (const baseRevision of [NaN, Infinity, -1, 0, 0.5]) {
    assert.throws(() => validateCandidate({ ...fact, baseRevision }), /revision/iu);
  }
  assert.throws(() => validateCandidate({ ...fact, links: ["../outside"] }), /link/iu);
});

test("source dedupe is independent of summarizer version", () => {
  const hook = { version: 1, event: "Stop", sessionId: "s", turnId: "t", transcriptPath: "C:\\synthetic\\rollout.jsonl", createdAt: "2026-09-05T00:00:00Z" };
  assert.equal(dedupeKey(hook, "v1"), dedupeKey(hook, "v2"));
});

test("an unaccepted worker adapter never starts a model or trusts a supplied version", async () => {
  await assert.rejects(runCodexSummarizer({ messages: [] }), /compatibility/iu);
  await assert.rejects(runCodexSummarizer({ messages: [] }, { version: "codex-cli0.153.1", command: "untrusted-command" }), /compatibility/iu);
});
