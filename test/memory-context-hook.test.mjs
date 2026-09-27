import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

test("memory reminder emits supported context without copying the prompt", () => {
  const result = spawnSync(process.execPath, ["scripts/memory-context-hook.mjs"], {
    input: JSON.stringify({ hook_event_name: "UserPromptSubmit", prompt: "private-test-content" }),
    encoding: "utf8",
  });
  assert.equal(result.status, 0);
  const output = JSON.parse(result.stdout);
  assert.equal(output.hookSpecificOutput.hookEventName, "UserPromptSubmit");
  assert.match(output.hookSpecificOutput.additionalContext, /memory_remember/u);
  assert.match(output.hookSpecificOutput.additionalContext, /owner review/u);
  assert.ok(!result.stdout.includes("private-test-content"));
});

test("memory reminder ignores other events and malformed input", () => {
  for (const input of ['{"hook_event_name":"Stop"}', 'not-json']) {
    const result = spawnSync(process.execPath, ["scripts/memory-context-hook.mjs"], { input, encoding: "utf8" });
    assert.equal(result.status, 0);
    assert.equal(result.stdout, "");
  }
});
