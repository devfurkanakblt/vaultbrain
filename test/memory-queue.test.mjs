import assert from "node:assert/strict";
import test from "node:test";
import { MemoryPointerQueue } from "../dist/memory/index.js";

const hook = { version: 1, event: "Stop", sessionId: "synthetic-session", turnId: "synthetic-turn", transcriptPath: "C:\\synthetic\\rollout.jsonl", createdAt: "2026-09-05T00:00:00.000Z" };

test("pointer queue is idempotent, expires, and never accepts content", () => {
  const queue = new MemoryPointerQueue();
  const first = queue.enqueue(hook, new Date("2026-09-05T00:00:00.000Z"));
  assert.equal(queue.enqueue({ ...hook, event: "SessionEnd" }).id, first.id);
  assert.equal(queue.status().pending, 1);
  assert.throws(() => queue.enqueue({ ...hook, text: "password=synthetic" }), /content|secret/i);
  assert.equal(queue.claim(new Date("2026-09-13T00:00:00.000Z")).length, 0);
  assert.equal(queue.status().expired, 1);
});

test("completed deliveries cannot re-enter the queue and returned references cannot mutate it", () => {
  const queue = new MemoryPointerQueue();
  const entry = queue.enqueue(hook);
  entry.payload.sessionId = "tampered";
  const [claimed] = queue.claim();
  assert.equal(claimed.payload.sessionId, hook.sessionId);
  queue.complete(entry.id);
  assert.equal(queue.enqueue(hook).state, "done");
  assert.equal(queue.claim(new Date("2099-01-01")).length, 0);
  assert.equal(queue.status().done, 1);
});
