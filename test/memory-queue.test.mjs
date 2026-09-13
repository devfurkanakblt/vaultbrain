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

test("a claimed pointer is delivered once and failed work retries only after backoff", () => {
  const queue = new MemoryPointerQueue();
  const start = new Date("2026-09-05T00:00:00.000Z");
  const entry = queue.enqueue({ ...hook, turnId: "retry-turn" }, start);

  assert.equal(queue.claim(start).length, 1);
  assert.equal(queue.claim(start).length, 0);
  assert.equal(queue.status().processing, 1);

  queue.fail(entry.id, start);
  assert.equal(queue.status().processing, 0);
  assert.equal(queue.claim(new Date(start.getTime() + 999)).length, 0);
  assert.equal(queue.claim(new Date(start.getTime() + 1000)).length, 1);
  queue.complete(entry.id);
  assert.equal(queue.status().done, 1);
  assert.doesNotThrow(() => queue.complete(entry.id));
});

test("terminal failures stay bounded and do not become an unbounded retry loop", () => {
  const queue = new MemoryPointerQueue();
  const start = new Date("2026-09-05T00:00:00.000Z");
  const entry = queue.enqueue({ ...hook, turnId: "terminal-turn" }, start);
  let now = start;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const [claimed] = queue.claim(now);
    assert.equal(claimed.attempts, attempt + 1);
    queue.fail(entry.id, now);
    now = new Date(now.getTime() + 60_000);
  }
  assert.equal(queue.claim(now).length, 0);
  assert.equal(queue.status().failed, 1);
});
