import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { DocumentVault } from "../dist/documents.js";
import { OllamaLocalModelAdapter } from "../dist/semantic.js";

const PASSPHRASE = "semantic-search-test-passphrase";

function tempVault() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "vault-brain-semantic-test-"));
}

class TopicEmbeddingAdapter {
  id = "test:topics:v1";
  calls = [];

  async embed(input) {
    this.calls.push([...input]);
    return input.map((text) => {
      const normalized = text.toLowerCase();
      if (/automobile|repair|vehicle|engine|garage|mechanic/u.test(normalized)) return [1, 0, 0];
      if (/bread|cooking|kitchen|sourdough|recipe/u.test(normalized)) return [0, 1, 0];
      return [0, 0, 1];
    });
  }
}

test("semantic recall is opt-in, revision-aware, and keeps its index in the unlocked session", async () => {
  const vault = new DocumentVault(tempVault(), PASSPHRASE);
  const vehicle = vault.put({
    path: "Reference/Vehicle Care",
    body: "Engine service schedule from the neighborhood garage mechanic.",
  });
  vault.put({
    path: "Recipes/Sourdough",
    body: "Bread fermentation notes and a reliable kitchen recipe.",
  });
  const adapter = new TopicEmbeddingAdapter();

  assert.deepEqual(vault.search("automobile repair"), []);
  const first = await vault.semanticSearch("automobile repair", adapter, { limit: 1, minScore: 0.5 });
  assert.equal(first[0].id, vehicle.id);
  assert.ok(first[0].score > 0.99);
  assert.deepEqual(adapter.calls.map((call) => call.length), [2, 1]);

  await vault.semanticSearch("car mechanic", adapter, { limit: 1 });
  assert.deepEqual(adapter.calls.map((call) => call.length), [2, 1, 1]);

  vault.put({
    id: vehicle.id,
    path: vehicle.path,
    body: "Updated engine maintenance guidance from a trusted mechanic.",
  });
  await vault.semanticSearch("vehicle repair", adapter, { limit: 1 });
  assert.deepEqual(adapter.calls.map((call) => call.length), [2, 1, 1, 1, 1]);

  vault.lock();
  await assert.rejects(() => vault.semanticSearch("vehicle repair", adapter), /locked/iu);
});

test("locking during an embedding request suppresses results and clears the session index", async () => {
  const vault = new DocumentVault(tempVault(), PASSPHRASE);
  vault.put({ path: "Private", body: "A private engine maintenance record." });
  let release;
  let started;
  const startedPromise = new Promise((resolve) => { started = resolve; });
  const releasePromise = new Promise((resolve) => { release = resolve; });
  const adapter = {
    id: "test:delayed:v1",
    async embed(input) {
      if (input.length > 0 && input[0].includes("Title:")) {
        started();
        await releasePromise;
      }
      return input.map(() => [1, 0]);
    },
  };

  const pending = vault.semanticSearch("maintenance", adapter);
  await startedPromise;
  vault.lock();
  release();
  await assert.rejects(pending, /locked while semantic search was running/iu);
});

test("Ollama adapter permits only loopback, refuses redirects, and validates both APIs", async () => {
  assert.throws(
    () => new OllamaLocalModelAdapter({ model: "embed", baseUrl: "https://models.example.com" }),
    /literal loopback host/iu
  );
  assert.throws(
    () => new OllamaLocalModelAdapter({ model: "embed", baseUrl: "http://127.0.0.1.example.com" }),
    /literal loopback host/iu
  );

  const calls = [];
  const adapter = new OllamaLocalModelAdapter({
    model: "local-test-model",
    baseUrl: "http://localhost:11434/models/",
    dimensions: 3,
    fetch: async (url, init) => {
      calls.push({ url: String(url), init, body: JSON.parse(String(init.body)) });
      if (String(url).endsWith("/api/embed")) {
        return new Response(JSON.stringify({ embeddings: [[0.25, 0.5, 0.75]] }), { status: 200 });
      }
      return new Response(JSON.stringify({ response: "local answer" }), { status: 200 });
    },
  });

  assert.deepEqual(await adapter.embed(["private note"]), [[0.25, 0.5, 0.75]]);
  assert.equal(await adapter.generate("Summarize locally", { system: "Stay concise." }), "local answer");
  assert.equal(calls[0].url, "http://localhost:11434/models/api/embed");
  assert.equal(calls[0].init.redirect, "error");
  assert.deepEqual(calls[0].body, {
    model: "local-test-model",
    input: ["private note"],
    truncate: true,
    dimensions: 3,
  });
  assert.equal(calls[1].url, "http://localhost:11434/models/api/generate");
  assert.equal(calls[1].body.stream, false);
});

test("semantic search rejects malformed model vectors instead of returning misleading scores", async () => {
  const vault = new DocumentVault(tempVault(), PASSPHRASE);
  vault.put({ path: "One", body: "Some content" });
  const malformed = { id: "test:bad", embed: async (input) => input.map(() => [Number.NaN]) };
  await assert.rejects(() => vault.semanticSearch("content", malformed), /non-finite/iu);

  vault.put({ path: "Two", body: "More content" });
  const inconsistent = {
    id: "test:inconsistent",
    embed: async (input) => input.map((_, index) => index === 0 ? [1, 0] : [1, 0, 0]),
  };
  await assert.rejects(() => vault.semanticSearch("content", inconsistent), /embedding dimensions/iu);
});
