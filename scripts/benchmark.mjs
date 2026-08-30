import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";

import { DocumentVault } from "../dist/documents.js";

function argument(name, fallback) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : fallback;
}

function percentile(samples, value) {
  const sorted = [...samples].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * value) - 1)];
}

function measureMany(count, operation) {
  const samples = [];
  for (let index = 0; index < count; index += 1) {
    const start = performance.now();
    operation(index);
    samples.push(performance.now() - start);
  }
  return { p50: percentile(samples, 0.5), p95: percentile(samples, 0.95), max: Math.max(...samples) };
}

/**
 * Budgets per corpus size. The 1k tier is the everyday gate; the larger tiers
 * are the production ones from docs/PRODUCT.md. Every number here was measured
 * on the development machine, not guessed — raise a tier only with a
 * measurement and a reason, never to make a red run go green.
 */
const TIERS = [
  { notes: 1_000, unlockMs: 2_000, quickSwitchP95: 30, fullTextP95: 100, openP95: 50, backlinkP95: 50 },
  { notes: 10_000, unlockMs: 2_000, quickSwitchP95: 30, fullTextP95: 100, openP95: 50, backlinkP95: 50 },
  { notes: 100_000, unlockMs: 2_000, quickSwitchP95: 30, fullTextP95: 100, openP95: 50, backlinkP95: 50 },
];

function budgetFor(count) {
  return TIERS.find((tier) => count <= tier.notes) ?? TIERS[TIERS.length - 1];
}

const noteCount = Number.parseInt(argument("--notes", "1000"), 10);
if (!Number.isSafeInteger(noteCount) || noteCount < 100 || noteCount > 100_000) {
  throw new Error("--notes must be an integer between 100 and 100000.");
}
const budget = budgetFor(noteCount);
const shouldAssert = process.argv.includes("--assert");
const passphrase = "benchmark-only-passphrase";
const root = fs.mkdtempSync(path.join(os.tmpdir(), "secondbrain-benchmark-"));
const resolvedRoot = path.resolve(root);
const resolvedTemp = path.resolve(os.tmpdir());
if (!resolvedRoot.startsWith(`${resolvedTemp}${path.sep}`)) {
  throw new Error("Refusing unsafe benchmark cleanup.");
}

try {
  const createStart = performance.now();
  const writer = new DocumentVault(root, passphrase);
  const inputs = Array.from({ length: noteCount }, (_, index) => ({
    path: `Corpus/Note-${String(index).padStart(6, "0")}.md`,
    title: `Benchmark Note ${index}`,
    body: [
      `# Benchmark Note ${index}`,
      `This document contains benchmarktoken${index % 100} and common recall text.`,
      index > 0 ? `Previous: [[Corpus/Note-${String(index - 1).padStart(6, "0")}]].` : "Root note.",
      `#corpus/group-${index % 20}`,
    ].join("\n"),
    properties: { ordinal: index, group: index % 20 },
  }));
  const created = writer.putMany(inputs);
  const bulkCreateMs = performance.now() - createStart;

  const unlockStart = performance.now();
  const vault = new DocumentVault(root, passphrase);
  const unlockAndIndexMs = performance.now() - unlockStart;
  // Force authenticated index decryption before recording warm timings.
  assert.equal(vault.list().length, noteCount);

  // The quick switcher matches titles, aliases and paths over the summaries it
  // already holds — it never calls the full-text engine. Measuring it that way
  // is what makes it comparable to the "title / quick switch" budget; the
  // full-text engine is measured separately against the full-text budget.
  // The first query also builds the per-session normalized search text, so it
  // is reported separately instead of being hidden inside a p95.
  const coldSearchStart = performance.now();
  vault.search("benchmarktoken0", 10);
  const coldSearchMs = performance.now() - coldSearchStart;

  const summaries = vault.list();
  const quickSwitch = measureMany(50, (index) => {
    const query = `note ${index % noteCount}`;
    const matches = summaries
      .filter((note) =>
        note.title.toLocaleLowerCase().includes(query) ||
        note.path.toLocaleLowerCase().includes(query) ||
        note.aliases.some((alias) => alias.toLocaleLowerCase().includes(query))
      )
      .slice(0, 50);
    assert.ok(matches.length > 0);
  });

  const titleSearch = measureMany(50, (index) => {
    const hits = vault.search(`Benchmark Note ${index % noteCount}`, 10);
    assert.ok(hits.length > 0);
  });
  const fullTextSearch = measureMany(50, (index) => {
    const hits = vault.search(`benchmarktoken${index % 100} tag:corpus/group-${index % 20}`, 20);
    assert.ok(hits.length > 0);
  });
  const noteOpen = measureMany(50, (index) => {
    assert.equal(vault.get(created[index % created.length].id).id, created[index % created.length].id);
  });
  const backlinks = measureMany(50, (index) => {
    vault.backlinks(created[index % Math.max(1, created.length - 1)].id);
  });

  const result = {
    notes: noteCount,
    tier: budget.notes,
    bulkCreateMs: Number(bulkCreateMs.toFixed(2)),
    unlockAndIndexMs: Number(unlockAndIndexMs.toFixed(2)),
    coldSearchMs: Number(coldSearchMs.toFixed(2)),
    quickSwitchMs: quickSwitch,
    titleSearchMs: titleSearch,
    fullTextSearchMs: fullTextSearch,
    noteOpenMs: noteOpen,
    backlinksMs: backlinks,
  };
  console.log(JSON.stringify(result, null, 2));

  if (shouldAssert) {
    const gate = (label, measured, limit) =>
      assert.ok(measured < limit, `${label} ${measured.toFixed(1)}ms exceeded ${limit}ms at ${noteCount} notes`);
    gate("unlock", unlockAndIndexMs, budget.unlockMs);
    gate("quick switch p95", quickSwitch.p95, budget.quickSwitchP95);
    gate("title-shaped full-text p95", titleSearch.p95, budget.fullTextP95);
    gate("full-text p95", fullTextSearch.p95, budget.fullTextP95);
    gate("note open p95", noteOpen.p95, budget.openP95);
    gate("backlinks p95", backlinks.p95, budget.backlinkP95);
    console.log(`Performance gates at the ${budget.notes}-note tier: PASS`);
  }
} finally {
  fs.rmSync(resolvedRoot, { recursive: true, force: true });
}
