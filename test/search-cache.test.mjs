import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { DocumentVault } from "../dist/documents.js";

// Deliberately uncached, full-sort oracle for the existing search contract.
// It does not call the production scoring or cache helpers.
function reference(notes, query, limit) {
  const normalize = (value) => value.normalize("NFKC").toLocaleLowerCase("en-US");
  const tags = [], paths = [], required = [], excluded = [];
  for (let chunk of query.match(/-?"[^"]+"|-?\S+/gu) ?? []) {
    const negative = chunk.startsWith("-");
    if (negative) chunk = chunk.slice(1);
    if (chunk.startsWith('"') && chunk.endsWith('"')) chunk = chunk.slice(1, -1);
    const term = normalize(chunk);
    if (term.startsWith("tag:")) tags.push(term.slice(4).replace(/^#/u, ""));
    else if (term.startsWith("path:")) paths.push(term.slice(5));
    else if (negative) excluded.push(term);
    else if (term) required.push(term);
  }
  return notes.flatMap((note) => {
    const title = normalize(note.title), body = normalize(note.body), file = normalize(note.path);
    const aliases = note.aliases.map(normalize), labels = note.tags.map(normalize);
    const properties = normalize(JSON.stringify(note.properties));
    const head = `${title}\n${aliases.join(" ")}\n${labels.join(" ")}\n${file}\n${properties}`;
    if (tags.some((tag) => !labels.includes(tag)) || paths.some((part) => !file.includes(part)) ||
        excluded.some((term) => head.includes(term) || body.includes(term)) ||
        required.some((term) => !head.includes(term) && !body.includes(term))) return [];
    let score = required.length ? 0 : 1;
    for (const term of required) {
      score += title === term ? 40 : title.includes(term) ? 20 : 0;
      if (aliases.some((alias) => alias.includes(term))) score += 14;
      if (labels.some((tag) => tag.includes(term))) score += 10;
      if (file.includes(term)) score += 8;
      score += Math.min(10, body.split(term).length - 1);
      if (properties.includes(term)) score += 4;
    }
    return [{ id: note.id, score, updatedAt: note.updatedAt }];
  }).sort((a, b) => b.score - a.score || (a.updatedAt < b.updatedAt ? 1 : a.updatedAt > b.updatedAt ? -1 : 0))
    .slice(0, Math.max(1, Math.min(limit, 100))).map(({ id, score }) => ({ id, score }));
}

const PASS = "search-cache-test-passphrase";
function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "search-cache-"));
  const vault = new DocumentVault(directory, PASS);
  vault.putMany(Array.from({ length: 24 }, (_, i) => ({
    path: `Corpus/Note-${i}.md`, title: `Benchmark Note ${i}`,
    body: `${"alpha ".repeat(i % 13)} benchmark note café ＡＬＰＨＡ ${i % 2 ? "hidden" : "visible"} #topic`,
    aliases: [`Alias ${i}`], properties: { group: i % 3 },
  })));
  return { directory, vault };
}

test("cached search preserves uncached scores, ordering and query grammar", () => {
  const { directory, vault } = fixture();
  try {
    const notes = vault.list().map((note) => vault.get(note.id));
    // The oracle uses the index's stable order for equal scores/timestamps.
    const byId = new Map(notes.map((note) => [note.id, note]));
    const ordered = vault.indexedNotes().map((note) => byId.get(note.id));
    const queries = ["", "alpha", "ALPHA alpha", '"benchmark note"', "café", "ＡＬＰＨＡ", "alpha -hidden",
      "tag:topic path:Corpus alpha", "alias", "group", "alpha benchmark note café visible", "x".repeat(257)];
    for (const query of queries) for (const limit of [0, 1, 10, 100, 101]) {
      const expected = reference(ordered, query, limit);
      for (let repeat = 0; repeat < 2; repeat++) {
        assert.deepEqual(vault.search(query, limit).map(({ id, score }) => ({ id, score })), expected, `${query}/${limit}`);
      }
    }
  } finally { vault.lock(); fs.rmSync(directory, { recursive: true, force: true }); }
});

test("occurrence cache is bounded, cleared after writes/rebuild and zeroed on lock", () => {
  const { directory, vault } = fixture();
  try {
    for (const term of ["alpha", "benchmark", "note", "café", "visible", "alias"]) vault.search(term);
    assert.equal(vault.bodyOccurrenceCache.size, 4);
    vault.search("x".repeat(257));
    assert.equal(vault.bodyOccurrenceCache.size, 4);
    const beforeMany = [...vault.bodyOccurrenceCache.values()];
    vault.search("alpha benchmark note café visible alias");
    assert.ok(vault.bodyOccurrenceCache.size <= 4);
    assert.ok([...vault.bodyOccurrenceCache.values()].every((counts) => counts instanceof Uint8Array && counts.length === 24));
    const note = vault.list()[0];
    vault.put({ id: note.id, path: note.path, body: "unique replacement" });
    assert.equal(vault.bodyOccurrenceCache.size, 0);
    vault.search("replacement");
    vault.remove(note.id);
    assert.equal(vault.bodyOccurrenceCache.size, 0);
    assert.equal(vault.search("replacement").length, 0);
    vault.rebuildIndex();
    assert.equal(vault.bodyOccurrenceCache.size, 0);
    vault.search("alpha");
    const references = [...beforeMany, ...vault.bodyOccurrenceCache.values()];
    vault.lock();
    assert.equal(vault.bodyOccurrenceCache.size, 0);
    for (const counts of references) assert.ok(counts.every((value) => value === 0));
    const reopened = new DocumentVault(directory, PASS);
    try { assert.equal(reopened.search("replacement").length, 0); } finally { reopened.lock(); }
  } finally { vault.lock(); fs.rmSync(directory, { recursive: true, force: true }); }
});
