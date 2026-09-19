// The query language from docs/CLI-AUDIT-2026-09-19.md finding 9. The review
// found a parser that recognized `tag:` and `path:` and silently treated every
// other documented operator as literal text -- and that stripped a leading `-`
// before deciding what kind of term it had, so `-tag:red` became a required
// tag filter instead of an exclusion.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { DocumentVault } from "../dist/documents.js";
import { parseQuery } from "../dist/search-query.js";
import { removeTree } from "../scripts/fs-tree.mjs";

const PASSPHRASE = "search-query-test-passphrase";

function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "search-query-"));
  const vault = new DocumentVault(directory, PASSPHRASE);
  vault.put({
    path: "Fruit/Apple.md",
    title: "Apple",
    body: "a crisp apple pie recipe",
    tags: ["red", "fruit"],
    properties: { status: "done", rating: 5 },
    createdAt: "2026-01-15T00:00:00.000Z",
  });
  vault.put({
    path: "Fruit/Banana.md",
    title: "Banana",
    // "grapple" contains "apple": a bare word is a substring match, a prefix
    // term is word-anchored, and these two notes are what tells them apart.
    body: "banana bread and grapple jokes",
    tags: ["yellow", "fruit"],
    properties: { status: "open" },
    createdAt: "2026-08-15T00:00:00.000Z",
  });
  return { directory, vault };
}

test("the query language answers the operators the product contract promises", () => {
  const { directory, vault } = fixture();
  const hits = (query) =>
    vault
      .search(query, 20)
      .map((hit) => hit.title)
      .sort()
      .join(",");
  try {
    const cases = [
      // Bare words keep the substring behaviour they have always had.
      ["apple", "Apple,Banana"],
      ["appl*", "Apple"],
      ["pie", "Apple"],
      // Boolean.
      ["apple OR banana", "Apple,Banana"],
      ["pie OR bread", "Apple,Banana"],
      ["pie AND crisp", "Apple"],
      ["pie AND bread", ""],
      ["pie bread", ""],
      // Phrase.
      ['"apple pie"', "Apple"],
      ['"crisp banana"', ""],
      // Tag, including the exact regression: negation must reach the filter.
      ["tag:red", "Apple"],
      ["-tag:red", "Banana"],
      ["tag:re*", "Apple"],
      ["tag:#red", "Apple"],
      ["tag:fruit", "Apple,Banana"],
      ["-tag:red -tag:yellow", ""],
      // Path and file.
      ["path:Fruit/", "Apple,Banana"],
      ["file:Apple", "Apple"],
      ["-file:Apple", "Banana"],
      // Properties.
      ["[status:done]", "Apple"],
      ["-[status:done]", "Banana"],
      ["[rating]", "Apple"],
      ["[rating:5]", "Apple"],
      ["[status:do*]", "Apple"],
      // Dates.
      ["created:2026-01-15", "Apple"],
      ["created:2026-01-01..2026-06-30", "Apple"],
      ["created:>=2026-07-01", "Banana"],
      ["created:<=2026-06-30", "Apple"],
      // Mixed.
      ["tag:red OR [status:open]", "Apple,Banana"],
      ["tag:fruit -[status:open]", "Apple"],
    ];
    for (const [query, expected] of cases) {
      assert.equal(hits(query), expected, `query: ${query}`);
    }
  } finally {
    vault.lock();
    removeTree(directory);
  }
});

test("an empty or unusable query does not silently match everything", () => {
  const { directory, vault } = fixture();
  try {
    // An empty query keeps returning the whole vault: that is the existing
    // "browse" behaviour, not an operator failure.
    assert.equal(vault.search("", 20).length, 2);
    // A trailing OR is a typo. The empty side must not become a match-all.
    assert.equal(vault.search("tag:red OR", 20).length, 1);
    assert.equal(vault.search("OR tag:red", 20).length, 1);
    // An operator with no argument falls back to text rather than throwing.
    assert.doesNotThrow(() => vault.search("tag:", 20));
    assert.doesNotThrow(() => vault.search("[]", 20));
    assert.doesNotThrow(() => vault.search("created:not-a-date", 20));
  } finally {
    vault.lock();
    removeTree(directory);
  }
});

test("operators are recognized only when written as operators", () => {
  // Lowercase `or` is a word, not a separator, so ordinary prose stays
  // searchable.
  assert.equal(parseQuery("apple or banana").clauses.length, 1);
  assert.equal(parseQuery("apple OR banana").clauses.length, 2);
  assert.equal(parseQuery("apple AND banana").clauses.length, 1);
  assert.deepEqual(parseQuery("apple AND banana").scoringTerms, ["apple", "banana"]);

  // Repeats are kept: a term written twice has always scored twice.
  assert.deepEqual(parseQuery("ALPHA alpha").scoringTerms, ["alpha", "alpha"]);

  // Negation binds to the whole term, whatever kind it is.
  const negated = parseQuery("-tag:red -[status:done] -\"a phrase\" -word");
  assert.deepEqual(
    negated.clauses[0].terms.map((term) => [term.matcher.kind, term.negated]),
    [
      ["tag", true],
      ["property", true],
      ["phrase", true],
      ["text", true],
    ],
  );
  assert.deepEqual(negated.scoringTerms, [], "a negated term must not score");
});

test("query parsing is bounded", () => {
  const many = parseQuery(Array.from({ length: 500 }, (_, index) => `term${index}`).join(" "));
  assert.ok(many.clauses[0].terms.length <= 64);
  const long = parseQuery("x".repeat(10_000));
  assert.ok(long.clauses[0].terms.every((term) => (term.matcher.value ?? "").length <= 512));
});
