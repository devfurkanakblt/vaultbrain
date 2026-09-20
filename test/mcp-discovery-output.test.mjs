// What the discovery tools put into an agent's context.
//
// `list_keys`, `find_key` and `find_notes_in_range` are read by a language
// model, and discovery is the largest thing this server contributes to a
// context: it lists every key the agent may see, on every conversation that
// browses the vault. These cover the shape and the cost, because a regression
// here is invisible — the output still "works", it just quietly costs more.
import assert from "node:assert/strict";
import test from "node:test";

import { discoveryLines } from "../dist/mcp-server.js";

const ENTRIES = [
  { file: "health", key: "DOCTOR_NAME", desc: "family doctor" },
  { file: "health", key: "BLOOD_TYPE", desc: "blood type" },
  { file: "finance", key: "IBAN", desc: "main current account" },
];

test("each line carries its own file, key and description", () => {
  assert.equal(
    discoveryLines(ENTRIES, "nothing"),
    [
      "health/DOCTOR_NAME — family doctor",
      "health/BLOOD_TYPE — blood type",
      "finance/IBAN — main current account",
    ].join("\n"),
  );
});

test("a line is complete on its own, so a file cannot be read off the wrong heading", () => {
  // The agent's next call is resolve_key(file, key). Grouping under a file
  // heading would be about 6% cheaper and would let a long listing be
  // misattributed; every line therefore repeats its file.
  for (const line of discoveryLines(ENTRIES, "nothing").split("\n")) {
    const [locator] = line.split(" — ");
    const [file, key] = locator.split("/");
    assert.ok(file && key, `every line names both a file and a key: ${line}`);
    assert.ok(
      ENTRIES.some((entry) => entry.file === file && entry.key === key),
      `${locator} should name a real entry`,
    );
  }
});

test("a journal note carries its timestamp between the key and the description", () => {
  assert.equal(
    discoveryLines(
      [{ file: "health", key: "NOTE_20260920_212739_0e78", createdAt: "2026-09-20T21:27:39.000Z", desc: "checkup summary" }],
      "nothing",
    ),
    "health/NOTE_20260920_212739_0e78 — 2026-09-20T21:27:39.000Z — checkup summary",
  );
});

test("an empty result says so in words rather than returning an empty container", () => {
  // `[]` and `{}` are what this used to return, and they read as "the tool
  // failed" as easily as "there is nothing", which costs a retry.
  assert.equal(discoveryLines([], 'Nothing in this vault matches "boat".'), 'Nothing in this vault matches "boat".');
});

test("an entry with no description contributes no separator", () => {
  assert.equal(discoveryLines([{ file: "work", key: "BADGE", desc: "" }], "nothing"), "work/BADGE");
});

test("listing a key costs less than handing over that key with its value", () => {
  // The defect this format replaced: pretty-printed JSON spent about a third
  // of its characters on indentation and quoting, so discovery — the step that
  // exists to avoid sending values — cost more per key than sending the value
  // would have. That inversion must not come back.
  const entries = Array.from({ length: 250 }, (_, index) => ({
    file: ["health", "finance", "work", "home", "travel"][index % 5],
    key: `FIELD_${String(index).padStart(4, "0")}`,
    desc: `synthetic record ${index} for the category`,
  }));
  const values = entries.map((entry) => `synthetic-value-${entry.key}-abcd1234`);

  const discovery = discoveryLines(entries, "nothing");
  const dumpWithValues = entries
    .map((entry, index) => `${entry.file}/${entry.key} (${entry.desc}): ${values[index]}`)
    .join("\n");
  const asPrettyJson = JSON.stringify(entries, null, 2);

  assert.ok(
    discovery.length < dumpWithValues.length,
    `discovery (${discovery.length}) must stay cheaper than dumping the same keys with values (${dumpWithValues.length})`,
  );
  // Measured against the shipped format on real vaults this ran between 1.53x
  // and 2.14x, depending on how long the descriptions are relative to the JSON
  // scaffolding around them — so the bound is the floor of that range, not the
  // best case.
  assert.ok(
    discovery.length * 1.4 < asPrettyJson.length,
    `discovery (${discovery.length}) should stay well under pretty-printed JSON (${asPrettyJson.length})`,
  );
});
