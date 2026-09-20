// Bulk key-value entry.
//
// Entering keys one command at a time costs about 620 ms each, of which
// roughly 610 is fixed: process start, the module graph and the scrypt
// keyring unwrap. Measured, 250 keys took 158 seconds and about one of those
// was the work. `upsertEntries` pays the fixed costs once.
//
// The interesting behaviour is not the speed — it is that a batch either
// lands whole or not at all. A half-written bulk import is the worst outcome
// here, because nothing on the outside says where it stopped.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { loadVaultFile, upsertEntries, upsertEntry, MAX_BULK_ENTRIES } from "../dist/store.js";
import { removeTree } from "../scripts/fs-tree.mjs";

const PASSPHRASE = "bulk-entry-test-passphrase";

function tempVault() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "vault-brain-bulk-test-"));
}

function entries(count, prefix = "FIELD") {
  return Array.from({ length: count }, (_, index) => ({
    key: `${prefix}_${index}`,
    value: `value-${index}`,
    desc: `record ${index}`,
  }));
}

test("a batch writes every entry it was given", () => {
  const vault = tempVault();
  try {
    const result = upsertEntries(vault, "health", entries(50), PASSPHRASE);
    assert.deepEqual(result, { added: 50, replaced: 0 });

    const stored = loadVaultFile(vault, "health", PASSPHRASE);
    assert.equal(stored.length, 50);
    assert.equal(stored.find((entry) => entry.key === "FIELD_37").value, "value-37");
    assert.equal(stored.find((entry) => entry.key === "FIELD_37").desc, "record 37");
  } finally {
    removeTree(vault);
  }
});

test("one invalid entry writes nothing at all", () => {
  const vault = tempVault();
  try {
    const batch = [...entries(3), { key: "BAD KEY", value: "x", desc: "d" }, ...entries(3, "TAIL")];
    assert.throws(() => upsertEntries(vault, "health", batch, PASSPHRASE), /Entry 4 \(BAD KEY\)/u);
    // Not "the good ones landed and the bad one did not" — nothing landed.
    assert.equal(fs.existsSync(path.join(vault, "health.kv.enc")), false);
  } finally {
    removeTree(vault);
  }
});

test("a rejected batch leaves an existing category exactly as it was", () => {
  const vault = tempVault();
  try {
    upsertEntry(vault, "health", "KEEP", "original", "kept", PASSPHRASE);
    const before = fs.readFileSync(path.join(vault, "health.kv.enc"));

    assert.throws(
      () => upsertEntries(vault, "health", [{ key: "NEW", value: "n", desc: "d" }, { key: "BAD KEY", value: "x", desc: "d" }], PASSPHRASE),
      /Invalid key/u,
    );

    assert.deepEqual(fs.readFileSync(path.join(vault, "health.kv.enc")), before, "the file was not rewritten");
    const stored = loadVaultFile(vault, "health", PASSPHRASE);
    assert.deepEqual(stored.map((entry) => entry.key), ["KEEP"]);
    assert.equal(stored[0].value, "original");
  } finally {
    removeTree(vault);
  }
});

test("a key repeated inside one batch is refused rather than resolved by order", () => {
  const vault = tempVault();
  try {
    // "Last one wins" is a reasonable rule the caller did not necessarily
    // intend, and silently dropping one of two hand-written values is the
    // kind of loss this vault exists to prevent.
    assert.throws(
      () =>
        upsertEntries(
          vault,
          "health",
          [
            { key: "IBAN", value: "first", desc: "one" },
            { key: "OTHER", value: "x", desc: "x" },
            { key: "IBAN", value: "second", desc: "two" },
          ],
          PASSPHRASE,
        ),
      /Entry 3 repeats the key IBAN, already given as entry 1/u,
    );
    assert.equal(fs.existsSync(path.join(vault, "health.kv.enc")), false);
  } finally {
    removeTree(vault);
  }
});

test("a batch updates existing keys in place instead of duplicating them", () => {
  const vault = tempVault();
  try {
    upsertEntries(vault, "health", entries(5), PASSPHRASE);
    const result = upsertEntries(
      vault,
      "health",
      [
        { key: "FIELD_2", value: "changed", desc: "changed desc" },
        { key: "BRAND_NEW", value: "new", desc: "new desc" },
      ],
      PASSPHRASE,
    );
    assert.deepEqual(result, { added: 1, replaced: 1 });

    const stored = loadVaultFile(vault, "health", PASSPHRASE);
    assert.equal(stored.length, 6, "the replaced key was not appended a second time");
    assert.equal(stored.find((entry) => entry.key === "FIELD_2").value, "changed");
    assert.equal(stored.find((entry) => entry.key === "FIELD_0").value, "value-0", "untouched keys survive");
  } finally {
    removeTree(vault);
  }
});

test("an empty batch is a no-op and does not create the category", () => {
  const vault = tempVault();
  try {
    assert.deepEqual(upsertEntries(vault, "health", [], PASSPHRASE), { added: 0, replaced: 0 });
    assert.equal(fs.existsSync(path.join(vault, "health.kv.enc")), false);
  } finally {
    removeTree(vault);
  }
});

test("a batch beyond the bound is refused before any work is done", () => {
  const vault = tempVault();
  try {
    // The whole batch is held in memory and encrypted as one plaintext, so an
    // unbounded batch is an unbounded allocation.
    assert.throws(
      () => upsertEntries(vault, "health", entries(MAX_BULK_ENTRIES + 1), PASSPHRASE),
      /cannot exceed 10000 entries/u,
    );
    assert.equal(fs.existsSync(path.join(vault, "health.kv.enc")), false);
  } finally {
    removeTree(vault);
  }
});

test("a description left empty keeps the one already stored", () => {
  const vault = tempVault();
  try {
    upsertEntry(vault, "health", "IBAN", "first", "main account", PASSPHRASE);
    upsertEntries(vault, "health", [{ key: "IBAN", value: "second", desc: "" }], PASSPHRASE);

    const stored = loadVaultFile(vault, "health", PASSPHRASE);
    assert.equal(stored[0].value, "second");
    assert.equal(stored[0].desc, "main account", "an omitted description does not erase the old one");
  } finally {
    removeTree(vault);
  }
});
