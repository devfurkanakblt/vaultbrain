import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { auditEntryHash, auditHeadMac } from "../dist/audit.js";

const VECTOR = JSON.parse(
  fs.readFileSync(
    path.resolve(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "audit-vector.json"),
    "utf8",
  ),
);

/**
 * The audit chain is written by both cores, so its two hash constructions have
 * to agree byte for byte or one core's entries stop verifying under the other.
 * This is the TypeScript half; `audit_vector_matches_the_committed_fixture` in
 * `src-tauri/src/audit.rs` reads the same file.
 */
test("the audit entry hash matches the committed cross-core vector", () => {
  const key = Buffer.from(VECTOR.key, "base64");
  let previous = VECTOR.genesisHash;
  for (const [index, expected] of VECTOR.entries.entries()) {
    assert.equal(expected.prevHash, previous, `entry ${index + 1} must chain to the previous hash`);
    const { hash, ...entry } = expected;
    assert.equal(auditEntryHash(entry, key), hash, `entry ${index + 1} hash`);
    previous = hash;
  }
});

test("the audit head mac matches the committed cross-core vector", () => {
  const key = Buffer.from(VECTOR.key, "base64");
  const { mac, ...head } = VECTOR.head;
  assert.equal(auditHeadMac(head, key), mac);
  assert.equal(head.signedEntries, VECTOR.entries.length);
  assert.equal(head.lastHash, VECTOR.entries.at(-1).hash);
});

test("an optional field that is absent is absent from the signature, not signed as null", () => {
  const key = Buffer.from(VECTOR.key, "base64");
  const bare = {
    timestamp: "2026-09-05T09:00:00.000Z",
    actor: "cli-direct",
    file: "f",
    key: "k",
    prevHash: "GENESIS",
  };
  // A log written before the grant fields existed must keep verifying, so an
  // absent field cannot contribute to the hash in any form.
  assert.equal(auditEntryHash(bare, key), auditEntryHash({ ...bare, agent: undefined }, key));
  assert.notEqual(auditEntryHash(bare, key), auditEntryHash({ ...bare, agent: "someone" }, key));
});
