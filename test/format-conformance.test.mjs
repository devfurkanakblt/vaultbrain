import assert from "node:assert/strict";
import test from "node:test";

import { AAD, FORMAT_COMPATIBILITY, VAULT_FORMAT_VERSION, canonicalBase64 } from "../dist/format-version.js";

test("the format version surface is frozen and complete", () => {
  assert.equal(VAULT_FORMAT_VERSION, "1.0");

  // Every AAD string is domain-separated under one prefix and is unique.
  const values = Object.values(AAD);
  assert.ok(values.length >= 20, "the inventory must cover every domain string in the codebase");
  for (const value of values) {
    assert.match(value, /^secondbrain-vault:/u, `AAD ${value} must carry the project prefix`);
  }
  assert.equal(new Set(values).size, values.length, "AAD strings must be unique");

  // The compatibility record names every artifact and the versions this build handles.
  for (const [artifact, entry] of Object.entries(FORMAT_COMPATIBILITY)) {
    assert.ok(entry.reads.length > 0, `${artifact} must declare readable versions`);
    assert.ok(entry.writes.length > 0, `${artifact} must declare written versions`);
    for (const written of entry.writes) {
      assert.ok(entry.reads.includes(written), `${artifact} must read every version it writes`);
    }
  }
  assert.deepEqual(FORMAT_COMPATIBILITY.encryptedEnvelope.reads, [0, 1]);
  assert.deepEqual(FORMAT_COMPATIBILITY.encryptedEnvelope.writes, [1]);
});

test("canonical base64 rejects non-canonical and wrong-length encodings", () => {
  const key = Buffer.alloc(44, 7).toString("base64");
  assert.equal(canonicalBase64(key, 44, "test key"), key);
  assert.throws(() => canonicalBase64(key, 32, "test key"), /invalid test key length/u);
  assert.throws(() => canonicalBase64("not base64!", undefined, "test key"), /malformed test key/u);
  // "QQ==" is canonical; "QQ" is the same bytes without padding and must be refused.
  assert.equal(canonicalBase64("QQ==", 1, "test key"), "QQ==");
  assert.throws(() => canonicalBase64("QQ", 1, "test key"), /malformed test key/u);
});
