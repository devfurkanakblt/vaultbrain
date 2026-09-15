import assert from "node:assert/strict";

// Assertions that an encrypted file at rest carries no plaintext.
//
// Matching short words against the raw file is flaky: base64 ciphertext is
// random, so a case-insensitive /secret|Batch/ eventually matches by chance.
// Instead the file must parse as exactly the expected envelope whose every
// value is base64 (or hex / an integer), so there is no field a plaintext
// could hide in, and each known plaintext must be absent verbatim. Every
// needle has to contain a character outside the base64 alphabet, which random
// ciphertext can never produce, so the absence check cannot false-positive.

const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/u;
const NON_BASE64 = /[^A-Za-z0-9+/=]/u;

function assertBase64(value, label) {
  assert.equal(typeof value, "string", `${label} must be a string`);
  assert.match(value, BASE64, `${label} must be base64`);
}

export function assertOpaqueDocumentPayload(payload, label = "payload") {
  assert.equal(typeof payload, "object", `${label} must be an object`);
  assert.notEqual(payload, null, `${label} must be an object`);
  assert.deepEqual(Object.keys(payload).sort(), ["authTag", "ciphertext", "iv", "version"], `${label} fields`);
  assert.equal(payload.version, 1, `${label} version`);
  assertBase64(payload.iv, `${label}.iv`);
  assertBase64(payload.authTag, `${label}.authTag`);
  assertBase64(payload.ciphertext, `${label}.ciphertext`);
}

export function assertNoPlaintext(raw, plaintexts, label = "file") {
  for (const plaintext of plaintexts) {
    assert.match(plaintext, NON_BASE64, `needle ${JSON.stringify(plaintext)} could occur in random base64`);
    assert.equal(raw.includes(plaintext), false, `${label} leaks ${JSON.stringify(plaintext)}`);
  }
}

/** A file holding one encrypted document payload, such as `pending-local.enc`. */
export function assertOpaqueEncryptedFile(raw, plaintexts, label = "file") {
  assertOpaqueDocumentPayload(JSON.parse(raw), label);
  assertNoPlaintext(raw, plaintexts, label);
}

/** A stored sync change envelope: a keyed hex ID around one encrypted payload. */
export function assertOpaqueChangeEnvelope(raw, plaintexts, label = "change") {
  const envelope = JSON.parse(raw);
  const allowed = envelope.version === 2 ? ["epoch", "id", "payload", "version"] : ["id", "payload", "version"];
  assert.deepEqual(Object.keys(envelope).sort(), allowed, `${label} fields`);
  assert.match(envelope.id, /^[a-f0-9]{64}$/u, `${label}.id`);
  if (envelope.version === 2) assert.ok(Number.isSafeInteger(envelope.epoch), `${label}.epoch`);
  assertOpaqueDocumentPayload(envelope.payload, `${label}.payload`);
  assertNoPlaintext(raw, plaintexts, label);
}
