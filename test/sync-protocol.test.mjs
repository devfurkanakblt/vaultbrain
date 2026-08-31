import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import {
  canonicalSyncJson,
  openSyncChange,
  sealSyncChange,
  validateSyncChangeBody,
} from "../dist/sync/protocol.js";
import { verifySyncChanges } from "../dist/sync/change-log.js";
import * as syncCompatibility from "../dist/sync.js";

const fixtures = path.join(import.meta.dirname, "fixtures", "sync-v1");
const golden = JSON.parse(fs.readFileSync(path.join(fixtures, "golden.json"), "utf8"));
const adversarial = JSON.parse(fs.readFileSync(path.join(fixtures, "adversarial.json"), "utf8"));
const key = Buffer.from(golden.keyHex, "hex");

function change(body = golden.body) {
  return { ...body, mutation: { ...body.mutation, value: structuredClone(body.mutation.value) } };
}

function replacementId(id) {
  return `${id.slice(0, -1)}${id.endsWith("0") ? "1" : "0"}`;
}

test("v1 golden body, keyed ID, opened result, and compatibility barrel are frozen", () => {
  assert.equal(canonicalSyncJson(golden.body), golden.canonical);
  const envelope = sealSyncChange(golden.body, key);
  assert.equal(envelope.id, golden.id);
  assert.deepEqual(openSyncChange(envelope, key), { id: golden.id, ...golden.body });
  assert.equal(syncCompatibility.canonicalSyncJson(golden.body), golden.canonical);
  assert.equal(syncCompatibility.sealSyncChange(golden.body, key).id, golden.id);
  assert.deepEqual(syncCompatibility.openSyncChange(envelope, key), { id: golden.id, ...golden.body });
  assert.deepEqual(syncCompatibility.verifySyncChanges([{ id: golden.id, ...golden.body }]), { changes: 1, devices: 1, heads: [golden.id] });
  assert.equal(typeof syncCompatibility.SyncChangeLog, "function");
  assert.equal(typeof syncCompatibility.SyncedDocumentVault, "function");
});

test("v1 protocol rejects deterministic adversarial inputs", () => {
  const envelope = sealSyncChange(golden.body, key);
  assert.throws(() => openSyncChange(envelope, Buffer.alloc(32, 7)), new RegExp(adversarial.errorPatterns.wrongKey, "u"));
  assert.throws(
    () => openSyncChange({ ...envelope, payload: { ...envelope.payload, authTag: `${envelope.payload.authTag.startsWith("A") ? "B" : "A"}${envelope.payload.authTag.slice(1)}` } }, key),
    new RegExp(adversarial.errorPatterns.tamper, "u"),
  );
  assert.throws(() => openSyncChange({ ...envelope, id: replacementId(envelope.id) }, key), /authenticate|does not match/u);
  assert.throws(
    () => openSyncChange({ ...envelope, payload: { ...envelope.payload, iv: adversarial.malformedBase64[0] } }, key),
    /malformed nonce/u,
  );
  for (const unsafeKey of adversarial.unsafeKeys) {
    assert.throws(() => canonicalSyncJson(JSON.parse(`{\"${unsafeKey}\":1}`)), new RegExp(adversarial.errorPatterns.unsafeKey, "u"));
  }
  assert.throws(() => canonicalSyncJson("\ud800"), new RegExp(adversarial.errorPatterns.surrogate, "u"));
  for (const id of adversarial.invalidChangeIds) {
    assert.throws(() => openSyncChange({ ...envelope, id }, key), new RegExp(adversarial.errorPatterns.malformedId, "u"));
  }
});

test("v1 protocol freezes admission limits and graph errors", () => {
  const parents = Array.from({ length: adversarial.limitBoundaries.parentsAccepted }, (_, index) => index.toString(16).padStart(64, "0"));
  const accepted = change({ ...golden.body, parents });
  assert.equal(validateSyncChangeBody(accepted).parents.length, parents.length);
  assert.throws(
    () => validateSyncChangeBody(change({ ...golden.body, parents: [...parents, "f".repeat(64)] })),
    /at most 256 parents/u,
  );
  assert.equal(validateSyncChangeBody(change({ ...golden.body, mutation: { ...golden.body.mutation, objectId: `a${"x".repeat(159)}` } })).mutation.objectId.length, 160);
  assert.throws(
    () => validateSyncChangeBody(change({ ...golden.body, mutation: { ...golden.body.mutation, objectId: `a${"x".repeat(160)}` } })),
    /Invalid sync object ID/u,
  );
  const base = { id: "a".repeat(64), ...golden.body };
  const child = { id: "b".repeat(64), ...change({ ...golden.body, sequence: 2, previousDeviceChange: base.id, parents: [base.id], mutation: { ...golden.body.mutation, baseRevision: 1, revision: 2 } }) };
  assert.deepEqual(verifySyncChanges([base, child]), { changes: 2, devices: 1, heads: [child.id] });
  assert.throws(() => verifySyncChanges([{ ...base, parents: ["c".repeat(64)] }]), new RegExp(adversarial.errorPatterns.missingParent, "u"));
  assert.throws(() => verifySyncChanges([{ ...base, parents: [base.id] }]), /cannot parent itself/u);
  assert.throws(() => verifySyncChanges([base, child, { ...child, id: "c".repeat(64) }]), new RegExp(adversarial.errorPatterns.fork, "u"));
  assert.throws(() => verifySyncChanges([{ ...base, parents: [child.id] }, child]), new RegExp(adversarial.errorPatterns.cycle, "u"));
  assert.throws(() => verifySyncChanges([base, { ...child, mutation: { ...child.mutation, baseRevision: 2, revision: 3 } }]), new RegExp(adversarial.errorPatterns.revisionJump, "u"));
});
