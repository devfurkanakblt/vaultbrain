import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalSyncJson, openSyncChange, sealSyncChange, validateSyncChangeBody } from "../dist/sync/protocol.js";
import { verifySyncChanges } from "../dist/sync/change-log.js";
import { encryptDocument } from "../dist/document-crypto.js";
import * as syncCompatibility from "../dist/sync.js";

const fixtures = path.join(import.meta.dirname, "fixtures", "sync-v1");
const golden = JSON.parse(fs.readFileSync(path.join(fixtures, "golden.json"), "utf8"));
const adversarial = JSON.parse(fs.readFileSync(path.join(fixtures, "adversarial.json"), "utf8"));
const key = Buffer.from(golden.keyHex, "hex");
// The golden fixture predates the syncChange/syncEnvelope split. Passing the
// same legacy key in both roles is exactly what compatibility requires: it
// proves output stays byte-identical to what the single-key protocol wrote.
const keys = { syncChangeKey: key, syncEnvelopeKey: key };

function change(body = golden.body) {
  return { ...body, mutation: { ...body.mutation, value: structuredClone(body.mutation.value) } };
}

function replacementId(id) {
  return `${id.slice(0, -1)}${id.endsWith("0") ? "1" : "0"}`;
}

function throwsError(action, pattern) {
  assert.throws(action, (error) => error instanceof Error && pattern.test(error.message));
}

function tempVault(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `secondbrain-sync-protocol-${label}-`));
}

test("v1 golden body, keyed ID, opened result, and compatibility barrel are frozen", () => {
  assert.equal(canonicalSyncJson(golden.body), golden.canonical);
  const envelope = sealSyncChange(golden.body, keys);
  assert.equal(envelope.id, golden.id);
  assert.deepEqual(openSyncChange(envelope, keys), { id: golden.id, ...golden.body });
  assert.equal(syncCompatibility.canonicalSyncJson(golden.body), golden.canonical);
  assert.equal(syncCompatibility.sealSyncChange(golden.body, keys).id, golden.id);
  assert.deepEqual(syncCompatibility.openSyncChange(envelope, keys), { id: golden.id, ...golden.body });
  assert.deepEqual(syncCompatibility.validateSyncChangeBody(golden.body), golden.body);
  assert.deepEqual(syncCompatibility.verifySyncChanges([{ id: golden.id, ...golden.body }]), {
    changes: 1,
    devices: 1,
    heads: [golden.id],
  });
  assert.deepEqual(
    syncCompatibility.resolveSyncObject([{ id: golden.id, ...golden.body }], "note", golden.body.mutation.objectId)
      .heads,
    [golden.id],
  );
  assert.equal(syncCompatibility.MAX_SYNC_ATTACHMENT_BYTES, 6242304);
  const vaultDir = tempVault("barrel");
  const log = new syncCompatibility.SyncChangeLog(vaultDir, "barrel-passphrase");
  const appended = log.append(golden.body.deviceId, golden.body.mutation, golden.body.createdAt);
  assert.equal(log.verify().heads[0], appended.id);
  log.close();
  const vault = new syncCompatibility.SyncedDocumentVault(vaultDir, "barrel-passphrase", golden.body.deviceId);
  const note = vault.put({ path: "Fixture.md", body: "fixture" });
  assert.equal(vault.changeLog.resolve("note", note.id).winner?.mutation.revision, 1);
  vault.lock();
  fs.rmSync(vaultDir, { recursive: true, force: true });
});

test("v1 protocol rejects deterministic adversarial inputs", () => {
  const envelope = sealSyncChange(golden.body, keys);
  throwsError(
    () => openSyncChange(envelope, { syncChangeKey: Buffer.alloc(32, 7), syncEnvelopeKey: Buffer.alloc(32, 7) }),
    new RegExp(adversarial.errorPatterns.wrongKey, "u"),
  );
  throwsError(
    () =>
      openSyncChange(
        {
          ...envelope,
          payload: {
            ...envelope.payload,
            authTag: `${envelope.payload.authTag.startsWith("A") ? "B" : "A"}${envelope.payload.authTag.slice(1)}`,
          },
        },
        keys,
      ),
    new RegExp(adversarial.errorPatterns.tamper, "u"),
  );
  throwsError(
    () => openSyncChange({ ...envelope, id: replacementId(envelope.id) }, keys),
    /authenticate|does not match/u,
  );
  for (const value of adversarial.malformedBase64)
    throwsError(
      () => openSyncChange({ ...envelope, payload: { ...envelope.payload, iv: value } }, keys),
      /malformed nonce/u,
    );
  const envelopeKey = crypto
    .createHmac("sha256", key)
    .update("secondbrain-vault:sync-change-key:v1")
    .update("\0")
    .update(envelope.id)
    .digest();
  const noncanonical = {
    ...envelope,
    payload: encryptDocument(`${golden.canonical}\n`, envelopeKey, `secondbrain-vault:sync-change:v1:${envelope.id}`),
  };
  envelopeKey.fill(0);
  throwsError(
    () => openSyncChange(noncanonical, keys),
    new RegExp(adversarial.errorPatterns.noncanonicalPlaintext, "u"),
  );
  for (const unsafeKey of adversarial.unsafeKeys) {
    throwsError(
      () => canonicalSyncJson(JSON.parse(`{\"${unsafeKey}\":1}`)),
      new RegExp(adversarial.errorPatterns.unsafeKey, "u"),
    );
  }
  throwsError(() => canonicalSyncJson("\ud800"), new RegExp(adversarial.errorPatterns.surrogate, "u"));
  for (const id of adversarial.invalidChangeIds) {
    throwsError(() => openSyncChange({ ...envelope, id }, keys), new RegExp(adversarial.errorPatterns.malformedId, "u"));
  }
});

test("v1 protocol freezes admission limits and graph errors", () => {
  const parents = Array.from({ length: adversarial.limitBoundaries.parentsAccepted }, (_, index) =>
    index.toString(16).padStart(64, "0"),
  );
  const accepted = change({ ...golden.body, parents });
  assert.equal(validateSyncChangeBody(accepted).parents.length, parents.length);
  throwsError(
    () => validateSyncChangeBody(change({ ...golden.body, parents: [...parents, "f".repeat(64)] })),
    /at most 256 parents/u,
  );
  throwsError(
    () => validateSyncChangeBody(change({ ...golden.body, parents: ["a".repeat(64), "a".repeat(64)] })),
    new RegExp(adversarial.errorPatterns.duplicateParents, "u"),
  );
  assert.equal(
    validateSyncChangeBody(
      change({ ...golden.body, mutation: { ...golden.body.mutation, objectId: `a${"x".repeat(159)}` } }),
    ).mutation.objectId.length,
    160,
  );
  throwsError(
    () =>
      validateSyncChangeBody(
        change({ ...golden.body, mutation: { ...golden.body.mutation, objectId: `a${"x".repeat(160)}` } }),
      ),
    /Invalid sync object ID/u,
  );
  const base = { id: "a".repeat(64), ...golden.body };
  const child = {
    id: "b".repeat(64),
    ...change({
      ...golden.body,
      sequence: 2,
      previousDeviceChange: base.id,
      parents: [base.id],
      mutation: { ...golden.body.mutation, baseRevision: 1, revision: 2 },
    }),
  };
  assert.deepEqual(verifySyncChanges([base, child]), { changes: 2, devices: 1, heads: [child.id] });
  throwsError(
    () => verifySyncChanges([{ ...base, parents: ["c".repeat(64)] }]),
    new RegExp(adversarial.errorPatterns.missingParent, "u"),
  );
  throwsError(() => verifySyncChanges([{ ...base, parents: [base.id] }]), /cannot parent itself/u);
  throwsError(
    () => verifySyncChanges([base, child, { ...child, id: "c".repeat(64) }]),
    new RegExp(adversarial.errorPatterns.fork, "u"),
  );
  throwsError(
    () => verifySyncChanges([{ ...base, parents: [child.id] }, child]),
    new RegExp(adversarial.errorPatterns.cycle, "u"),
  );
  throwsError(
    () => verifySyncChanges([base, { ...child, mutation: { ...child.mutation, baseRevision: 2, revision: 3 } }]),
    new RegExp(adversarial.errorPatterns.revisionJump, "u"),
  );
});
