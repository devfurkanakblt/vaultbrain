import fs from "node:fs";
import path from "node:path";
import { verifyAuditWithKey } from "./audit.js";
import { decryptWithKey, type KeyedEncryptedPayload } from "./crypto.js";
import { decryptDocument, type DocumentPayload } from "./document-crypto.js";
import { assertNotSymlink } from "./fs-safe.js";
import type { KeySet } from "./keyring.js";
import { resolveInside } from "./safety.js";
import { APPLIED_AAD, openSyncChange } from "./sync/protocol.js";

const INDEX_AAD = "secondbrain-vault:document-index:v1";

function readPayload<T>(filePath: string): T {
  assertNotSymlink(filePath);
  return JSON.parse(fs.readFileSync(filePath, "utf8")) as T;
}

/**
 * Prove that independently recovered keys belong to this vault before replacing
 * keyring.json. Phase 7.4's object inventory can extend this same boundary with
 * its full current/retiring scan when that branch is merged.
 */
export function verifyRecoveryKeySet(vaultDir: string, keys: KeySet): number {
  let verified = 0;
  const indexPath = resolveInside(vaultDir, path.join("documents", "index.enc"));
  if (fs.existsSync(indexPath)) {
    JSON.parse(decryptDocument(readPayload<DocumentPayload>(indexPath), keys.documents, INDEX_AAD));
    verified += 1;
  }

  if (fs.existsSync(vaultDir)) {
    for (const entry of fs.readdirSync(vaultDir, { withFileTypes: true })) {
      if (!entry.name.endsWith(".kv.enc")) continue;
      if (!entry.isFile()) throw new Error("A vault key-value path is not a regular file.");
      const logicalName = entry.name.slice(0, -".kv.enc".length);
      const filePath = resolveInside(vaultDir, entry.name);
      decryptWithKey(readPayload<KeyedEncryptedPayload>(filePath), keys.kv, logicalName);
      verified += 1;
    }
  }

  const grantsPath = resolveInside(vaultDir, "grants.enc");
  if (fs.existsSync(grantsPath)) {
    decryptWithKey(readPayload<KeyedEncryptedPayload>(grantsPath), keys.kv, "grants");
    verified += 1;
  }

  const appliedPath = resolveInside(vaultDir, path.join("documents", "sync", "applied.enc"));
  if (fs.existsSync(appliedPath)) {
    JSON.parse(decryptDocument(readPayload<DocumentPayload>(appliedPath), keys.documents, APPLIED_AAD));
    verified += 1;
  }

  const changesDir = resolveInside(vaultDir, path.join("documents", "sync", "changes"));
  if (fs.existsSync(changesDir)) {
    assertNotSymlink(changesDir);
    for (const entry of fs.readdirSync(changesDir, { withFileTypes: true })) {
      if (!entry.name.endsWith(".change.enc")) continue;
      if (!entry.isFile()) throw new Error("A sync change path is not a regular file.");
      openSyncChange(readPayload(resolveInside(vaultDir, path.join("documents", "sync", "changes", entry.name))), {
        syncChangeKey: keys.syncChange,
        syncEnvelopeKey: keys.syncEnvelope,
      });
      verified += 1;
    }
  }

  const audit = verifyAuditWithKey(vaultDir, keys.audit);
  if (!audit.valid) throw new Error(audit.error ?? "The recovery keyset does not authenticate the audit chain.");
  if (audit.signedEntries > 0) verified += 1;
  return verified;
}

