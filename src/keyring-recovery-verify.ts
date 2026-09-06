import fs from "node:fs";
import path from "node:path";
import { verifyAuditWithKey } from "./audit.js";
import { decryptWithKey, type KeyedEncryptedPayload } from "./crypto.js";
import { decryptDocument, type DocumentPayload } from "./document-crypto.js";
import { AAD } from "./format-version.js";
import { assertNotSymlink } from "./fs-safe.js";
import type { KeySet, RetiringKeys } from "./keyring.js";
import { resolveInside } from "./safety.js";
import { APPLIED_AAD, openSyncChange } from "./sync/protocol.js";

function readPayload<T>(filePath: string): T {
  assertNotSymlink(filePath);
  return JSON.parse(fs.readFileSync(filePath, "utf8")) as T;
}

/** Node's AES-GCM authentication failure for a valid envelope under the wrong key. */
function isAuthenticationFailure(error: unknown): boolean {
  return error instanceof Error && error.message === "Unsupported state or unable to authenticate data";
}

/**
 * Try the key in force, then its retiring predecessor only when AES-GCM
 * authentication proves the first key is not the one that sealed the artifact.
 * Structural envelope and JSON failures are not key mismatches, so they must
 * remain visible rather than being retried with another key.
 */
function openWithFallback<T>(open: (key: Buffer) => T, current: Buffer, retiring: Buffer | undefined): T {
  try {
    return open(current);
  } catch (error) {
    if (!retiring || !isAuthenticationFailure(error)) throw error;
    return open(retiring);
  }
}

/**
 * Prove that independently recovered keys belong to this vault before replacing
 * keyring.json.
 *
 * Deliberately not `planRekey`'s inventory. That walk classifies every artifact
 * because every one must be re-encrypted; this check only needs one artifact of
 * each key class to prove that key belongs to the vault. Walking every revision
 * and attachment chunk would multiply restore cost without proving more.
 */
export function verifyRecoveryKeySet(vaultDir: string, keys: KeySet, retiring: RetiringKeys | null = null): number {
  let verified = 0;
  const indexPath = resolveInside(vaultDir, path.join("documents", "index.enc"));
  if (fs.existsSync(indexPath)) {
    JSON.parse(
      openWithFallback(
        (key) => decryptDocument(readPayload<DocumentPayload>(indexPath), key, AAD.documentIndex),
        keys.documents,
        retiring?.documents,
      ),
    );
    verified += 1;
  }

  if (fs.existsSync(vaultDir)) {
    for (const entry of fs.readdirSync(vaultDir, { withFileTypes: true })) {
      if (!entry.name.endsWith(".kv.enc")) continue;
      if (!entry.isFile()) throw new Error("A vault key-value path is not a regular file.");
      const logicalName = entry.name.slice(0, -".kv.enc".length);
      const filePath = resolveInside(vaultDir, entry.name);
      openWithFallback(
        (key) => decryptWithKey(readPayload<KeyedEncryptedPayload>(filePath), key, logicalName),
        keys.kv,
        retiring?.kv,
      );
      verified += 1;
    }
  }

  const grantsPath = resolveInside(vaultDir, "grants.enc");
  if (fs.existsSync(grantsPath)) {
    openWithFallback(
      (key) => decryptWithKey(readPayload<KeyedEncryptedPayload>(grantsPath), key, "grants"),
      keys.kv,
      retiring?.kv,
    );
    verified += 1;
  }

  const appliedPath = resolveInside(vaultDir, path.join("documents", "sync", "applied.enc"));
  if (fs.existsSync(appliedPath)) {
    JSON.parse(
      openWithFallback(
        (key) => decryptDocument(readPayload<DocumentPayload>(appliedPath), key, APPLIED_AAD),
        keys.documents,
        retiring?.documents,
      ),
    );
    verified += 1;
  }

  const changesDir = resolveInside(vaultDir, path.join("documents", "sync", "changes"));
  if (fs.existsSync(changesDir)) {
    assertNotSymlink(changesDir);
    for (const entry of fs.readdirSync(changesDir, { withFileTypes: true })) {
      if (!entry.name.endsWith(".change.enc")) continue;
      if (!entry.isFile()) throw new Error("A sync change path is not a regular file.");
      openWithFallback(
        (key) =>
          openSyncChange(readPayload(resolveInside(vaultDir, path.join("documents", "sync", "changes", entry.name))), {
            syncChangeKey: keys.syncChange,
            syncEnvelopeKey: key,
          }),
        keys.syncEnvelope,
        retiring?.syncEnvelope,
      );
      verified += 1;
    }
  }

  const audit = verifyAuditWithKey(vaultDir, keys.audit);
  if (!audit.valid) throw new Error(audit.error ?? "The recovery keyset does not authenticate the audit chain.");
  if (audit.signedEntries > 0) verified += 1;
  return verified;
}

