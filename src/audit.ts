import crypto from "node:crypto";
import fs from "node:fs";
import { assertNotSymlink, readTextFileLimited, writeFileAtomic } from "./fs-safe.js";
import { openOrCreateVaultKey, openVaultKey } from "./keyring.js";
import { resolveInside } from "./safety.js";
import { withVaultLock } from "./vault-lock.js";

export interface AuditEntry {
  timestamp: string;
  actor: "cli-direct" | "mcp-agent" | "cli-direct-write" | "mcp-agent-write" | "cli-keyring";
  file: string;
  key: string;
  /** Which agent identity asked, when a grant policy governs the vault. */
  agent?: string;
  /** The grant that allowed it, so a later revocation has something to point at. */
  grant?: string;
  /** How much of the value the caller actually received. */
  redaction?: "none" | "partial" | "full";
  /** A denial and a held-back resolution are recorded, not only successes. */
  outcome?: "allowed" | "denied" | "pending";
  prevHash?: string;
  hash?: string;
}

export interface AuditVerification {
  valid: boolean;
  signedEntries: number;
  legacyEntries: number;
  error?: string;
}

const AUDIT_FILENAME = "audit.log";
const AUDIT_META_FILENAME = "audit.meta.json";
const AUDIT_HEAD_FILENAME = "audit.head.json";
const GENESIS_HASH = "GENESIS";
const MAX_AUDIT_BYTES = 16 * 1024 * 1024;
const auditKeyCache = new Map<string, { key: Buffer; lastUsed: number }>();

export function clearAuditKeyCache(vaultDir?: string): void {
  const prefix = vaultDir ? `${resolveInside(vaultDir, ".")}\0` : undefined;
  for (const [id, cached] of auditKeyCache) {
    if (!prefix || id.startsWith(prefix)) {
      cached.key.fill(0);
      auditKeyCache.delete(id);
    }
  }
}

interface AuditMeta {
  version: 1;
  salt: string;
}

interface AuditHead {
  version: 1;
  signedEntries: number;
  lastHash: string;
  mac: string;
}

function auditPath(vaultDir: string): string {
  return resolveInside(vaultDir, AUDIT_FILENAME);
}

function metaPath(vaultDir: string): string {
  return resolveInside(vaultDir, AUDIT_META_FILENAME);
}

function headPath(vaultDir: string): string {
  return resolveInside(vaultDir, AUDIT_HEAD_FILENAME);
}

function loadOrCreateMeta(vaultDir: string): AuditMeta {
  const p = metaPath(vaultDir);
  if (fs.existsSync(p)) {
    assertNotSymlink(p);
    const meta: AuditMeta = JSON.parse(readTextFileLimited(p, 64 * 1024, "Audit metadata"));
    if (meta.version !== 1 || !meta.salt) throw new Error("Invalid audit metadata.");
    return meta;
  }
  const meta: AuditMeta = { version: 1, salt: crypto.randomBytes(16).toString("base64") };
  writeFileAtomic(p, JSON.stringify(meta, null, 2), { mode: 0o600 });
  return meta;
}

function loadMeta(vaultDir: string): AuditMeta | null {
  const p = metaPath(vaultDir);
  if (!fs.existsSync(p)) return null;
  assertNotSymlink(p);
  const meta: AuditMeta = JSON.parse(readTextFileLimited(p, 64 * 1024, "Audit metadata"));
  return meta.version === 1 && meta.salt ? meta : null;
}

function auditKey(vaultDir: string, passphrase: string, meta: AuditMeta): Buffer {
  // The fingerprint only identifies an already-unlocked in-process session;
  // neither it nor the derived key is persisted. This avoids paying the KDF
  // cost for every MCP audit event while retaining passphrase separation.
  const fingerprint = crypto
    .createHash("sha256")
    .update(meta.salt, "utf8")
    .update("\0", "utf8")
    .update(passphrase, "utf8")
    .digest("hex");
  const cacheId = `${resolveInside(vaultDir, ".")}\0${fingerprint}`;
  const cutoff = Date.now() - 5 * 60 * 1000;
  for (const [id, cached] of auditKeyCache) {
    if (cached.lastUsed < cutoff || (auditKeyCache.size > 8 && id !== cacheId)) {
      cached.key.fill(0);
      auditKeyCache.delete(id);
    }
  }
  const cached = auditKeyCache.get(cacheId);
  if (cached) {
    cached.lastUsed = Date.now();
    return cached.key;
  }

  const derived = crypto.scryptSync(passphrase, Buffer.from(meta.salt, "base64"), 32, {
    N: 2 ** 15,
    maxmem: 64 * 1024 * 1024,
  });
  auditKeyCache.set(cacheId, { key: derived, lastUsed: Date.now() });
  return derived;
}

function headMac(head: Omit<AuditHead, "mac">, key: Buffer): string {
  return crypto.createHmac("sha256", key).update(JSON.stringify(head), "utf8").digest("hex");
}

function saveHead(vaultDir: string, signedEntries: number, lastHash: string, key: Buffer): void {
  const unsigned = { version: 1 as const, signedEntries, lastHash };
  writeFileAtomic(headPath(vaultDir), JSON.stringify({ ...unsigned, mac: headMac(unsigned, key) }), {
    mode: 0o600,
  });
}

/**
 * A keyring vault keeps its chain key in the keyset, so changing the
 * passphrase later cannot orphan the audit history. A legacy vault keeps
 * deriving from `audit.meta.json` exactly as before.
 */
function chainKeyForAppend(vaultDir: string, passphrase: string): Buffer {
  const key = openOrCreateVaultKey(vaultDir, passphrase, "audit");
  if (key) return key;
  return auditKey(vaultDir, passphrase, loadOrCreateMeta(vaultDir));
}

/**
 * The grant fields are folded in only when an entry carries them, so a log
 * written before this build hashes byte-for-byte as it did and keeps verifying,
 * while everything new — including who asked and how much they got — is signed.
 */
function signedPayload(entry: Omit<AuditEntry, "hash"> & { prevHash: string }): string {
  return JSON.stringify({
    timestamp: entry.timestamp,
    actor: entry.actor,
    file: entry.file,
    key: entry.key,
    ...(entry.agent === undefined ? {} : { agent: entry.agent }),
    ...(entry.grant === undefined ? {} : { grant: entry.grant }),
    ...(entry.redaction === undefined ? {} : { redaction: entry.redaction }),
    ...(entry.outcome === undefined ? {} : { outcome: entry.outcome }),
    prevHash: entry.prevHash,
  });
}

function calculateHash(
  entry: Omit<AuditEntry, "hash"> & { prevHash: string },
  key: Buffer
): string {
  return crypto.createHmac("sha256", key).update(signedPayload(entry), "utf8").digest("hex");
}

export function appendAudit(
  vaultDir: string,
  entry: Omit<AuditEntry, "timestamp" | "prevHash" | "hash">,
  passphrase: string
): void {
  appendAuditWithKey(vaultDir, entry, chainKeyForAppend(vaultDir, passphrase));
}

/**
 * Append with an already-open audit key, including before a keyring is
 * installed or restored. Holds the same vault lock and advances the same
 * signed-head record as the passphrase entry point: an append that skipped
 * either would leave the chain verifiable but the head stale.
 */
export function appendAuditWithKey(
  vaultDir: string,
  entry: Omit<AuditEntry, "timestamp" | "prevHash" | "hash">,
  key: Buffer,
): void {
  withVaultLock(vaultDir, () => {
    fs.mkdirSync(vaultDir, { recursive: true, mode: 0o700 });
    const p = auditPath(vaultDir);
    assertNotSymlink(p);
    const existing = readAudit(vaultDir);
    const signedEntries = existing.filter((item) => item.hash).length;
    const previousSigned = [...existing].reverse().find((item) => item.hash);
    const prevHash = previousSigned?.hash ?? GENESIS_HASH;
    const unsigned = { timestamp: new Date().toISOString(), ...entry, prevHash };
    const hash = calculateHash(unsigned, key);
    const full: AuditEntry = { ...unsigned, hash };
    fs.appendFileSync(p, JSON.stringify(full) + "\n", { encoding: "utf8", mode: 0o600 });
    saveHead(vaultDir, signedEntries + 1, hash, key);
  });
}

export function readAudit(vaultDir: string): AuditEntry[] {
  const p = auditPath(vaultDir);
  if (!fs.existsSync(p)) return [];
  assertNotSymlink(p);
  if (fs.statSync(p).size > MAX_AUDIT_BYTES) {
    throw new Error("Audit log exceeds the 16 MiB safety limit.");
  }
  return fs
    .readFileSync(p, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as AuditEntry);
}

export function verifyAudit(vaultDir: string, passphrase: string): AuditVerification {
  const entries = readAudit(vaultDir);
  const legacyEntries = entries.filter((entry) => !entry.hash || !entry.prevHash).length;
  const signed = entries.filter(
    (entry): entry is AuditEntry & { hash: string; prevHash: string } =>
      Boolean(entry.hash && entry.prevHash)
  );
  if (signed.length === 0) {
    if (fs.existsSync(headPath(vaultDir)) || loadMeta(vaultDir)) {
      return { valid: false, signedEntries: 0, legacyEntries, error: "Audit log is missing or truncated." };
    }
    return { valid: true, signedEntries: 0, legacyEntries };
  }

  const keyringKey = openVaultKey(vaultDir, passphrase, "audit");
  let key: Buffer;
  if (keyringKey) {
    key = keyringKey;
  } else {
    const meta = loadMeta(vaultDir);
    if (!meta) {
      return { valid: false, signedEntries: signed.length, legacyEntries, error: "Missing audit metadata." };
    }
    key = auditKey(vaultDir, passphrase, meta);
  }

  return verifySignedEntries(vaultDir, entries, key);
}

/** Verify using key material recovered independently of a readable keyring. */
export function verifyAuditWithKey(vaultDir: string, key: Buffer): AuditVerification {
  return verifySignedEntries(vaultDir, readAudit(vaultDir), key);
}

function verifySignedEntries(vaultDir: string, entries: AuditEntry[], key: Buffer): AuditVerification {
  const legacyEntries = entries.filter((entry) => !entry.hash || !entry.prevHash).length;
  const signed = entries.filter(
    (entry): entry is AuditEntry & { hash: string; prevHash: string } =>
      Boolean(entry.hash && entry.prevHash),
  );
  if (signed.length === 0) return { valid: true, signedEntries: 0, legacyEntries };
  let expectedPrevious = GENESIS_HASH;
  for (let index = 0; index < signed.length; index += 1) {
    const entry = signed[index];
    if (entry.prevHash !== expectedPrevious) {
      return {
        valid: false,
        signedEntries: signed.length,
        legacyEntries,
        error: `Broken audit chain at signed entry ${index + 1}.`,
      };
    }
    const expectedHash = calculateHash(entry, key);
    if (!/^[a-f0-9]{64}$/u.test(entry.hash)) {
      return {
        valid: false,
        signedEntries: signed.length,
        legacyEntries,
        error: `Malformed audit signature at signed entry ${index + 1}.`,
      };
    }
    if (!crypto.timingSafeEqual(Buffer.from(entry.hash, "hex"), Buffer.from(expectedHash, "hex"))) {
      return {
        valid: false,
        signedEntries: signed.length,
        legacyEntries,
        error: `Invalid audit signature at signed entry ${index + 1}.`,
      };
    }
    expectedPrevious = entry.hash;
  }
  const sealedPath = headPath(vaultDir);
  if (!fs.existsSync(sealedPath)) {
    // Audit heads were introduced after signed chains. A migrated vault keeps
    // audit.meta.json as its authenticated legacy marker, so its already-
    // verified chain remains readable; the next append writes the head. New
    // keyring-native vaults have no metadata file and still fail closed when
    // their head is removed.
    if (loadMeta(vaultDir)) {
      return { valid: true, signedEntries: signed.length, legacyEntries };
    }
    return { valid: false, signedEntries: signed.length, legacyEntries, error: "Audit head is missing." };
  }
  assertNotSymlink(sealedPath);
  const head = JSON.parse(readTextFileLimited(sealedPath, 64 * 1024, "Audit head")) as AuditHead;
  const unsigned = { version: head.version, signedEntries: head.signedEntries, lastHash: head.lastHash };
  const expectedMac = headMac(unsigned, key);
  const validMac = /^[a-f0-9]{64}$/u.test(head.mac) && crypto.timingSafeEqual(
    Buffer.from(head.mac, "hex"),
    Buffer.from(expectedMac, "hex")
  );
  if (!validMac || head.version !== 1 || head.signedEntries !== signed.length || head.lastHash !== expectedPrevious) {
    return { valid: false, signedEntries: signed.length, legacyEntries, error: "Audit head does not match the log." };
  }
  return { valid: true, signedEntries: signed.length, legacyEntries };
}
