import crypto from "node:crypto";
import fs from "node:fs";
import { assertNotSymlink, writeFileAtomic } from "./fs-safe.js";
import { resolveInside } from "./safety.js";
import { openOrCreateVaultKey, openVaultKey } from "./keyring.js";

export interface AuditEntry {
  timestamp: string;
  actor: "cli-direct" | "mcp-agent" | "cli-direct-write" | "mcp-agent-write";
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
const GENESIS_HASH = "GENESIS";
const auditKeyCache = new Map<string, Buffer>();

interface AuditMeta {
  version: 1;
  salt: string;
}

function auditPath(vaultDir: string): string {
  return resolveInside(vaultDir, AUDIT_FILENAME);
}

function metaPath(vaultDir: string): string {
  return resolveInside(vaultDir, AUDIT_META_FILENAME);
}

function loadOrCreateMeta(vaultDir: string): AuditMeta {
  const p = metaPath(vaultDir);
  if (fs.existsSync(p)) {
    assertNotSymlink(p);
    const meta: AuditMeta = JSON.parse(fs.readFileSync(p, "utf8"));
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
  const meta: AuditMeta = JSON.parse(fs.readFileSync(p, "utf8"));
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
  const cached = auditKeyCache.get(cacheId);
  if (cached) return cached;

  const derived = crypto.scryptSync(passphrase, Buffer.from(meta.salt, "base64"), 32, {
    N: 2 ** 15,
    maxmem: 64 * 1024 * 1024,
  });
  auditKeyCache.set(cacheId, derived);
  return derived;
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
  fs.mkdirSync(vaultDir, { recursive: true, mode: 0o700 });
  const p = auditPath(vaultDir);
  assertNotSymlink(p);
  const existing = readAudit(vaultDir);
  const previousSigned = [...existing].reverse().find((item) => item.hash);
  const prevHash = previousSigned?.hash ?? GENESIS_HASH;
  const unsigned = { timestamp: new Date().toISOString(), ...entry, prevHash };
  const hash = calculateHash(unsigned, chainKeyForAppend(vaultDir, passphrase));
  const full: AuditEntry = { ...unsigned, hash };
  fs.appendFileSync(p, JSON.stringify(full) + "\n", { encoding: "utf8", mode: 0o600 });
}

export function readAudit(vaultDir: string): AuditEntry[] {
  const p = auditPath(vaultDir);
  if (!fs.existsSync(p)) return [];
  assertNotSymlink(p);
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
  if (signed.length === 0) return { valid: true, signedEntries: 0, legacyEntries };

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
  return { valid: true, signedEntries: signed.length, legacyEntries };
}
