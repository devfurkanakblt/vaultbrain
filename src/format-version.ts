/**
 * The single inventory of everything that identifies this vault's on-disk
 * format: the frozen format version, which artifact versions this build reads
 * and writes, and every AEAD domain-separation string.
 *
 * These strings are load-bearing. Changing one does not fail loudly — it makes
 * previously written vaults undecryptable. They live here so they are
 * reviewable in one place and are frozen by test/format-conformance.test.mjs.
 *
 * Compatibility policy: within 1.x only additive optional fields are allowed.
 * Bumping an artifact version, changing an AAD string, removing a field, or
 * altering a canonical encoding requires format 2.0 and a migration path.
 */

/** Frozen on-disk format version. Not the product version in package.json. */
export const VAULT_FORMAT_VERSION = "1.0";

export interface FormatArtifact {
  /** Where the artifact lives, relative to the vault directory. */
  readonly path: string;
  /** Whether this is a durable vault artifact, a recovery-time temporary, a contained payload, or an external file. */
  readonly persistence: "persistent" | "transient" | "nested" | "external";
  /** Whether the artifact's own bytes are encrypted (rather than merely carrying encrypted children). */
  readonly protection: "encrypted" | "plaintext";
  /** Anchored POSIX path matcher; absent for nested or external formats. */
  readonly pattern?: RegExp;
  /** Exact crash-leftover filename shape, never accepted as a live artifact. */
  readonly temporaryPattern?: RegExp;
  /** A deliberate format-specific limitation, not an implicit skip. */
  readonly limitation?: string;
  /** Versions this build can open. */
  readonly reads: readonly number[];
  /** Versions this build produces. Always a subset of `reads`. */
  readonly writes: readonly number[];
  /** Names of every frozen crypto domain this artifact uses. */
  readonly domains: readonly (keyof typeof AAD)[];
  /** What the two supported key-rotation operations do to this artifact. */
  readonly rekey: Readonly<{
    normal: "reencrypt" | "preserve" | "replace-keyset";
    rotateIdentities: "reencrypt" | "preserve" | "rewrite-identities" | "reset" | "replace-keyset";
  }>;
}

export type FormatCompatibility = Readonly<Record<string, FormatArtifact>>;

/**
 * Fixed AEAD domain-separation strings. Suffixed builders below cover the
 * artifacts whose AAD includes an identifier.
 */
export const AAD = {
  workspace: "secondbrain-vault:workspace:v1",
  savedViews: "secondbrain-vault:saved-views:v1",
  keyringSlot: "secondbrain-vault:keyring-slot:v1",
  keyedEnvelope: "secondbrain-vault:kv:v2",
  documentKeyCheck: "secondbrain-vault:document-key:v1",
  documentIndex: "secondbrain-vault:document-index:v1",
  indexLogPrefix: "secondbrain-vault:index-log:v1:",
  pluginPolicy: "secondbrain-vault:plugin-policy:v1",
  retentionPolicy: "secondbrain-vault:retention-policy:v1",
  attachmentId: "secondbrain-vault:attachment-id:v1\0",
  syncChangeId: "secondbrain-vault:sync-change-id:v1",
  syncBlobKey: "secondbrain-vault:sync-blob-key:v1",
  syncChangeKey: "secondbrain-vault:sync-change-key:v1",
  syncChangeKeyV2: "secondbrain-vault:sync-change-key:v2",
  syncChangePrefix: "secondbrain-vault:sync-change:v1:",
  syncApplied: "secondbrain-vault:sync-applied:v1",
  syncLocalTransaction: "secondbrain-vault:sync-local-transaction:v1",
  syncApplyReceipt: "secondbrain-vault:sync-apply-receipt:v1",
  syncDeviceRegistry: "secondbrain-vault:sync-device-registry:v1",
  syncFreshnessCheckpoint: "secondbrain-vault:sync-freshness-checkpoint:v1",
  syncAuthorityKey: "secondbrain-vault:sync-authority-key:v1",
  syncDeviceKeyPrefix: "secondbrain-vault:sync-device-key:v1:",
  syncAgreementKeyPrefix: "secondbrain-vault:sync-agreement-key:v1:",
  syncEpochKeyPrefix: "secondbrain-vault:sync-epoch-key:v1:",
  syncEpochWrap: "secondbrain-vault:sync-epoch-wrap:v1",
  notePrefix: "secondbrain-vault:note:v1:",
  noteHistoryPrefix: "secondbrain-vault:note-history:v1:",
  canvasPrefix: "secondbrain-vault:canvas:v1:",
  canvasHistoryPrefix: "secondbrain-vault:canvas-history:v1:",
  pluginPrefix: "secondbrain-vault:plugin:v1:",
  pluginStorePrefix: "secondbrain-vault:plugin-store:v1:",
  attachmentManifestPrefix: "secondbrain-vault:attachment-manifest:v1:",
  attachmentChunkPrefix: "secondbrain-vault:attachment-chunk:v1:",
  backupKey: "secondbrain-vault:backup-key:v1",
  backupManifestPrefix: "secondbrain-vault:backup-manifest:v1:",
  backupEntryPrefix: "secondbrain-vault:backup-entry:v1:",
} as const;

const reencrypt = { normal: "reencrypt", rotateIdentities: "reencrypt" } as const;
const reset = { normal: "reencrypt", rotateIdentities: "reset" } as const;
const preserve = { normal: "preserve", rotateIdentities: "reset" } as const;

/**
 * Every durable encrypted family, its format layers, crypto domains, and
 * rotation behavior. Keep this exhaustive: re-key planning and format
 * conformance tests use it as the reviewable source of truth.
 */
export const FORMAT_COMPATIBILITY: FormatCompatibility = {
  vaultKeyring: {
    pattern: new RegExp("^keyring\\.json$", "u"),
    path: "keyring.json",
    persistence: "persistent",
    protection: "encrypted",
    reads: [2],
    writes: [2],
    domains: ["keyringSlot"],
    rekey: { normal: "replace-keyset", rotateIdentities: "replace-keyset" },
  },
  vaultKeyset: {
    limitation: "Rust refuses transitional keyset v2; finish or roll back re-key with the CLI first.",
    path: "keyring.json (wrapped)",
    persistence: "nested",
    protection: "encrypted",
    reads: [1, 2],
    writes: [1, 2],
    domains: ["keyringSlot"],
    rekey: { normal: "replace-keyset", rotateIdentities: "replace-keyset" },
  },
  encryptedEnvelope: {
    pattern: new RegExp("^[^/]+\\.kv\\.enc$", "u"),
    path: "*.kv.enc",
    persistence: "persistent",
    protection: "encrypted",
    reads: [0, 1, 2],
    writes: [1, 2],
    domains: ["keyedEnvelope"],
    rekey: reencrypt,
  },
  keyedEnvelope: {
    pattern: new RegExp("^grants\\.enc$", "u"),
    path: "*.kv.enc, grants.enc",
    persistence: "persistent",
    protection: "encrypted",
    reads: [2],
    writes: [2],
    domains: ["keyedEnvelope"],
    rekey: reencrypt,
  },
  schemaCatalog: {
    pattern: new RegExp("^schema[.]enc$", "u"),
    path: "schema.enc",
    persistence: "persistent",
    protection: "encrypted",
    // Versions 0 and 1 are catalogs earlier releases sealed with a key derived
    // straight from the passphrase. They stay readable so an existing vault
    // keeps working; the next `vbrain index` rewrites them under the keyring.
    reads: [0, 1, 2],
    writes: [2],
    domains: ["keyedEnvelope"],
    rekey: reencrypt,
  },
  documentManifest: {
    pattern: new RegExp("^documents/manifest\\.json$", "u"),
    path: "documents/manifest.json",
    persistence: "persistent",
    protection: "plaintext",
    reads: [1, 2],
    writes: [1, 2],
    domains: ["documentKeyCheck"],
    rekey: { normal: "preserve", rotateIdentities: "preserve" },
  },
  portableWorkspace: {
    pattern: new RegExp("^documents/workspace\\.enc$", "u"),
    path: "documents/workspace.enc",
    persistence: "persistent",
    protection: "encrypted",
    reads: [1],
    writes: [1],
    domains: ["workspace"],
    rekey: reencrypt,
  },
  savedViews: {
    pattern: new RegExp("^documents/views\\.enc$", "u"),
    path: "documents/views.enc",
    persistence: "persistent",
    protection: "encrypted",
    reads: [1],
    writes: [1],
    domains: ["savedViews"],
    rekey: reencrypt,
  },
  documentIndex: {
    pattern: new RegExp("^documents/index\\.enc$", "u"),
    path: "documents/index.enc",
    persistence: "persistent",
    protection: "encrypted",
    reads: [1],
    writes: [1],
    domains: ["documentIndex"],
    rekey: { normal: "reencrypt", rotateIdentities: "rewrite-identities" },
  },
  indexLog: {
    pattern: new RegExp("^documents/index-log[.]enc$", "u"),
    path: "documents/index-log.enc",
    persistence: "persistent",
    protection: "encrypted",
    // The log defers the index snapshot; it never outlives one. A re-key
    // rewrites the snapshot, so the log it extended is compacted into that
    // snapshot first and the file is then absent rather than re-encrypted.
    limitation: "Compacted into the index snapshot before a re-key; never re-encrypted in place.",
    reads: [1],
    writes: [1],
    domains: ["indexLogPrefix"],
    rekey: { normal: "preserve", rotateIdentities: "reset" },
  },
  pluginPolicy: {
    pattern: new RegExp("^documents/plugin-policy\\.enc$", "u"),
    path: "documents/plugin-policy.enc",
    persistence: "persistent",
    protection: "encrypted",
    reads: [1],
    writes: [1],
    domains: ["pluginPolicy"],
    rekey: reencrypt,
  },
  retentionPolicy: {
    pattern: new RegExp("^documents/retention\\.enc$", "u"),
    path: "documents/retention.enc",
    persistence: "persistent",
    protection: "encrypted",
    reads: [1],
    writes: [1],
    domains: ["retentionPolicy"],
    rekey: reencrypt,
  },
  documentObjects: {
    pattern: new RegExp("^documents/objects/[a-f0-9-]{36}\\.(?:note|canvas|plugin|pluginstore)\\.enc$", "u"),
    path: "documents/objects/{id}.{note|canvas|plugin|pluginstore}.enc",
    persistence: "persistent",
    protection: "encrypted",
    reads: [1],
    writes: [1],
    domains: ["notePrefix", "canvasPrefix", "pluginPrefix", "pluginStorePrefix"],
    rekey: { normal: "reencrypt", rotateIdentities: "rewrite-identities" },
  },
  documentHistory: {
    pattern: new RegExp("^documents/history/[a-f0-9-]{36}/(?:0|[1-9]\\d*)\\.(?:note|canvas)\\.enc$", "u"),
    path: "documents/history/{id}/{revision}.{note|canvas}.enc",
    persistence: "persistent",
    protection: "encrypted",
    reads: [1],
    writes: [1],
    domains: ["noteHistoryPrefix", "canvasHistoryPrefix"],
    rekey: { normal: "reencrypt", rotateIdentities: "rewrite-identities" },
  },
  attachmentManifest: {
    pattern: new RegExp("^documents/attachments/[a-f0-9]{64}/manifest\\.enc$", "u"),
    path: "documents/attachments/{id}/manifest.enc",
    persistence: "persistent",
    protection: "encrypted",
    reads: [1],
    writes: [1],
    domains: ["attachmentId", "attachmentManifestPrefix"],
    rekey: { normal: "reencrypt", rotateIdentities: "rewrite-identities" },
  },
  attachmentChunks: {
    pattern: new RegExp("^documents/attachments/[a-f0-9]{64}/(?:0|[1-9]\\d*)\\.chunk\\.enc$", "u"),
    path: "documents/attachments/{id}/{index}.chunk.enc",
    persistence: "persistent",
    protection: "encrypted",
    reads: [1],
    writes: [1],
    domains: ["attachmentId", "attachmentChunkPrefix"],
    rekey: { normal: "reencrypt", rotateIdentities: "rewrite-identities" },
  },
  syncChangeEnvelope: {
    limitation:
      "Re-key refuses vaults containing epoch >=2 changes before commit; epoch keys are not rotated by ordinary re-key.",
    pattern: new RegExp("^documents/sync/changes/[a-f0-9]{64}\\.change\\.enc$", "u"),
    path: "documents/sync/changes/{id}.change.enc",
    persistence: "persistent",
    protection: "encrypted",
    reads: [1, 2],
    writes: [1, 2],
    domains: ["syncChangeId", "syncChangeKey", "syncChangeKeyV2", "syncChangePrefix"],
    rekey: reset,
  },
  syncChangeBody: {
    path: "inside sync change envelope",
    persistence: "nested",
    protection: "encrypted",
    reads: [1, 2, 3],
    writes: [1, 2, 3],
    domains: ["syncChangeId"],
    rekey: reset,
  },
  syncDeviceRegistry: {
    pattern: new RegExp("^documents/sync/devices\\.enc$", "u"),
    path: "documents/sync/devices.enc",
    persistence: "persistent",
    protection: "encrypted",
    reads: [1],
    writes: [1],
    domains: ["syncDeviceRegistry"],
    rekey: reset,
  },
  syncEnrollmentRequest: {
    path: "(transferred)",
    persistence: "external",
    protection: "encrypted",
    reads: [1, 2],
    writes: [1, 2],
    domains: ["syncAuthorityKey", "syncAgreementKeyPrefix"],
    rekey: { normal: "preserve", rotateIdentities: "reset" },
  },
  syncFreshnessCheckpoint: {
    pattern: new RegExp("^documents/sync/checkpoint\\.enc$", "u"),
    path: "documents/sync/checkpoint.enc",
    persistence: "persistent",
    protection: "encrypted",
    reads: [1],
    writes: [1],
    domains: ["syncFreshnessCheckpoint"],
    rekey: reset,
  },
  syncAppliedState: {
    pattern: new RegExp("^documents/sync/applied\\.enc$", "u"),
    path: "documents/sync/applied.enc",
    persistence: "persistent",
    protection: "encrypted",
    reads: [1],
    writes: [1],
    domains: ["syncApplied"],
    rekey: reset,
  },
  syncLocalTransaction: {
    pattern: new RegExp("^documents/sync/pending-local\\.enc$", "u"),
    path: "documents/sync/pending-local.enc",
    // A crash can leave this intent behind, but recovery reads and re-keys it
    // as a live encrypted payload; classifying it as transient would silently
    // remove it from the fail-closed re-key boundary.
    persistence: "persistent",
    protection: "encrypted",
    reads: [1],
    writes: [1],
    domains: ["syncLocalTransaction"],
    rekey: reset,
  },
  syncApplyReceipt: {
    pattern: new RegExp("^documents/sync/apply-receipt\\.enc$", "u"),
    path: "documents/sync/apply-receipt.enc",
    // Same recovery rule as pending-local: temporary in lifetime, persistent
    // for on-disk classification until the owner clears it.
    persistence: "persistent",
    protection: "encrypted",
    reads: [1],
    writes: [1],
    domains: ["syncApplyReceipt"],
    rekey: reset,
  },
  syncIdentity: {
    pattern: new RegExp("^documents/sync/identity/(?:authority|[a-f0-9-]{36}(?:\\.x25519)?)\\.key\\.enc$", "u"),
    path: "documents/sync/identity/{authority|device|agreement}.key.enc",
    persistence: "persistent",
    protection: "encrypted",
    reads: [1],
    writes: [1],
    domains: ["syncAuthorityKey", "syncDeviceKeyPrefix", "syncAgreementKeyPrefix"],
    rekey: reset,
  },
  syncEpochKey: {
    pattern: new RegExp("^documents/sync/identity/epochs/(?:0|[1-9]\\d*)\\.key\\.enc$", "u"),
    path: "documents/sync/identity/epochs/{epoch}.key.enc",
    persistence: "persistent",
    protection: "encrypted",
    reads: [1],
    writes: [1],
    domains: ["syncEpochKeyPrefix", "syncEpochWrap"],
    rekey: reset,
  },
  syncBlob: {
    pattern: new RegExp("^documents/sync/blobs/[a-f0-9]{64}$", "u"),
    path: "documents/sync/blobs/{sha256}",
    persistence: "persistent",
    protection: "encrypted",
    reads: [1],
    writes: [1],
    domains: ["syncBlobKey", "attachmentChunkPrefix"],
    rekey: preserve,
  },
  vaultBackup: {
    path: "(backup archive)",
    persistence: "external",
    protection: "encrypted",
    reads: [1],
    writes: [1],
    domains: ["backupKey", "backupManifestPrefix", "backupEntryPrefix"],
    rekey: { normal: "preserve", rotateIdentities: "preserve" },
  },
  /** Plaintext write intent; recovery consumes it before ordinary document reads continue. */
  documentJournal: {
    pattern: new RegExp("^documents/journal\\.json$", "u"),
    path: "documents/journal.json",
    persistence: "transient",
    protection: "plaintext",
    reads: [1],
    writes: [1],
    domains: [],
    rekey: { normal: "preserve", rotateIdentities: "preserve" },
  },
  /** Re-key's durable commit record; it is intentionally not a live vault payload. */
  rekeyJournal: {
    path: ".rekey/journal.json",
    persistence: "transient",
    protection: "plaintext",
    reads: [1],
    writes: [1],
    domains: [],
    rekey: { normal: "preserve", rotateIdentities: "preserve" },
  },
  /** Verified replacement payloads, held only until the re-key journal installs them. */
  rekeyNewTree: {
    path: ".rekey/new/{live artifact}",
    persistence: "nested",
    protection: "encrypted",
    reads: [1],
    writes: [1],
    domains: [],
    rekey: { normal: "reencrypt", rotateIdentities: "rewrite-identities" },
  },
  /** Rollback copies created during identity rotation before final deletion. */
  rekeyOldTree: {
    path: ".rekey/old/{live artifact}",
    persistence: "nested",
    protection: "encrypted",
    reads: [1],
    writes: [1],
    domains: [],
    rekey: { normal: "preserve", rotateIdentities: "reset" },
  },
  /** TypeScript atomic-write sibling; only the exact writer shape is a crash leftover. */
  typescriptAtomicTemp: {
    path: ".{final-name}.{pid}.{uuid}.tmp",
    temporaryPattern: new RegExp("^\\..+\\.[1-9]\\d*\\.[0-9a-f-]{36}\\.tmp$", "u"),
    persistence: "transient",
    protection: "encrypted",
    reads: [1],
    writes: [1],
    domains: [],
    rekey: { normal: "preserve", rotateIdentities: "preserve" },
  },
  /** Native atomic-write sibling; UUID-only suffix differs from the TypeScript writer. */
  rustAtomicTemp: {
    path: ".{final-name}.{uuid}.tmp",
    temporaryPattern: new RegExp("^\\..+\\.[0-9a-f-]{36}\\.tmp$", "u"),
    persistence: "transient",
    protection: "encrypted",
    reads: [1],
    writes: [1],
    domains: [],
    rekey: { normal: "preserve", rotateIdentities: "preserve" },
  },
  /** The recovery slot mirror lives outside the vault and is independently encrypted. */
  recoveryKit: {
    path: "(external recovery kit)",
    persistence: "external",
    protection: "encrypted",
    reads: [1],
    writes: [1],
    domains: ["keyringSlot"],
    rekey: { normal: "preserve", rotateIdentities: "replace-keyset" },
  },
  vaultAuditLog: {
    path: "audit.log",
    persistence: "persistent",
    protection: "plaintext",
    reads: [1],
    writes: [1],
    domains: [],
    rekey: { normal: "preserve", rotateIdentities: "preserve" },
  },
  vaultAuditMetadata: {
    path: "audit.meta.json, audit.head.json",
    persistence: "persistent",
    protection: "plaintext",
    reads: [1],
    writes: [1],
    domains: [],
    rekey: { normal: "preserve", rotateIdentities: "preserve" },
  },
} as const;

/** Reject paths with no declared compatibility and re-key policy. */
export function artifactForPath(
  relative: string,
  catalogue: FormatCompatibility = FORMAT_COMPATIBILITY,
): FormatArtifact {
  if (
    relative.includes("\\") ||
    relative.split("/").some((part) => part === ".." || part === ".") ||
    relative.startsWith("/")
  )
    throw new Error("Uncatalogued artifact path.");
  // This classifier is the live encrypted-file boundary used by re-key. The
  // catalogue also describes plaintext journals and crash leftovers, but
  // describing them must never turn them into accepted re-key payloads.
  const matches = Object.values(catalogue).filter(
    (entry) => entry.persistence === "persistent" && entry.protection === "encrypted" && entry.pattern?.test(relative),
  );
  if (matches.length !== 1) throw new Error("Uncatalogued or ambiguous encrypted artifact: " + relative);
  return matches[0];
}

export const noteAad = (id: string): string => `${AAD.notePrefix}${id}`;
export const noteHistoryAad = (id: string, revision: number): string => `${AAD.noteHistoryPrefix}${id}:${revision}`;
export const canvasAad = (id: string): string => `${AAD.canvasPrefix}${id}`;
export const canvasHistoryAad = (id: string, revision: number): string => `${AAD.canvasHistoryPrefix}${id}:${revision}`;
export const pluginAad = (id: string): string => `${AAD.pluginPrefix}${id}`;
export const pluginStoreAad = (id: string): string => `${AAD.pluginStorePrefix}${id}`;
export const attachmentManifestAad = (id: string): string => `${AAD.attachmentManifestPrefix}${id}`;
export const attachmentChunkAad = (id: string, index: number): string => `${AAD.attachmentChunkPrefix}${id}:${index}`;
export const syncChangeAad = (id: string): string => `${AAD.syncChangePrefix}${id}`;
export const syncDeviceKeyAad = (deviceId: string): string => `${AAD.syncDeviceKeyPrefix}${deviceId}`;
export const syncAgreementKeyAad = (deviceId: string): string => `${AAD.syncAgreementKeyPrefix}${deviceId}`;
export const syncEpochKeyAad = (epoch: number): string => `${AAD.syncEpochKeyPrefix}${epoch}`;
/**
 * Binds a backup entry to its position and its path, so entries cannot be
 * reordered, swapped between paths, or moved between backups without the seal
 * failing.
 */
export const backupEntryAad = (index: number, entryPath: string): string =>
  `${AAD.backupEntryPrefix}${index}:${entryPath}`;
/**
 * Binds a backup's sealed file list to the preamble it was written under, so
 * the two halves of an archive header cannot be taken from different backups.
 */
export const backupManifestAad = (preambleDigest: string): string => `${AAD.backupManifestPrefix}${preambleDigest}`;

/**
 * Strict base64: rejects malformed alphabets, non-canonical padding, and
 * unexpected lengths. Shared so every artifact validates encodings identically.
 */
export function canonicalBase64(value: unknown, expectedBytes: number | undefined, label: string): string {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) {
    throw new Error(`Encrypted payload has malformed ${label}.`);
  }
  const decoded = Buffer.from(value, "base64");
  if (expectedBytes !== undefined && decoded.length !== expectedBytes) {
    throw new Error(`Encrypted payload has invalid ${label} length.`);
  }
  if (decoded.toString("base64") !== value) {
    throw new Error(`Encrypted payload has non-canonical ${label}.`);
  }
  return value;
}
