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
  /** Versions this build can open. */
  readonly reads: readonly number[];
  /** Versions this build produces. Always a subset of `reads`. */
  readonly writes: readonly number[];
}

export type FormatCompatibility = Readonly<Record<string, FormatArtifact>>;

export const FORMAT_COMPATIBILITY: FormatCompatibility = {
  vaultKeyring: { path: "keyring.json", reads: [2], writes: [2] },
  vaultKeyset: { path: "keyring.json (wrapped)", reads: [1, 2], writes: [1, 2] },
  encryptedEnvelope: { path: "*.kv.enc", reads: [0, 1], writes: [1] },
  documentManifest: { path: "documents/manifest.json", reads: [1, 2], writes: [1, 2] },
  documentPayload: { path: "documents/objects/*.enc", reads: [1], writes: [1] },
  syncChangeEnvelope: { path: "documents/sync/changes/*.change.enc", reads: [1, 2, 3], writes: [1, 2, 3] },
  syncDeviceCertificate: { path: "documents/sync/devices.enc", reads: [1, 2], writes: [1, 2] },
  syncDeviceRegistry: { path: "documents/sync/devices.enc", reads: [1, 2], writes: [1, 2] },
  syncEnrollmentRequest: { path: "(transferred)", reads: [1, 2], writes: [1, 2] },
  syncFreshnessCheckpoint: { path: "documents/sync/checkpoint.enc", reads: [1], writes: [1] },
  syncAppliedState: { path: "documents/sync/applied.enc", reads: [1], writes: [1] },
  retentionPolicy: { path: "documents/retention.enc", reads: [1], writes: [1] },
  vaultBackup: { path: "(backup archive)", reads: [1], writes: [1] },
} as const;

/**
 * Fixed AEAD domain-separation strings. Suffixed builders below cover the
 * artifacts whose AAD includes an identifier.
 */
export const AAD = {
  keyringSlot: "secondbrain-vault:keyring-slot:v1",
  documentKeyCheck: "secondbrain-vault:document-key:v1",
  documentIndex: "secondbrain-vault:document-index:v1",
  pluginPolicy: "secondbrain-vault:plugin-policy:v1",
  retentionPolicy: "secondbrain-vault:retention-policy:v1",
  attachmentId: "secondbrain-vault:attachment-id:v1\0",
  syncChangeId: "secondbrain-vault:sync-change-id:v1",
  syncBlobKey: "secondbrain-vault:sync-blob-key:v1",
  syncChangeKey: "secondbrain-vault:sync-change-key:v1",
  syncChangeKeyV2: "secondbrain-vault:sync-change-key:v2",
  syncChangePrefix: "secondbrain-vault:sync-change:v1:",
  syncApplied: "secondbrain-vault:sync-applied:v1",
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

export const noteAad = (id: string): string => `${AAD.notePrefix}${id}`;
export const noteHistoryAad = (id: string, revision: number): string =>
  `${AAD.noteHistoryPrefix}${id}:${revision}`;
export const canvasAad = (id: string): string => `${AAD.canvasPrefix}${id}`;
export const canvasHistoryAad = (id: string, revision: number): string =>
  `${AAD.canvasHistoryPrefix}${id}:${revision}`;
export const pluginAad = (id: string): string => `${AAD.pluginPrefix}${id}`;
export const pluginStoreAad = (id: string): string => `${AAD.pluginStorePrefix}${id}`;
export const attachmentManifestAad = (id: string): string => `${AAD.attachmentManifestPrefix}${id}`;
export const attachmentChunkAad = (id: string, index: number): string =>
  `${AAD.attachmentChunkPrefix}${id}:${index}`;
export const syncChangeAad = (id: string): string => `${AAD.syncChangePrefix}${id}`;
export const syncDeviceKeyAad = (deviceId: string): string => `${AAD.syncDeviceKeyPrefix}${deviceId}`;
export const syncAgreementKeyAad = (deviceId: string): string =>
  `${AAD.syncAgreementKeyPrefix}${deviceId}`;
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
export const backupManifestAad = (preambleDigest: string): string =>
  `${AAD.backupManifestPrefix}${preambleDigest}`;

/**
 * Strict base64: rejects malformed alphabets, non-canonical padding, and
 * unexpected lengths. Shared so every artifact validates encodings identically.
 */
export function canonicalBase64(value: unknown, expectedBytes: number | undefined, label: string): string {
  if (
    typeof value !== "string" ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)
  ) {
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
