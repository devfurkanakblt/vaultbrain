import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  decryptDocument,
  encryptDocument,
  openDocumentKey,
  type DocumentKeySession,
  type DocumentPayload,
  type DocumentReadKey,
} from "./document-crypto.js";
import {
  assertNoSymlinkComponents,
  assertNotSymlink,
  readTextFileLimited,
  writeFileAtomic,
} from "./fs-safe.js";
import { resolveInside } from "./safety.js";
import { withVaultLock } from "./vault-lock.js";
import {
  ATTACHMENT_CHUNK_SIZE,
  DocumentVault,
  MAX_ATTACHMENT_SIZE,
  type AttachmentInfo,
  type CanvasDocument,
  type CanvasInput,
  type NoteDocument,
  type NoteInput,
  type NoteSummary,
  type PluginPackage,
  type PluginSecurityPolicy,
  type PluginSummary,
} from "./documents.js";
import {
  AAD,
  canonicalBase64,
  syncAgreementKeyAad,
  syncChangeAad,
  syncDeviceKeyAad,
} from "./format-version.js";
import {
  agreementPrivateKeyFromBase64,
  agreementPublicKeyFromBase64,
  exportAgreementPublicKey,
  generateAgreementKeyPair,
  validateEpochKeyWrap,
  EPOCH_KEY_BYTES,
  hasEpochKey,
  readEpochKey,
  saveEpochKey,
  wrapEpochKey,
  unwrapEpochKey,
  type EpochKeyWrap,
} from "./sync-epoch.js";
import { SyncApplyEngine, planSyncApplication, type SyncApplyEffects } from "./sync/engine.js";
import { SyncBlobStore, deriveBlobKey, openAttachmentBlob, sealAttachmentBlobs } from "./sync-blobs.js";
import {
  SyncApplyReceiptStore,
  SyncLocalTransaction,
  type SyncApplyLiveIdentity,
  type SyncApplyReceipt,
  type SyncLocalStorageOperation,
  type SyncTransactionEffects,
  type SyncTransactionOptions,
} from "./sync/transaction.js";

const MAX_CHANGE_BYTES = 8 * 1024 * 1024;
const MAX_ENVELOPE_BYTES = 12 * 1024 * 1024;
const MAX_DEVICE_REGISTRY_BYTES = 8 * 1024 * 1024;
const MAX_CHANGE_COUNT = 50_000;
const MAX_CHANGE_STORE_BYTES = 512 * 1024 * 1024;
const MAX_PARENTS = 256;
const MAX_JSON_DEPTH = 32;
const MAX_JSON_NODES = 100_000;
const CHANGE_ID = /^[a-f0-9]{64}$/u;
const DEVICE_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const OBJECT_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/u;

export type SyncObjectType = "note" | "canvas" | "attachment" | "plugin" | "vault";
export type SyncOperation = "put" | "delete";
export type SyncJson = null | boolean | number | string | SyncJson[] | { [key: string]: SyncJson };

export interface SyncMutation {
  objectType: SyncObjectType;
  objectId: string;
  operation: SyncOperation;
  baseRevision: number | null;
  revision: number;
  value: SyncJson;
}

export interface SyncChangeBody {
  version: 1 | 2 | 3;
  deviceId: string;
  sequence: number;
  previousDeviceChange: string | null;
  parents: string[];
  createdAt: string;
  mutation: SyncMutation;
  authorization?: SyncChangeAuthorization;
}

export interface SyncChangeAuthorization {
  certificateSerial: number;
  signature: string;
}

export interface EncryptedSyncChange {
  version: 1 | 2;
  id: string;
  /** Present on version 2 envelopes only; always 2 or greater. */
  epoch?: number;
  payload: DocumentPayload;
}

export interface SyncChangeKeys {
  /** Permanent identity key: rotating envelope encryption must not rewrite DAG IDs. */
  syncChangeKey: Buffer;
  /** Rotatable key used only to derive the per-change encryption key. */
  syncEnvelopeKey: Buffer;
  /**
   * The outgoing envelope key of a re-key that has not finished re-sealing
   * every change body. Read-only, like `legacyKey`.
   */
  retiringSyncEnvelopeKey?: Buffer;
  /** Optional pre-keyring key used only while reading already-written changes. */
  legacyKey?: Buffer;
  /**
   * Recomputes the id of a change written before the identity key was
   * separated from the documents key. Never decrypts anything; it exists only
   * so a re-key can re-seal such a change's body without renaming it.
   */
  legacyIdentityKey?: Buffer;
}

export type SyncChangeKeyMaterial = Buffer | SyncChangeKeys;

/** Resolves an epoch number to its identity/envelope key material. */
export type SyncEpochKeyResolver = (epoch: number) => SyncChangeKeyMaterial;

export interface SyncChange extends SyncChangeBody {
  id: string;
}

export interface SyncEnrollmentRequest {
  version: 1 | 2;
  deviceId: string;
  name: string;
  publicKey: string;
  /** base64 X25519 SPKI DER. Present on version 2 requests only. */
  keyAgreementKey?: string;
  requestedAt: string;
  nonce: string;
  proof: string;
}

export interface SyncDeviceCertificate {
  version: 1 | 2;
  serial: number;
  deviceId: string;
  name: string;
  publicKey: string;
  /** base64 X25519 SPKI DER. Present on version 2 certificates only. */
  keyAgreementKey?: string;
  enrolledAt: string;
  epoch: number;
}

export interface SyncDeviceRecord {
  certificate: SyncDeviceCertificate;
  certificateSignature: string;
  revokedAt?: string;
  revokedAfterSequence?: number;
}

export interface SyncDeviceRegistryBody {
  version: 1 | 2;
  revision: number;
  epoch: number;
  authorityPublicKey: string;
  updatedAt: string;
  legacyChangeIds: string[];
  devices: SyncDeviceRecord[];
  /** Present at epoch 2 and above: one wrap per active device. */
  epochKeys?: EpochKeyWrap[];
}

export interface SignedSyncDeviceRegistry {
  body: SyncDeviceRegistryBody;
  signature: string;
}

export interface EncryptedSyncDeviceRegistry {
  version: 1;
  payload: DocumentPayload;
}

export interface SyncFreshnessCheckpointBody {
  version: 1;
  sequence: number;
  authorityFingerprint: string;
  registryRevision: number;
  epoch: number;
  changeCount: number;
  heads: string[];
  createdAt: string;
  previousCheckpoint: string | null;
}

export interface SignedSyncFreshnessCheckpoint {
  id: string;
  body: SyncFreshnessCheckpointBody;
  signature: string;
}

export interface EncryptedSyncFreshnessCheckpoint {
  version: 1;
  payload: DocumentPayload;
}

export interface SyncVerification {
  changes: number;
  devices: number;
  heads: string[];
}

export interface SyncResolution {
  objectType: SyncObjectType;
  objectId: string;
  status: "missing" | "clean" | "conflict";
  winner?: SyncChange;
  conflicts: SyncChange[];
  heads: string[];
}

export interface SyncAppliedObject {
  changeId: string;
  revision: number;
  operation: SyncOperation;
}

interface SyncAppliedState {
  version: 1;
  objects: Record<string, SyncAppliedObject>;
}

export interface SyncApplyResult {
  objectType: SyncObjectType;
  objectId: string;
  changeId: string;
  revision: number;
  applied: number;
  alreadyApplied: boolean;
  /** Present only when unresolved remote heads left live storage untouched. */
  conflict?: true;
  heads?: string[];
}

interface NoteSyncSnapshot {
  path: string;
  title: string;
  body: string;
  aliases: string[];
  tags: string[];
  properties: NoteDocument["properties"];
  createdAt: string;
  frontmatterSource?: string;
}

interface CanvasSyncSnapshot {
  path: string;
  title: string;
  nodes: CanvasDocument["nodes"];
  edges: CanvasDocument["edges"];
  createdAt: string;
}

export interface InlineAttachmentSyncSnapshot {
  filename: string;
  mime: string;
  data: string;
}

export interface BlobAttachmentSyncSnapshot {
  filename: string;
  mime: string;
  size: number;
  chunks: number;
  blobs: string[];
}

export type AttachmentSyncSnapshot = InlineAttachmentSyncSnapshot | BlobAttachmentSyncSnapshot;

/** An attachment snapshot may reference at most this many blobs, matching the parents cap. */
export const MAX_ATTACHMENT_BLOBS = 256;
const BLOB_ID_PATTERN = /^[0-9a-f]{64}$/u;

interface PluginSyncSnapshot {
  manifest: PluginPackage["manifest"];
  source: string;
}

interface PluginLocalStorageInput extends PluginSyncSnapshot {
  localEnabled: boolean;
}

const PLUGIN_POLICY_OBJECT_ID = "plugin-policy";

function validateOptionalDeviceId(passphrase: string, deviceId: string | undefined): string {
  if (deviceId !== undefined && !DEVICE_ID.test(deviceId)) {
    throw new Error("Sync device ID must be a lowercase UUID.");
  }
  return passphrase;
}

function sameSyncValue(left: SyncJson, right: SyncJson): boolean {
  return canonicalSyncJson(left) === canonicalSyncJson(right);
}

/**
 * Compare two captured storage snapshots. Two seals of the same attachment
 * carry different blob ids by design - the AEAD nonce is fresh each time - so
 * an attachment is compared on the identity the change already content-
 * addresses, never on the snapshot bytes.
 */
function sameStorageValue(objectType: SyncObjectType, left: SyncJson, right: SyncJson): boolean {
  if (objectType !== "attachment") return sameSyncValue(left, right);
  if (left === null || right === null) return left === right;
  return sameAttachmentSnapshot(left, right);
}

function noteSummary(note: NoteDocument): NoteSummary {
  return {
    id: note.id,
    path: note.path,
    title: note.title,
    aliases: note.aliases,
    tags: note.tags,
    updatedAt: note.updatedAt,
    revision: note.revision,
  };
}

function assertUnicode(value: string, label: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error(`${label} contains an unpaired surrogate.`);
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new Error(`${label} contains an unpaired surrogate.`);
    }
  }
}

function validateJson(value: unknown, depth = 0, counter = { nodes: 0 }): asserts value is SyncJson {
  counter.nodes += 1;
  if (counter.nodes > MAX_JSON_NODES) throw new Error("Sync change JSON is too complex.");
  if (depth > MAX_JSON_DEPTH) throw new Error("Sync change JSON is nested too deeply.");
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Sync change JSON contains a non-finite number.");
    return;
  }
  if (typeof value === "string") {
    assertUnicode(value, "Sync change JSON");
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) validateJson(item, depth + 1, counter);
    return;
  }
  if (typeof value !== "object") throw new Error("Sync changes may contain JSON values only.");
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error("Sync change JSON must use plain objects.");
  }
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    assertUnicode(key, "Sync change key");
    if (key === "__proto__" || key === "prototype" || key === "constructor") {
      throw new Error(`Unsafe sync change key: ${key}`);
    }
    validateJson(item, depth + 1, counter);
  }
}

/** RFC 8785-compatible canonical JSON for the JSON subset accepted above. */
export function canonicalSyncJson(value: SyncJson): string {
  validateJson(value);
  return canonicalJsonUnchecked(value);
}

function canonicalJsonUnchecked(value: SyncJson): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJsonUnchecked).join(",")}]`;
  const entries = Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJsonUnchecked(value[key])}`);
  return `{${entries.join(",")}}`;
}

function integer(value: unknown, minimum: number, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) {
    throw new Error(`${label} must be a safe integer of at least ${minimum}.`);
  }
  return value as number;
}

function validateMutation(value: unknown): SyncMutation {
  const mutation = value as SyncMutation | undefined;
  if (!mutation || typeof mutation !== "object" || Array.isArray(mutation)) {
    throw new Error("Sync change mutation must be an object.");
  }
  if (!["note", "canvas", "attachment", "plugin", "vault"].includes(mutation.objectType)) {
    throw new Error("Unsupported sync object type.");
  }
  if (typeof mutation.objectId !== "string" || !OBJECT_ID.test(mutation.objectId)) {
    throw new Error("Invalid sync object ID.");
  }
  if (mutation.operation !== "put" && mutation.operation !== "delete") {
    throw new Error("Unsupported sync operation.");
  }
  const revision = integer(mutation.revision, 1, "Sync revision");
  const baseRevision = mutation.baseRevision === null ? null : integer(mutation.baseRevision, 0, "Sync base revision");
  if ((baseRevision === null && revision !== 1) || (baseRevision !== null && revision !== baseRevision + 1)) {
    throw new Error("A sync revision must advance exactly one step from its base revision.");
  }
  validateJson(mutation.value);
  if (mutation.operation === "delete" && mutation.value !== null) {
    throw new Error("A delete sync change cannot carry a value.");
  }
  if (mutation.operation === "put" && mutation.value === null) {
    throw new Error("A put sync change must carry a value.");
  }
  return {
    objectType: mutation.objectType,
    objectId: mutation.objectId,
    operation: mutation.operation,
    baseRevision,
    revision,
    value: structuredClone(mutation.value),
  };
}

function validateChangeAuthorization(value: unknown): SyncChangeAuthorization {
  const authorization = value as SyncChangeAuthorization | undefined;
  if (!authorization || typeof authorization !== "object" || Array.isArray(authorization)) {
    throw new Error("A version 2 sync change requires device authorization.");
  }
  return {
    certificateSerial: integer(authorization.certificateSerial, 1, "Sync certificate serial"),
    signature: canonicalBase64(authorization.signature, 64, "device signature"),
  };
}

/**
 * The branch `parseAttachmentSnapshot` takes: a put whose attachment snapshot
 * references blobs instead of carrying inline base64. Deliberately structural
 * and non-throwing, because body validation has always deferred snapshot
 * well-formedness to the reader that actually needs the bytes.
 */
function carriesBlobAttachmentSnapshot(mutation: SyncMutation): boolean {
  if (mutation.objectType !== "attachment" || mutation.operation !== "put") return false;
  const value = mutation.value;
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const raw = value as Record<string, SyncJson>;
  return raw.data === undefined && raw.blobs !== undefined;
}

/**
 * Version 3 exists so that a client which only understands the inline
 * attachment form refuses a blob manifest at the version check, instead of
 * accepting the version and then choking on a snapshot shape it has never seen.
 * It is an *authorized* version: a device with no registry has no signature to
 * offer, so its manifest stays on the version 1 ladder, which has no version 3
 * counterpart.
 */
function changeBodyVersion(mutation: SyncMutation, authorized: boolean): 1 | 2 | 3 {
  if (!authorized) return 1;
  return carriesBlobAttachmentSnapshot(mutation) ? 3 : 2;
}

export function validateSyncChangeBody(value: unknown): SyncChangeBody {
  const body = value as SyncChangeBody | undefined;
  if (
    !body ||
    typeof body !== "object" ||
    Array.isArray(body) ||
    (body.version !== 1 && body.version !== 2 && body.version !== 3)
  ) {
    throw new Error("Unsupported or invalid sync change.");
  }
  if (typeof body.deviceId !== "string" || !DEVICE_ID.test(body.deviceId)) {
    throw new Error("Sync device ID must be a lowercase UUID.");
  }
  const sequence = integer(body.sequence, 1, "Sync device sequence");
  const previousDeviceChange = body.previousDeviceChange;
  if (
    previousDeviceChange !== null &&
    (typeof previousDeviceChange !== "string" || !CHANGE_ID.test(previousDeviceChange))
  ) {
    throw new Error("Invalid previous device change ID.");
  }
  if (!Array.isArray(body.parents) || body.parents.length > MAX_PARENTS) {
    throw new Error(`A sync change may have at most ${MAX_PARENTS} parents.`);
  }
  const parents = [...new Set(body.parents)];
  if (parents.length !== body.parents.length || parents.some((id) => typeof id !== "string" || !CHANGE_ID.test(id))) {
    throw new Error("Sync parents must be unique change IDs.");
  }
  parents.sort();
  if ((sequence === 1) !== (previousDeviceChange === null)) {
    throw new Error("Only the first device change may omit its previous device change.");
  }
  if (previousDeviceChange && !parents.includes(previousDeviceChange)) {
    throw new Error("The previous device change must also be a causal parent.");
  }
  const timestamp = typeof body.createdAt === "string" ? Date.parse(body.createdAt) : Number.NaN;
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== body.createdAt) {
    throw new Error("Sync change timestamp must be a canonical ISO timestamp.");
  }
  const normalized: SyncChangeBody = {
    version: body.version,
    deviceId: body.deviceId,
    sequence,
    previousDeviceChange,
    parents,
    createdAt: body.createdAt,
    mutation: validateMutation(body.mutation),
  };
  if (body.version === 1) {
    if (body.authorization !== undefined) {
      throw new Error("A legacy sync change cannot carry device authorization.");
    }
  } else {
    normalized.authorization = validateChangeAuthorization(body.authorization);
  }
  const blobForm = carriesBlobAttachmentSnapshot(normalized.mutation);
  if (normalized.version === 3 && !blobForm) {
    throw new Error("A version 3 sync change must carry an attachment blob manifest.");
  }
  if (normalized.version === 2 && blobForm) {
    throw new Error("An attachment blob manifest requires a version 3 sync change.");
  }
  const bytes = Buffer.byteLength(canonicalSyncJson(normalized as unknown as SyncJson), "utf8");
  if (bytes > MAX_CHANGE_BYTES) throw new Error("Sync change exceeds 8 MiB.");
  return normalized;
}

function changeAuthorizationPayload(body: SyncChangeBody): Buffer {
  if (body.version === 1 || !body.authorization) {
    throw new Error("Only authorized sync changes have a device signature payload.");
  }
  const payload = {
    // The real version, so the signature binds the generation of the format the
    // body claims to be. Pinning a literal here would leave a 2<->3 relabelling
    // signature-valid, resting the whole guarantee on the change id alone.
    version: body.version,
    deviceId: body.deviceId,
    sequence: body.sequence,
    previousDeviceChange: body.previousDeviceChange,
    parents: body.parents,
    createdAt: body.createdAt,
    mutation: body.mutation,
    authorization: { certificateSerial: body.authorization.certificateSerial },
  };
  return Buffer.from(canonicalSyncJson(payload as unknown as SyncJson), "utf8");
}

function changeId(body: SyncChangeBody, key: Buffer, epoch: number): string {
  return crypto
    .createHmac("sha256", key)
    .update(AAD.syncChangeId)
    .update("\0")
    .update(epoch === 1 ? "" : `${epoch}\0`)
    .update(canonicalSyncJson(body as unknown as SyncJson))
    .digest("hex");
}

function changeEncryptionKey(key: Buffer, id: string, epoch: number): Buffer {
  return crypto
    .createHmac("sha256", key)
    .update(epoch === 1 ? AAD.syncChangeKey : AAD.syncChangeKeyV2)
    .update("\0")
    .update(id)
    .digest();
}

function splitSyncKeys(keys: SyncChangeKeyMaterial): SyncChangeKeys {
  return Buffer.isBuffer(keys)
    ? { syncChangeKey: keys, syncEnvelopeKey: keys }
    : keys;
}

export function sealSyncChange(
  body: SyncChangeBody,
  keys: SyncChangeKeyMaterial,
  epoch = 1,
): EncryptedSyncChange {
  if (!Number.isSafeInteger(epoch) || epoch < 1) throw new Error("A sync epoch must be a positive integer.");
  const normalized = validateSyncChangeBody(body);
  const canonical = canonicalSyncJson(normalized as unknown as SyncJson);
  const { syncChangeKey, syncEnvelopeKey } = splitSyncKeys(keys);
  // A structured key pair is the keyring-native form: its identity key is
  // intentionally epoch-independent. A bare Buffer remains the legacy API,
  // including the old epoch-bound IDs needed to open existing fixtures.
  const id = changeId(normalized, syncChangeKey, Buffer.isBuffer(keys) ? epoch : 1);
  const envelopeKey = changeEncryptionKey(syncEnvelopeKey, id, epoch);
  try {
    const payload = encryptDocument(canonical, envelopeKey, syncChangeAad(id));
    return epoch === 1 ? { version: 1, id, payload } : { version: 2, id, epoch, payload };
  } finally {
    envelopeKey.fill(0);
  }
}

function validateEnvelope(value: unknown): EncryptedSyncChange {
  const envelope = value as EncryptedSyncChange | undefined;
  if (
    !envelope ||
    typeof envelope !== "object" ||
    Array.isArray(envelope) ||
    (envelope.version !== 1 && envelope.version !== 2)
  ) {
    throw new Error("Unsupported or invalid encrypted sync envelope.");
  }
  if (envelope.version === 2) {
    if (!Number.isSafeInteger(envelope.epoch) || (envelope.epoch as number) < 2) {
      throw new Error("A version 2 sync envelope must declare an epoch of 2 or above.");
    }
  } else if (envelope.epoch !== undefined) {
    throw new Error("A version 1 sync envelope cannot declare an epoch.");
  }
  if (typeof envelope.id !== "string" || !CHANGE_ID.test(envelope.id)) {
    throw new Error("Invalid encrypted sync change ID.");
  }
  const payload = envelope.payload as DocumentPayload | undefined;
  if (
    !payload ||
    payload.version !== 1 ||
    typeof payload.ciphertext !== "string" ||
    payload.ciphertext.length > Math.ceil((MAX_CHANGE_BYTES * 4) / 3) + 16
  ) {
    throw new Error("Invalid encrypted sync payload.");
  }
  canonicalBase64(payload.iv, 12, "nonce");
  canonicalBase64(payload.authTag, 16, "authentication tag");
  canonicalBase64(payload.ciphertext, undefined, "ciphertext");
  return structuredClone(envelope);
}

/** Structural validation available to an opaque relay that does not hold vault keys. */
export function validateRelayEnvelope(value: unknown): EncryptedSyncChange {
  return validateEnvelope(value);
}

/** Structural validation for encrypted control artifacts whose plaintext remains relay-opaque. */
export function validateRelayArtifactEnvelope(
  value: unknown,
): EncryptedSyncDeviceRegistry | EncryptedSyncFreshnessCheckpoint {
  const envelope = value as EncryptedSyncDeviceRegistry | EncryptedSyncFreshnessCheckpoint | undefined;
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope) || envelope.version !== 1) {
    throw new Error("Unsupported or invalid encrypted sync control artifact.");
  }
  const payload = envelope.payload as DocumentPayload | undefined;
  if (
    !payload ||
    payload.version !== 1 ||
    typeof payload.ciphertext !== "string" ||
    payload.ciphertext.length > Math.ceil((MAX_DEVICE_REGISTRY_BYTES * 4) / 3) + 16
  ) {
    throw new Error("Invalid encrypted sync control payload.");
  }
  canonicalBase64(payload.iv, 12, "nonce");
  canonicalBase64(payload.authTag, 16, "authentication tag");
  canonicalBase64(payload.ciphertext, undefined, "ciphertext");
  return structuredClone(envelope);
}

function canonicalTimestamp(value: unknown, label: string): string {
  const timestamp = typeof value === "string" ? Date.parse(value) : Number.NaN;
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    throw new Error(`${label} must be a canonical ISO timestamp.`);
  }
  return value as string;
}

function deviceName(value: unknown): string {
  if (typeof value !== "string" || value.trim() !== value || value.length < 1 || value.length > 80 || /[\r\n]/u.test(value)) {
    throw new Error("Sync device name must be a single line of 1-80 characters.");
  }
  return value;
}

function publicKeyFromBase64(value: unknown, label: string): crypto.KeyObject {
  const encoded = canonicalBase64(value, 44, label);
  let key: crypto.KeyObject;
  try {
    key = crypto.createPublicKey({ key: Buffer.from(encoded, "base64"), format: "der", type: "spki" });
  } catch {
    throw new Error(`${label} is not a valid Ed25519 public key.`);
  }
  if (key.asymmetricKeyType !== "ed25519") throw new Error(`${label} must be an Ed25519 public key.`);
  return key;
}

function privateKeyFromBase64(value: string, label: string): crypto.KeyObject {
  const encoded = canonicalBase64(value, 48, label);
  let key: crypto.KeyObject;
  try {
    key = crypto.createPrivateKey({ key: Buffer.from(encoded, "base64"), format: "der", type: "pkcs8" });
  } catch {
    throw new Error(`${label} is not a valid Ed25519 private key.`);
  }
  if (key.asymmetricKeyType !== "ed25519") throw new Error(`${label} must be an Ed25519 private key.`);
  return key;
}

function exportPublicKey(key: crypto.KeyObject): string {
  return key.export({ format: "der", type: "spki" }).toString("base64");
}

function exportPrivateKey(key: crypto.KeyObject): string {
  return key.export({ format: "der", type: "pkcs8" }).toString("base64");
}

function signCanonical(value: SyncJson, privateKey: crypto.KeyObject): string {
  return crypto.sign(null, Buffer.from(canonicalSyncJson(value), "utf8"), privateKey).toString("base64");
}

function verifyCanonical(value: SyncJson, signature: unknown, publicKey: crypto.KeyObject, label: string): string {
  const encoded = canonicalBase64(signature, 64, label);
  if (!crypto.verify(null, Buffer.from(canonicalSyncJson(value), "utf8"), publicKey, Buffer.from(encoded, "base64"))) {
    throw new Error(`${label} verification failed.`);
  }
  return encoded;
}

function enrollmentRequestPayload(request: Omit<SyncEnrollmentRequest, "proof">): SyncJson {
  return structuredClone(request) as unknown as SyncJson;
}

function validateEnrollmentRequest(value: unknown): SyncEnrollmentRequest {
  const request = value as SyncEnrollmentRequest | undefined;
  if (
    !request ||
    typeof request !== "object" ||
    Array.isArray(request) ||
    (request.version !== 1 && request.version !== 2)
  ) {
    throw new Error("Unsupported or invalid sync enrollment request.");
  }
  if (typeof request.deviceId !== "string" || !DEVICE_ID.test(request.deviceId)) {
    throw new Error("Enrollment device ID must be a lowercase UUID.");
  }
  const normalized: SyncEnrollmentRequest = {
    version: request.version,
    deviceId: request.deviceId,
    name: deviceName(request.name),
    publicKey: canonicalBase64(request.publicKey, 44, "enrollment public key"),
    requestedAt: canonicalTimestamp(request.requestedAt, "Enrollment request time"),
    nonce: canonicalBase64(request.nonce, 32, "enrollment nonce"),
    proof: canonicalBase64(request.proof, 64, "enrollment proof"),
  };
  if (request.version === 2) {
    agreementPublicKeyFromBase64(request.keyAgreementKey, "Enrollment key agreement key");
    normalized.keyAgreementKey = request.keyAgreementKey;
  } else if (request.keyAgreementKey !== undefined) {
    throw new Error("A version 1 enrollment request cannot carry a key agreement key.");
  }
  const publicKey = publicKeyFromBase64(normalized.publicKey, "Enrollment public key");
  verifyCanonical(
    enrollmentRequestPayload({
      version: normalized.version,
      deviceId: normalized.deviceId,
      name: normalized.name,
      publicKey: normalized.publicKey,
      ...(normalized.keyAgreementKey !== undefined ? { keyAgreementKey: normalized.keyAgreementKey } : {}),
      requestedAt: normalized.requestedAt,
      nonce: normalized.nonce,
    }),
    normalized.proof,
    publicKey,
    "Enrollment proof",
  );
  return normalized;
}

function certificatePayload(certificate: SyncDeviceCertificate): SyncJson {
  return structuredClone(certificate) as unknown as SyncJson;
}

function validateCertificate(value: unknown): SyncDeviceCertificate {
  const certificate = value as SyncDeviceCertificate | undefined;
  if (
    !certificate ||
    typeof certificate !== "object" ||
    Array.isArray(certificate) ||
    (certificate.version !== 1 && certificate.version !== 2)
  ) {
    throw new Error("Unsupported or invalid sync device certificate.");
  }
  if (typeof certificate.deviceId !== "string" || !DEVICE_ID.test(certificate.deviceId)) {
    throw new Error("Certificate device ID must be a lowercase UUID.");
  }
  const normalized: SyncDeviceCertificate = {
    version: certificate.version,
    serial: integer(certificate.serial, 1, "Device certificate serial"),
    deviceId: certificate.deviceId,
    name: deviceName(certificate.name),
    publicKey: canonicalBase64(certificate.publicKey, 44, "certificate public key"),
    enrolledAt: canonicalTimestamp(certificate.enrolledAt, "Device enrollment time"),
    epoch: integer(certificate.epoch, 1, "Device certificate epoch"),
  };
  if (certificate.version === 2) {
    // Validated as X25519 rather than by length: Ed25519 SPKI is also 44 bytes.
    agreementPublicKeyFromBase64(certificate.keyAgreementKey, "Certificate key agreement key");
    normalized.keyAgreementKey = certificate.keyAgreementKey;
  } else if (certificate.keyAgreementKey !== undefined) {
    throw new Error("A version 1 device certificate cannot carry a key agreement key.");
  }
  return normalized;
}

function registryBodyPayload(body: SyncDeviceRegistryBody): SyncJson {
  return structuredClone(body) as unknown as SyncJson;
}

function validateSignedDeviceRegistry(value: unknown): SignedSyncDeviceRegistry {
  const registry = value as SignedSyncDeviceRegistry | undefined;
  const raw = registry?.body;
  if (
    !registry ||
    typeof registry !== "object" ||
    Array.isArray(registry) ||
    !raw ||
    (raw.version !== 1 && raw.version !== 2)
  ) {
    throw new Error("Unsupported or invalid sync device registry.");
  }
  const authorityPublicKey = canonicalBase64(raw.authorityPublicKey, 44, "authority public key");
  const authorityKey = publicKeyFromBase64(authorityPublicKey, "Authority public key");
  if (!Array.isArray(raw.legacyChangeIds) || !Array.isArray(raw.devices)) {
    throw new Error("Sync device registry lists are invalid.");
  }
  const legacyChangeIds = raw.legacyChangeIds.map((id) => {
    if (typeof id !== "string" || !CHANGE_ID.test(id)) throw new Error("Registry contains an invalid legacy change ID.");
    return id;
  });
  if (new Set(legacyChangeIds).size !== legacyChangeIds.length || [...legacyChangeIds].sort().some((id, i) => id !== legacyChangeIds[i])) {
    throw new Error("Registry legacy change IDs must be unique and sorted.");
  }
  const devices = raw.devices.map((value) => {
    const record = value as SyncDeviceRecord;
    if (!record || typeof record !== "object" || Array.isArray(record)) {
      throw new Error("Registry contains an invalid device record.");
    }
    const certificate = validateCertificate(record.certificate);
    publicKeyFromBase64(certificate.publicKey, "Certificate public key");
    const certificateSignature = verifyCanonical(
      certificatePayload(certificate),
      record.certificateSignature,
      authorityKey,
      "Device certificate signature",
    );
    const normalized: SyncDeviceRecord = { certificate, certificateSignature };
    if (record.revokedAt !== undefined || record.revokedAfterSequence !== undefined) {
      normalized.revokedAt = canonicalTimestamp(record.revokedAt, "Device revocation time");
      normalized.revokedAfterSequence = integer(record.revokedAfterSequence, 0, "Device revocation sequence");
    }
    return normalized;
  });
  const deviceIds = devices.map((record) => record.certificate.deviceId);
  const serials = devices.map((record) => record.certificate.serial);
  if (
    new Set(deviceIds).size !== deviceIds.length ||
    new Set(serials).size !== serials.length ||
    [...deviceIds].sort().some((id, i) => id !== deviceIds[i])
  ) {
    throw new Error("Registry devices must have unique IDs and serials and be sorted by ID.");
  }
  const body: SyncDeviceRegistryBody = {
    version: raw.version,
    revision: integer(raw.revision, 1, "Device registry revision"),
    epoch: integer(raw.epoch, 1, "Device registry epoch"),
    authorityPublicKey,
    updatedAt: canonicalTimestamp(raw.updatedAt, "Device registry update time"),
    legacyChangeIds,
    devices,
  };
  // The registry version and its epoch move together: version 2 exists to carry
  // wrapped epoch keys, and epoch 1 is sealed with the vault key. Checking the
  // pair here, before the keys themselves, keeps an epoch-1 version-2 registry
  // to one message whether or not it carried epoch keys.
  if ((raw.version === 2) !== (body.epoch >= 2)) {
    throw new Error(
      "A device registry is version 2 exactly when its epoch is 2 or above: epoch 1 is sealed with the vault key.",
    );
  }
  if (raw.version === 2) {
    if (!Array.isArray(raw.epochKeys)) throw new Error("A version 2 device registry must list epoch keys.");
    body.epochKeys = raw.epochKeys.map((wrap) => validateEpochKeyWrap(wrap));
  } else if (raw.epochKeys !== undefined) {
    throw new Error("A version 1 device registry cannot carry epoch keys.");
  }

  const active = devices.filter((record) => !record.revokedAt);
  for (const record of devices) {
    if (record.certificate.epoch > body.epoch) {
      throw new Error("A device certificate cannot target a future registry epoch.");
    }
  }

  if (body.epoch >= 2) {
    // Restates the pair rule above, and is what narrows epochKeys below.
    if (body.version !== 2 || !body.epochKeys) {
      throw new Error("A registry at epoch 2 or above must be version 2 and carry epoch keys.");
    }
    for (const record of active) {
      if (record.certificate.version !== 2) {
        throw new Error("An active device at epoch 2 or above needs a version 2 certificate.");
      }
      if (record.certificate.epoch !== body.epoch) {
        throw new Error("An active device certificate must sit at the current registry epoch.");
      }
    }
    for (const record of devices) {
      if (record.revokedAt && record.certificate.epoch >= body.epoch) {
        throw new Error("A revoked device certificate must sit below the current registry epoch.");
      }
    }
    const wrapped = body.epochKeys.map((wrap) => wrap.deviceId);
    const expected = active.map((record) => record.certificate.deviceId).sort();
    if (new Set(wrapped).size !== wrapped.length) {
      throw new Error("Registry epoch keys must not repeat a device.");
    }
    if ([...wrapped].sort().some((id, index) => id !== wrapped[index])) {
      throw new Error("Registry epoch keys must be sorted by device ID.");
    }
    if (wrapped.length !== expected.length || expected.some((id, index) => id !== wrapped[index])) {
      throw new Error("Registry epoch keys must cover exactly the active devices.");
    }
  }

  const signature = verifyCanonical(registryBodyPayload(body), registry.signature, authorityKey, "Device registry signature");
  return { body, signature };
}

export function syncRegistryFingerprint(registry: SignedSyncDeviceRegistry): string {
  return crypto.createHash("sha256").update(Buffer.from(registry.body.authorityPublicKey, "base64")).digest("hex");
}

function registryPath(rootDir: string): string {
  return resolveInside(rootDir, path.join("sync", "devices.enc"));
}

function identityDir(rootDir: string): string {
  return resolveInside(rootDir, path.join("sync", "identity"));
}

function authorityKeyPath(rootDir: string): string {
  return resolveInside(identityDir(rootDir), "authority.key.enc");
}

function deviceKeyPath(rootDir: string, deviceId: string): string {
  if (!DEVICE_ID.test(deviceId)) throw new Error("Sync device ID must be a lowercase UUID.");
  return resolveInside(identityDir(rootDir), `${deviceId}.key.enc`);
}

function agreementKeyPath(rootDir: string, deviceId: string): string {
  if (!DEVICE_ID.test(deviceId)) throw new Error("Sync device ID must be a lowercase UUID.");
  return resolveInside(identityDir(rootDir), `${deviceId}.x25519.key.enc`);
}

function readAgreementKey(rootDir: string, vaultKey: DocumentReadKey, deviceId: string): crypto.KeyObject {
  const filePath = agreementKeyPath(rootDir, deviceId);
  if (!fs.existsSync(filePath)) {
    throw new Error(`This device has no sync key agreement key; re-enroll device ${deviceId}.`);
  }
  assertNotSymlink(filePath);
  const payload = JSON.parse(
    readTextFileLimited(filePath, 64 * 1024, "Sync device agreement key"),
  ) as DocumentPayload;
  return agreementPrivateKeyFromBase64(
    decryptDocument(payload, vaultKey, syncAgreementKeyAad(deviceId)),
    "Sync device agreement key",
  );
}

function saveAgreementKey(
  rootDir: string,
  vaultKey: Buffer,
  deviceId: string,
  key: crypto.KeyObject,
): void {
  writeFileAtomic(
    agreementKeyPath(rootDir, deviceId),
    JSON.stringify(
      encryptDocument(
        key.export({ format: "der", type: "pkcs8" }).toString("base64"),
        vaultKey,
        syncAgreementKeyAad(deviceId),
      ),
    ),
    { mode: 0o600 },
  );
}

function encryptPrivateKey(key: crypto.KeyObject, vaultKey: Buffer, aad: string): DocumentPayload {
  return encryptDocument(exportPrivateKey(key), vaultKey, aad);
}

function readPrivateKey(filePath: string, vaultKey: DocumentReadKey, aad: string, label: string): crypto.KeyObject {
  if (!fs.existsSync(filePath)) throw new Error(`${label} is not available on this device.`);
  assertNotSymlink(filePath);
  const payload = JSON.parse(readTextFileLimited(filePath, 64 * 1024, label)) as DocumentPayload;
  return privateKeyFromBase64(decryptDocument(payload, vaultKey, aad), label);
}

function savePrivateKey(filePath: string, key: crypto.KeyObject, vaultKey: Buffer, aad: string): void {
  writeFileAtomic(filePath, JSON.stringify(encryptPrivateKey(key, vaultKey, aad)), { mode: 0o600 });
}

function readDeviceRegistry(rootDir: string, vaultKey: DocumentReadKey): SignedSyncDeviceRegistry | undefined {
  const filePath = registryPath(rootDir);
  if (!fs.existsSync(filePath)) return undefined;
  assertNotSymlink(filePath);
  const envelope = JSON.parse(
    readTextFileLimited(filePath, MAX_DEVICE_REGISTRY_BYTES, "Sync device registry"),
  ) as EncryptedSyncDeviceRegistry;
  if (!envelope || envelope.version !== 1 || !envelope.payload) {
    throw new Error("Unsupported or invalid encrypted sync device registry.");
  }
  const plaintext = decryptDocument(envelope.payload, vaultKey, AAD.syncDeviceRegistry);
  return validateSignedDeviceRegistry(JSON.parse(plaintext));
}

function encryptedRegistry(registry: SignedSyncDeviceRegistry, vaultKey: Buffer): EncryptedSyncDeviceRegistry {
  return {
    version: 1,
    payload: encryptDocument(canonicalSyncJson(registry as unknown as SyncJson), vaultKey, AAD.syncDeviceRegistry),
  };
}

function saveDeviceRegistry(rootDir: string, vaultKey: Buffer, registry: SignedSyncDeviceRegistry): void {
  const normalized = validateSignedDeviceRegistry(registry);
  writeFileAtomic(registryPath(rootDir), JSON.stringify(encryptedRegistry(normalized, vaultKey)), { mode: 0o600 });
}

function signRegistryBody(body: SyncDeviceRegistryBody, authorityKey: crypto.KeyObject): SignedSyncDeviceRegistry {
  const normalizedBody = structuredClone(body);
  normalizedBody.devices.sort((left, right) => left.certificate.deviceId.localeCompare(right.certificate.deviceId));
  normalizedBody.legacyChangeIds.sort();
  return validateSignedDeviceRegistry({
    body: normalizedBody,
    signature: signCanonical(registryBodyPayload(normalizedBody), authorityKey),
  });
}

function validateAuthorizedChanges(changes: readonly SyncChange[], registry: SignedSyncDeviceRegistry | undefined): void {
  if (!registry) return;
  const legacy = new Set(registry.body.legacyChangeIds);
  const devices = new Map(registry.body.devices.map((record) => [record.certificate.deviceId, record]));
  for (const change of changes) {
    if (change.version === 1) {
      if (!legacy.has(change.id)) throw new Error(`Legacy sync change ${change.id} is not authorized by the device registry.`);
      continue;
    }
    const record = devices.get(change.deviceId);
    if (!record) throw new Error(`Sync device ${change.deviceId} is not enrolled.`);
    if (change.authorization?.certificateSerial !== record.certificate.serial) {
      throw new Error(`Sync change ${change.id} uses the wrong device certificate.`);
    }
    if (record.revokedAfterSequence !== undefined && change.sequence > record.revokedAfterSequence) {
      throw new Error(`Sync device ${change.deviceId} was revoked after sequence ${record.revokedAfterSequence}.`);
    }
    const publicKey = publicKeyFromBase64(record.certificate.publicKey, "Device public key");
    const signature = Buffer.from(change.authorization.signature, "base64");
    if (!crypto.verify(null, changeAuthorizationPayload(change), publicKey, signature)) {
      throw new Error(`Sync change ${change.id} has an invalid device signature.`);
    }
  }
}

function enrollmentLegacyChanges(rootDir: string, keys: SyncChangeKeys): SyncChange[] {
  const changesDir = resolveInside(rootDir, path.join("sync", "changes"));
  if (!fs.existsSync(changesDir)) return [];
  assertNoSymlinkComponents(rootDir, changesDir);
  const names = fs
    .readdirSync(changesDir)
    .filter((name) => name.endsWith(".change.enc"))
    .sort();
  if (names.length > MAX_CHANGE_COUNT) {
    throw new Error(`A sync change store may contain at most ${MAX_CHANGE_COUNT} changes.`);
  }
  let totalBytes = 0;
  const changes = names.map((name) => {
    const id = name.slice(0, -".change.enc".length);
    if (!CHANGE_ID.test(id)) throw new Error(`Invalid sync change filename: ${name}`);
    const filePath = resolveInside(changesDir, name);
    assertNotSymlink(filePath);
    totalBytes += fs.statSync(filePath).size;
    if (totalBytes > MAX_CHANGE_STORE_BYTES) {
      throw new Error("The sync change store exceeds its 512 MiB safety limit.");
    }
    const envelope = validateEnvelope(
      JSON.parse(readTextFileLimited(filePath, MAX_ENVELOPE_BYTES, `Sync envelope ${id}`)),
    );
    if (envelope.id !== id) throw new Error(`Sync change filename does not match its envelope: ${id}`);
    const change = openSyncChange(envelope, keys);
    if (change.version !== 1) {
      throw new Error("A signed sync change cannot exist before device enrollment is initialized.");
    }
    return change;
  });
  validateChangeSet(changes);
  return changes;
}

function signAuthorizedChange(
  body: Omit<SyncChangeBody, "authorization">,
  registry: SignedSyncDeviceRegistry,
  rootDir: string,
  vaultKey: DocumentReadKey,
): SyncChangeBody {
  const record = registry.body.devices.find((candidate) => candidate.certificate.deviceId === body.deviceId);
  if (!record) throw new Error(`Sync device ${body.deviceId} is not enrolled.`);
  if (record.revokedAt) throw new Error(`Sync device ${body.deviceId} is revoked.`);
  if (record.certificate.epoch !== registry.body.epoch) {
    throw new Error(`Sync device ${body.deviceId} is not enrolled for epoch ${registry.body.epoch}.`);
  }
  const privateKey = readPrivateKey(
    deviceKeyPath(rootDir, body.deviceId),
    vaultKey,
    syncDeviceKeyAad(body.deviceId),
    "Sync device private key",
  );
  if (exportPublicKey(crypto.createPublicKey(privateKey)) !== record.certificate.publicKey) {
    throw new Error("The local sync private key does not match the enrolled device certificate.");
  }
  const unsigned: SyncChangeBody = {
    ...body,
    // The caller already chose 2 or 3 from the mutation's shape. Only a
    // registry-less body arrives here as version 1, and enrolling it makes it 2.
    version: body.version === 1 ? 2 : body.version,
    authorization: { certificateSerial: record.certificate.serial, signature: Buffer.alloc(64).toString("base64") },
  };
  unsigned.authorization!.signature = crypto
    .sign(null, changeAuthorizationPayload(unsigned), privateKey)
    .toString("base64");
  return validateSyncChangeBody(unsigned);
}

function checkpointPath(rootDir: string): string {
  return resolveInside(rootDir, path.join("sync", "checkpoint.enc"));
}

function checkpointBodyPayload(body: SyncFreshnessCheckpointBody): SyncJson {
  return structuredClone(body) as unknown as SyncJson;
}

function checkpointId(body: SyncFreshnessCheckpointBody, signature: string): string {
  return crypto
    .createHash("sha256")
    .update(canonicalSyncJson({ body, signature } as unknown as SyncJson))
    .digest("hex");
}

function validateSignedCheckpoint(
  value: unknown,
  registry: SignedSyncDeviceRegistry,
): SignedSyncFreshnessCheckpoint {
  const checkpoint = value as SignedSyncFreshnessCheckpoint | undefined;
  const raw = checkpoint?.body;
  if (!checkpoint || typeof checkpoint !== "object" || Array.isArray(checkpoint) || !raw || raw.version !== 1) {
    throw new Error("Unsupported or invalid sync freshness checkpoint.");
  }
  if (!Array.isArray(raw.heads) || raw.heads.length > MAX_PARENTS) {
    throw new Error(`A freshness checkpoint may contain at most ${MAX_PARENTS} heads.`);
  }
  const heads = raw.heads.map((id) => {
    if (typeof id !== "string" || !CHANGE_ID.test(id)) throw new Error("Checkpoint contains an invalid head ID.");
    return id;
  });
  if (new Set(heads).size !== heads.length || [...heads].sort().some((id, index) => id !== heads[index])) {
    throw new Error("Checkpoint heads must be unique and sorted.");
  }
  const body: SyncFreshnessCheckpointBody = {
    version: 1,
    sequence: integer(raw.sequence, 1, "Checkpoint sequence"),
    authorityFingerprint:
      typeof raw.authorityFingerprint === "string" && CHANGE_ID.test(raw.authorityFingerprint)
        ? raw.authorityFingerprint
        : (() => {
            throw new Error("Checkpoint authority fingerprint is invalid.");
          })(),
    registryRevision: integer(raw.registryRevision, 1, "Checkpoint registry revision"),
    epoch: integer(raw.epoch, 1, "Checkpoint epoch"),
    changeCount: integer(raw.changeCount, 0, "Checkpoint change count"),
    heads,
    createdAt: canonicalTimestamp(raw.createdAt, "Checkpoint creation time"),
    previousCheckpoint:
      raw.previousCheckpoint === null
        ? null
        : typeof raw.previousCheckpoint === "string" && CHANGE_ID.test(raw.previousCheckpoint)
          ? raw.previousCheckpoint
          : (() => {
              throw new Error("Checkpoint predecessor is invalid.");
            })(),
  };
  if ((body.sequence === 1) !== (body.previousCheckpoint === null)) {
    throw new Error("Only the first freshness checkpoint may omit its predecessor.");
  }
  if (body.authorityFingerprint !== syncRegistryFingerprint(registry)) {
    throw new Error("Freshness checkpoint uses a different enrollment authority.");
  }
  if (body.registryRevision > registry.body.revision || body.epoch > registry.body.epoch) {
    throw new Error("Freshness checkpoint refers to a registry state that is not installed.");
  }
  const authorityKey = publicKeyFromBase64(registry.body.authorityPublicKey, "Authority public key");
  const signature = verifyCanonical(
    checkpointBodyPayload(body),
    checkpoint.signature,
    authorityKey,
    "Freshness checkpoint signature",
  );
  const id = typeof checkpoint.id === "string" && CHANGE_ID.test(checkpoint.id) ? checkpoint.id : "";
  if (id !== checkpointId(body, signature)) throw new Error("Freshness checkpoint ID does not match its content.");
  return { id, body, signature };
}

function encryptedCheckpoint(
  checkpoint: SignedSyncFreshnessCheckpoint,
  vaultKey: Buffer,
): EncryptedSyncFreshnessCheckpoint {
  return {
    version: 1,
    payload: encryptDocument(
      canonicalSyncJson(checkpoint as unknown as SyncJson),
      vaultKey,
      AAD.syncFreshnessCheckpoint,
    ),
  };
}

function readCheckpoint(
  rootDir: string,
  vaultKey: DocumentReadKey,
  registry: SignedSyncDeviceRegistry,
): SignedSyncFreshnessCheckpoint | undefined {
  const filePath = checkpointPath(rootDir);
  if (!fs.existsSync(filePath)) return undefined;
  assertNotSymlink(filePath);
  const envelope = JSON.parse(
    readTextFileLimited(filePath, 1024 * 1024, "Sync freshness checkpoint"),
  ) as EncryptedSyncFreshnessCheckpoint;
  if (!envelope || envelope.version !== 1 || !envelope.payload) {
    throw new Error("Unsupported or invalid encrypted freshness checkpoint.");
  }
  return validateSignedCheckpoint(
    JSON.parse(decryptDocument(envelope.payload, vaultKey, AAD.syncFreshnessCheckpoint)),
    registry,
  );
}

function saveCheckpoint(
  rootDir: string,
  vaultKey: Buffer,
  registry: SignedSyncDeviceRegistry,
  checkpoint: SignedSyncFreshnessCheckpoint,
): void {
  const normalized = validateSignedCheckpoint(checkpoint, registry);
  writeFileAtomic(checkpointPath(rootDir), JSON.stringify(encryptedCheckpoint(normalized, vaultKey)), { mode: 0o600 });
}

function assertCheckpointHistory(
  checkpoint: SignedSyncFreshnessCheckpoint,
  changes: readonly SyncChange[],
): void {
  const verification = validateChangeSet(changes);
  const byId = new Map(changes.map((change) => [change.id, change]));
  for (const head of checkpoint.body.heads) {
    if (!byId.has(head)) throw new Error(`Freshness checkpoint head ${head} is missing from sync history.`);
  }
  const reachable = new Set<string>();
  const visit = (id: string): void => {
    if (reachable.has(id)) return;
    const change = byId.get(id);
    if (!change) throw new Error(`Freshness checkpoint history is missing change ${id}.`);
    reachable.add(id);
    for (const parent of change.parents) visit(parent);
  };
  for (const head of checkpoint.body.heads) visit(head);
  if (reachable.size !== checkpoint.body.changeCount) {
    throw new Error(
      `Freshness checkpoint commits ${checkpoint.body.changeCount} changes, but ${reachable.size} are reachable.`,
    );
  }
  if (checkpoint.body.changeCount > verification.changes) {
    throw new Error("Freshness checkpoint is ahead of the available sync history.");
  }
}

export class SyncDeviceManager {
  private readonly session: DocumentKeySession;
  private closed = false;

  constructor(
    private readonly vaultDir: string,
    passphrase: string,
  ) {
    this.session = openDocumentKey(vaultDir, passphrase);
    fs.mkdirSync(identityDir(this.session.rootDir), { recursive: true, mode: 0o700 });
  }

  close(): void {
    if (this.closed) return;
    this.session.key.fill(0);
    this.closed = true;
  }

  private key(): Buffer {
    if (this.closed) throw new Error("Sync device manager is closed.");
    return this.session.key;
  }

  /** The write key, then the retiring one of an unfinished re-key. */
  private readKeys(): readonly Buffer[] {
    if (this.closed) throw new Error("Sync device manager is closed.");
    return this.session.readKeys;
  }

  /**
   * Epoch-1 change material: a permanent identity key, a rotatable body key,
   * the retiring body key of an unfinished re-key, and the bare documents key
   * that opens changes sealed before either existed.
   */
  private syncKeys(): SyncChangeKeys {
    if (this.closed) throw new Error("Sync device manager is closed.");
    return {
      syncChangeKey: this.session.syncChangeKey,
      syncEnvelopeKey: this.session.syncEnvelopeKey,
      retiringSyncEnvelopeKey: this.session.syncEnvelopeReadKeys[1],
      legacyKey: this.session.key,
      legacyIdentityKey: this.session.legacyChangeIdentityKey ?? undefined,
    };
  }

  state(): SignedSyncDeviceRegistry | undefined {
    const registry = readDeviceRegistry(this.session.rootDir, this.readKeys());
    return registry ? structuredClone(registry) : undefined;
  }

  fingerprint(): string | undefined {
    const registry = this.state();
    return registry ? syncRegistryFingerprint(registry) : undefined;
  }

  initializeOwner(
    name: string,
    deviceId = crypto.randomUUID(),
    now = new Date().toISOString(),
  ): SignedSyncDeviceRegistry {
    return withVaultLock(this.vaultDir, () => {
      if (readDeviceRegistry(this.session.rootDir, this.readKeys())) {
        throw new Error("Sync device enrollment is already initialized.");
      }
      if (fs.existsSync(authorityKeyPath(this.session.rootDir))) {
        throw new Error("A local sync enrollment authority key already exists; explicit recovery is required.");
      }
      if (!DEVICE_ID.test(deviceId)) throw new Error("Sync device ID must be a lowercase UUID.");
      const normalizedTime = canonicalTimestamp(now, "Device enrollment time");
      const legacy = enrollmentLegacyChanges(this.session.rootDir, this.syncKeys()).map((change) => change.id);
      const authority = crypto.generateKeyPairSync("ed25519");
      const device = crypto.generateKeyPairSync("ed25519");
      const agreement = generateAgreementKeyPair();
      const certificate: SyncDeviceCertificate = {
        version: 2,
        serial: 1,
        deviceId,
        name: deviceName(name),
        publicKey: exportPublicKey(device.publicKey),
        keyAgreementKey: exportAgreementPublicKey(agreement.publicKey),
        enrolledAt: normalizedTime,
        epoch: 1,
      };
      const record: SyncDeviceRecord = {
        certificate,
        certificateSignature: signCanonical(certificatePayload(certificate), authority.privateKey),
      };
      const registry = signRegistryBody(
        {
          version: 1,
          revision: 1,
          epoch: 1,
          authorityPublicKey: exportPublicKey(authority.publicKey),
          updatedAt: normalizedTime,
          legacyChangeIds: legacy.sort(),
          devices: [record],
        },
        authority.privateKey,
      );
      savePrivateKey(authorityKeyPath(this.session.rootDir), authority.privateKey, this.key(), AAD.syncAuthorityKey);
      savePrivateKey(
        deviceKeyPath(this.session.rootDir, deviceId),
        device.privateKey,
        this.key(),
        syncDeviceKeyAad(deviceId),
      );
      saveAgreementKey(this.session.rootDir, this.key(), deviceId, agreement.privateKey);
      saveDeviceRegistry(this.session.rootDir, this.key(), registry);
      return structuredClone(registry);
    });
  }

  createEnrollmentRequest(
    name: string,
    deviceId = crypto.randomUUID(),
    now = new Date().toISOString(),
  ): SyncEnrollmentRequest {
    return withVaultLock(this.vaultDir, () => {
      const registry = readDeviceRegistry(this.session.rootDir, this.readKeys());
      if (!registry) throw new Error("Initialize or import a trusted sync device registry first.");
      if (!DEVICE_ID.test(deviceId)) throw new Error("Sync device ID must be a lowercase UUID.");
      if (registry.body.devices.some((record) => record.certificate.deviceId === deviceId)) {
        throw new Error(`Sync device ${deviceId} is already enrolled.`);
      }
      if (fs.existsSync(deviceKeyPath(this.session.rootDir, deviceId))) {
        throw new Error(`A pending private key already exists for sync device ${deviceId}.`);
      }
      const pair = crypto.generateKeyPairSync("ed25519");
      const agreement = generateAgreementKeyPair();
      const unsigned: Omit<SyncEnrollmentRequest, "proof"> = {
        version: 2,
        deviceId,
        name: deviceName(name),
        publicKey: exportPublicKey(pair.publicKey),
        keyAgreementKey: exportAgreementPublicKey(agreement.publicKey),
        requestedAt: canonicalTimestamp(now, "Enrollment request time"),
        nonce: crypto.randomBytes(32).toString("base64"),
      };
      const request: SyncEnrollmentRequest = {
        ...unsigned,
        proof: signCanonical(enrollmentRequestPayload(unsigned), pair.privateKey),
      };
      savePrivateKey(
        deviceKeyPath(this.session.rootDir, deviceId),
        pair.privateKey,
        this.key(),
        syncDeviceKeyAad(deviceId),
      );
      try {
        saveAgreementKey(this.session.rootDir, this.key(), deviceId, agreement.privateKey);
      } catch (error) {
        // The two keys are one unit: a device holding an identity key but no
        // agreement key can never be issued an epoch wrap, and the pending-key
        // guard above would then refuse the retry that would fix it. Undo the
        // first write so asking again is all it takes.
        fs.rmSync(deviceKeyPath(this.session.rootDir, deviceId), { force: true });
        throw error;
      }
      return validateEnrollmentRequest(request);
    });
  }

  enroll(requestValue: unknown, now = new Date().toISOString()): SignedSyncDeviceRegistry {
    return withVaultLock(this.vaultDir, () => {
      const registry = readDeviceRegistry(this.session.rootDir, this.readKeys());
      if (!registry) throw new Error("Sync device enrollment is not initialized.");
      const request = validateEnrollmentRequest(requestValue);
      if (registry.body.devices.some((record) => record.certificate.deviceId === request.deviceId)) {
        throw new Error(`Sync device ${request.deviceId} is already enrolled.`);
      }
      const authorityKey = readPrivateKey(
        authorityKeyPath(this.session.rootDir),
        this.key(),
        AAD.syncAuthorityKey,
        "Sync enrollment authority private key",
      );
      if (exportPublicKey(crypto.createPublicKey(authorityKey)) !== registry.body.authorityPublicKey) {
        throw new Error("The local enrollment authority key does not match the pinned registry authority.");
      }
      const certificate: SyncDeviceCertificate = {
        version: request.version,
        serial: Math.max(0, ...registry.body.devices.map((record) => record.certificate.serial)) + 1,
        deviceId: request.deviceId,
        name: request.name,
        publicKey: request.publicKey,
        enrolledAt: canonicalTimestamp(now, "Device enrollment time"),
        epoch: registry.body.epoch,
      };
      if (request.version === 2) certificate.keyAgreementKey = request.keyAgreementKey;
      const nextBody: SyncDeviceRegistryBody = {
        ...registry.body,
        revision: registry.body.revision + 1,
        updatedAt: certificate.enrolledAt,
        devices: [
          ...registry.body.devices,
          {
            certificate,
            certificateSignature: signCanonical(certificatePayload(certificate), authorityKey),
          },
        ],
      };
      const next = signRegistryBody(nextBody, authorityKey);
      saveDeviceRegistry(this.session.rootDir, this.key(), next);
      return structuredClone(next);
    });
  }

  revoke(deviceId: string, revokedAfterSequence: number, now = new Date().toISOString()): SignedSyncDeviceRegistry {
    return withVaultLock(this.vaultDir, () => {
      const registry = readDeviceRegistry(this.session.rootDir, this.readKeys());
      if (!registry) throw new Error("Sync device enrollment is not initialized.");
      const record = registry.body.devices.find((candidate) => candidate.certificate.deviceId === deviceId);
      if (!record) throw new Error(`Sync device ${deviceId} is not enrolled.`);
      if (record.revokedAt) throw new Error(`Sync device ${deviceId} is already revoked.`);
      const remaining = registry.body.devices.filter(
        (candidate) => !candidate.revokedAt && candidate.certificate.deviceId !== deviceId,
      );
      if (remaining.length === 0) {
        throw new Error(
          "Refusing to revoke the last active sync device: the new epoch key would reach nobody and the log could not be extended.",
        );
      }
      for (const candidate of remaining) {
        if (candidate.certificate.version !== 2 || !candidate.certificate.keyAgreementKey) {
          throw new Error(
            `Sync device ${candidate.certificate.deviceId} predates key agreement; re-enroll it before revoking another device.`,
          );
        }
      }

      const cutoff = integer(revokedAfterSequence, 0, "Device revocation sequence");
      const authorityKey = readPrivateKey(
        authorityKeyPath(this.session.rootDir),
        this.key(),
        AAD.syncAuthorityKey,
        "Sync enrollment authority private key",
      );
      const revokedAt = canonicalTimestamp(now, "Device revocation time");
      const epoch = registry.body.epoch + 1;
      const epochKey = crypto.randomBytes(EPOCH_KEY_BYTES);

      try {
        // Reissue the remaining devices at the new epoch, reusing their keys,
        // and wrap the fresh content key to those devices only.
        const devices: SyncDeviceRecord[] = registry.body.devices.map((candidate) => {
          if (candidate.certificate.deviceId === deviceId) {
            return { ...candidate, revokedAt, revokedAfterSequence: cutoff };
          }
          if (candidate.revokedAt) return candidate;
          const certificate: SyncDeviceCertificate = { ...candidate.certificate, epoch };
          return {
            ...candidate,
            certificate,
            certificateSignature: signCanonical(certificatePayload(certificate), authorityKey),
          };
        });
        const epochKeys = remaining
          .map((candidate) =>
            wrapEpochKey(
              epochKey,
              epoch,
              candidate.certificate.deviceId,
              agreementPublicKeyFromBase64(candidate.certificate.keyAgreementKey, "Certificate key agreement key"),
            ),
          )
          .sort((left, right) => left.deviceId.localeCompare(right.deviceId));

        const next = signRegistryBody(
          {
            ...registry.body,
            version: 2,
            revision: registry.body.revision + 1,
            epoch,
            updatedAt: revokedAt,
            devices,
            epochKeys,
          },
          authorityKey,
        );
        // Persist the key before the registry: a crash between the two leaves a
        // recoverable key with no registry referencing it, rather than a
        // registry naming an epoch this device cannot open.
        saveEpochKey(this.session.rootDir, this.key(), epoch, epochKey);
        saveDeviceRegistry(this.session.rootDir, this.key(), next);
        return structuredClone(next);
      } finally {
        epochKey.fill(0);
      }
    });
  }

  exportRegistry(): EncryptedSyncDeviceRegistry {
    const registry = readDeviceRegistry(this.session.rootDir, this.readKeys());
    if (!registry) throw new Error("Sync device enrollment is not initialized.");
    return encryptedRegistry(registry, this.key());
  }

  inspectRegistry(value: unknown): SignedSyncDeviceRegistry {
    const envelope = value as EncryptedSyncDeviceRegistry | undefined;
    if (!envelope || envelope.version !== 1 || !envelope.payload) {
      throw new Error("Unsupported or invalid encrypted sync device registry bundle.");
    }
    const incoming = validateSignedDeviceRegistry(
      JSON.parse(decryptDocument(envelope.payload, this.readKeys(), AAD.syncDeviceRegistry)),
    );
    const current = readDeviceRegistry(this.session.rootDir, this.readKeys());
    if (current && current.body.authorityPublicKey !== incoming.body.authorityPublicKey) {
      throw new Error("Incoming sync registry uses a different enrollment authority.");
    }
    return structuredClone(incoming);
  }

  importRegistry(value: unknown, expectedAuthorityFingerprint?: string): SignedSyncDeviceRegistry {
    return withVaultLock(this.vaultDir, () => {
      const envelope = value as EncryptedSyncDeviceRegistry | undefined;
      if (!envelope || envelope.version !== 1 || !envelope.payload) {
        throw new Error("Unsupported or invalid encrypted sync device registry bundle.");
      }
      const incoming = validateSignedDeviceRegistry(
        JSON.parse(decryptDocument(envelope.payload, this.readKeys(), AAD.syncDeviceRegistry)),
      );
      const current = readDeviceRegistry(this.session.rootDir, this.readKeys());
      const fingerprint = syncRegistryFingerprint(incoming);
      if (current) {
        if (current.body.authorityPublicKey !== incoming.body.authorityPublicKey) {
          throw new Error("Incoming sync registry uses a different enrollment authority.");
        }
        if (incoming.body.revision < current.body.revision) {
          throw new Error("Incoming sync registry is a rollback.");
        }
        if (
          incoming.body.revision === current.body.revision &&
          canonicalSyncJson(incoming as unknown as SyncJson) !== canonicalSyncJson(current as unknown as SyncJson)
        ) {
          throw new Error("Incoming sync registry forks the current revision.");
        }
      } else {
        if (!expectedAuthorityFingerprint || !CHANGE_ID.test(expectedAuthorityFingerprint)) {
          throw new Error("First registry import requires the expected 64-character authority fingerprint.");
        }
        if (fingerprint !== expectedAuthorityFingerprint) {
          throw new Error("Incoming sync registry does not match the expected enrollment authority.");
        }
      }
      // Adopt the epoch key wrapped to whichever local device this vault holds.
      if (
        incoming.body.epoch > 1 &&
        incoming.body.epochKeys &&
        !hasEpochKey(this.session.rootDir, incoming.body.epoch)
      ) {
        for (const wrap of incoming.body.epochKeys) {
          if (!fs.existsSync(agreementKeyPath(this.session.rootDir, wrap.deviceId))) continue;
          const privateKey = readAgreementKey(this.session.rootDir, this.readKeys(), wrap.deviceId);
          const epochKey = unwrapEpochKey(wrap, incoming.body.epoch, wrap.deviceId, privateKey);
          try {
            saveEpochKey(this.session.rootDir, this.key(), incoming.body.epoch, epochKey);
          } finally {
            epochKey.fill(0);
          }
          break;
        }
      }
      saveDeviceRegistry(this.session.rootDir, this.key(), incoming);
      return structuredClone(incoming);
    });
  }

  createCheckpoint(
    changes: readonly SyncChange[],
    now = new Date().toISOString(),
  ): SignedSyncFreshnessCheckpoint {
    return withVaultLock(this.vaultDir, () => {
      const registry = readDeviceRegistry(this.session.rootDir, this.readKeys());
      if (!registry) throw new Error("Sync device enrollment is not initialized.");
      validateChangeSet(changes);
      validateAuthorizedChanges(changes, registry);
      const authorityKey = readPrivateKey(
        authorityKeyPath(this.session.rootDir),
        this.key(),
        AAD.syncAuthorityKey,
        "Sync enrollment authority private key",
      );
      const current = readCheckpoint(this.session.rootDir, this.readKeys(), registry);
      const parentIds = new Set(changes.flatMap((change) => change.parents));
      const body: SyncFreshnessCheckpointBody = {
        version: 1,
        sequence: (current?.body.sequence ?? 0) + 1,
        authorityFingerprint: syncRegistryFingerprint(registry),
        registryRevision: registry.body.revision,
        epoch: registry.body.epoch,
        changeCount: changes.length,
        heads: changes.map((change) => change.id).filter((id) => !parentIds.has(id)).sort(),
        createdAt: canonicalTimestamp(now, "Checkpoint creation time"),
        previousCheckpoint: current?.id ?? null,
      };
      const signature = signCanonical(checkpointBodyPayload(body), authorityKey);
      const checkpoint = validateSignedCheckpoint(
        { id: checkpointId(body, signature), body, signature },
        registry,
      );
      assertCheckpointHistory(checkpoint, changes);
      saveCheckpoint(this.session.rootDir, this.key(), registry, checkpoint);
      return structuredClone(checkpoint);
    });
  }

  exportCheckpoint(): EncryptedSyncFreshnessCheckpoint {
    const registry = readDeviceRegistry(this.session.rootDir, this.readKeys());
    if (!registry) throw new Error("Sync device enrollment is not initialized.");
    const checkpoint = readCheckpoint(this.session.rootDir, this.readKeys(), registry);
    if (!checkpoint) throw new Error("No sync freshness checkpoint has been created.");
    return encryptedCheckpoint(checkpoint, this.key());
  }

  checkpoint(): SignedSyncFreshnessCheckpoint | undefined {
    const registry = readDeviceRegistry(this.session.rootDir, this.readKeys());
    if (!registry) return undefined;
    const checkpoint = readCheckpoint(this.session.rootDir, this.readKeys(), registry);
    return checkpoint ? structuredClone(checkpoint) : undefined;
  }

  inspectCheckpoint(value: unknown): SignedSyncFreshnessCheckpoint {
    const registry = readDeviceRegistry(this.session.rootDir, this.readKeys());
    if (!registry) throw new Error("Sync device enrollment is not initialized.");
    const envelope = value as EncryptedSyncFreshnessCheckpoint | undefined;
    if (!envelope || envelope.version !== 1 || !envelope.payload) {
      throw new Error("Unsupported or invalid encrypted freshness checkpoint bundle.");
    }
    return structuredClone(
      validateSignedCheckpoint(
        JSON.parse(decryptDocument(envelope.payload, this.readKeys(), AAD.syncFreshnessCheckpoint)),
        registry,
      ),
    );
  }

  importCheckpoint(
    value: unknown,
    changes: readonly SyncChange[],
    expectedCheckpointId?: string,
  ): SignedSyncFreshnessCheckpoint {
    return withVaultLock(this.vaultDir, () => {
      const registry = readDeviceRegistry(this.session.rootDir, this.readKeys());
      if (!registry) throw new Error("Sync device enrollment is not initialized.");
      const envelope = value as EncryptedSyncFreshnessCheckpoint | undefined;
      if (!envelope || envelope.version !== 1 || !envelope.payload) {
        throw new Error("Unsupported or invalid encrypted freshness checkpoint bundle.");
      }
      const incoming = validateSignedCheckpoint(
        JSON.parse(decryptDocument(envelope.payload, this.readKeys(), AAD.syncFreshnessCheckpoint)),
        registry,
      );
      assertCheckpointHistory(incoming, changes);
      const current = readCheckpoint(this.session.rootDir, this.readKeys(), registry);
      if (!current) {
        if (!expectedCheckpointId || !CHANGE_ID.test(expectedCheckpointId)) {
          throw new Error("First checkpoint import requires the expected 64-character checkpoint ID.");
        }
        if (incoming.id !== expectedCheckpointId) {
          throw new Error("Incoming freshness checkpoint does not match the expected checkpoint ID.");
        }
      } else if (incoming.body.sequence < current.body.sequence) {
        throw new Error("Incoming freshness checkpoint is a rollback.");
      } else if (incoming.body.sequence === current.body.sequence) {
        if (incoming.id !== current.id) throw new Error("Incoming freshness checkpoint forks the current sequence.");
        return structuredClone(current);
      } else if (
        incoming.body.sequence !== current.body.sequence + 1 ||
        incoming.body.previousCheckpoint !== current.id
      ) {
        throw new Error("Incoming freshness checkpoint does not extend the pinned checkpoint chain.");
      }
      saveCheckpoint(this.session.rootDir, this.key(), registry, incoming);
      return structuredClone(incoming);
    });
  }

  verifyCheckpoint(changes: readonly SyncChange[]): SignedSyncFreshnessCheckpoint {
    const registry = readDeviceRegistry(this.session.rootDir, this.readKeys());
    if (!registry) throw new Error("Sync device enrollment is not initialized.");
    validateAuthorizedChanges(changes, registry);
    const checkpoint = readCheckpoint(this.session.rootDir, this.readKeys(), registry);
    if (!checkpoint) throw new Error("No sync freshness checkpoint is pinned.");
    assertCheckpointHistory(checkpoint, changes);
    return structuredClone(checkpoint);
  }
}

export function openSyncChange(
  value: unknown,
  key: SyncChangeKeyMaterial | SyncEpochKeyResolver,
): SyncChange {
  const envelope = validateEnvelope(value);
  const epoch = envelope.version === 2 ? envelope.epoch! : 1;
  let material: SyncChangeKeyMaterial;
  if (typeof key === "function") {
    material = key(epoch);
  } else {
    if (epoch !== 1) {
      throw new Error(`Opening an epoch ${epoch} sync change requires an epoch key resolver.`);
    }
    material = key;
  }
  const { syncChangeKey, syncEnvelopeKey, retiringSyncEnvelopeKey, legacyKey, legacyIdentityKey } =
    splitSyncKeys(material);
  // Ordered: the key in force, then the outgoing key of an unfinished re-key,
  // then the pre-keyring key that opens changes written before migration. Only
  // the last of those changes how the change's identity is recomputed.
  const candidates: { key: Buffer; legacy: boolean }[] = [{ key: syncEnvelopeKey, legacy: false }];
  if (retiringSyncEnvelopeKey && retiringSyncEnvelopeKey !== syncEnvelopeKey) {
    candidates.push({ key: retiringSyncEnvelopeKey, legacy: false });
  }
  if (legacyKey && legacyKey !== syncEnvelopeKey) candidates.push({ key: legacyKey, legacy: true });

  let encryptionKey = syncEnvelopeKey;
  let usedLegacyKey = false;
  let plaintext: string | undefined;
  let failure: unknown;
  for (const candidate of candidates) {
    const envelopeKey = changeEncryptionKey(candidate.key, envelope.id, epoch);
    try {
      plaintext = decryptDocument(envelope.payload, envelopeKey, syncChangeAad(envelope.id));
      encryptionKey = candidate.key;
      usedLegacyKey = candidate.legacy;
      failure = undefined;
      break;
    } catch (error) {
      failure = error;
    } finally {
      envelopeKey.fill(0);
    }
  }
  if (plaintext === undefined) throw failure;
  if (Buffer.byteLength(plaintext, "utf8") > MAX_CHANGE_BYTES) throw new Error("Sync change exceeds 8 MiB.");
  const body = validateSyncChangeBody(JSON.parse(plaintext));
  const identityKey = usedLegacyKey ? encryptionKey : syncChangeKey;
  const modernId = changeId(body, identityKey, Buffer.isBuffer(material) || usedLegacyKey ? epoch : 1);
  // Candidates, in the order they became possible. `legacyIdentityKey` covers
  // a change a re-key re-sealed under the new envelope key but whose id an
  // older build had derived from the documents key that re-key replaced.
  const candidateIds = [modernId];
  if (epoch > 1 && !Buffer.isBuffer(material)) candidateIds.push(changeId(body, syncEnvelopeKey, epoch));
  if (legacyIdentityKey && !usedLegacyKey) candidateIds.push(changeId(body, legacyIdentityKey, epoch));
  const matched = candidateIds.find((candidate) => candidate === envelope.id) ?? modernId;
  const actual = Buffer.from(matched, "hex");
  const expected = Buffer.from(envelope.id, "hex");
  if (!crypto.timingSafeEqual(actual, expected)) throw new Error("Sync change ID does not match its content.");
  if (plaintext !== canonicalSyncJson(body as unknown as SyncJson)) {
    throw new Error("Sync change plaintext is not canonically encoded.");
  }
  return { id: envelope.id, ...body };
}

/**
 * Re-encrypts an epoch 1 change body under a new envelope key, leaving its id
 * untouched. This is what `vbrain rekey` applies to the change log.
 *
 * The id is not recomputed, and it must not be: it is what the causal DAG,
 * the applied cursor and every pinned checkpoint reference. Opening first is
 * deliberate — it validates the id against the body and the body against its
 * canonical encoding, so a re-seal cannot launder a tampered change into one
 * that verifies under the new key.
 *
 * Epoch 2 and above are refused. Their bodies are sealed under an epoch key,
 * which a re-key does not rotate; only the file holding that epoch key is
 * rewritten.
 */
export function resealSyncChange(
  value: unknown,
  from: SyncChangeKeyMaterial | SyncEpochKeyResolver,
  toSyncEnvelopeKey: Buffer,
): EncryptedSyncChange {
  const envelope = validateEnvelope(value);
  if (envelope.version !== 1) {
    throw new Error("Only an epoch 1 sync change is re-sealed; later epochs keep their epoch key.");
  }
  const { id, ...body } = openSyncChange(envelope, from);
  const canonical = canonicalSyncJson(body as unknown as SyncJson);
  const envelopeKey = changeEncryptionKey(toSyncEnvelopeKey, id, 1);
  try {
    return { version: 1, id, payload: encryptDocument(canonical, envelopeKey, syncChangeAad(id)) };
  } finally {
    envelopeKey.fill(0);
  }
}

function objectKey(change: SyncChange): string {
  return `${change.mutation.objectType}\0${change.mutation.objectId}`;
}

function syncObjectKey(objectType: SyncObjectType, objectId: string): string {
  return `${objectType}\0${objectId}`;
}

function asSyncJson(value: unknown): SyncJson {
  validateJson(value);
  return structuredClone(value) as SyncJson;
}

function assertSyncSnapshotSize(value: unknown, label: string): void {
  const jsonCompatible = JSON.parse(JSON.stringify(value)) as SyncJson;
  const bytes = Buffer.byteLength(canonicalSyncJson(jsonCompatible), "utf8");
  // Leave room for device metadata and the maximum causal-parent list.
  if (bytes > MAX_CHANGE_BYTES - 64 * 1024) {
    throw new Error(`${label} is too large for an 8 MiB sync change.`);
  }
}

function parentFirstChanges(changes: readonly SyncChange[]): SyncChange[] {
  const byId = new Map(changes.map((change) => [change.id, change]));
  const ordered: SyncChange[] = [];
  const visited = new Set<string>();
  const visit = (change: SyncChange): void => {
    if (visited.has(change.id)) return;
    for (const parent of change.parents) {
      const known = byId.get(parent);
      if (known) visit(known);
    }
    visited.add(change.id);
    ordered.push(change);
  };
  for (const change of [...changes].sort(
    (left, right) => left.createdAt.localeCompare(right.createdAt) || left.id.localeCompare(right.id),
  )) {
    visit(change);
  }
  return ordered;
}

function prevalidateLocalCaptureSnapshot(value: unknown, label: string): SyncJson {
  const snapshot = asSyncJson(value);
  assertSyncSnapshotSize(snapshot, label);
  return snapshot;
}

function noteSnapshot(note: NoteDocument): NoteSyncSnapshot {
  const snapshot: NoteSyncSnapshot = {
    path: note.path,
    title: note.title,
    body: note.body,
    aliases: note.aliases,
    tags: note.tags,
    properties: note.properties,
    createdAt: note.createdAt,
  };
  if (note.frontmatterSource !== undefined) snapshot.frontmatterSource = note.frontmatterSource;
  return structuredClone(snapshot);
}

function canvasSnapshot(canvas: CanvasDocument): CanvasSyncSnapshot {
  return structuredClone({
    path: canvas.path,
    title: canvas.title,
    nodes: canvas.nodes,
    edges: canvas.edges,
    createdAt: canvas.createdAt,
  });
}

/** Overwrite a blob key session in place. */
function zeroBlobSession(session: DocumentKeySession): void {
  session.key.fill(0);
  session.attachmentIdKey.fill(0);
  session.syncChangeKey.fill(0);
  session.syncEnvelopeKey.fill(0);
}

/**
 * Capture an attachment as blob references and stage the sealed chunks the
 * receiving device will need. The bytes never enter the change body.
 */
/**
 * Sealing uses the permanent blob key alone. Opening also accepts the two
 * documents-key generations, because blobs staged by a build that predates
 * `deriveBlobKey` are sealed under the documents key and must keep opening.
 */
function blobSealKey(session: DocumentKeySession): Buffer {
  return deriveBlobKey(session.syncChangeKey);
}

function blobReadKeys(session: DocumentKeySession): Buffer[] {
  return [blobSealKey(session), ...session.readKeys];
}

function attachmentSnapshot(
  data: Buffer,
  info: AttachmentInfo,
  key: Buffer,
  store: SyncBlobStore,
): BlobAttachmentSyncSnapshot {
  const { blobs, payloads } = sealAttachmentBlobs(data, info.id, key);
  for (const [index, payload] of payloads.entries()) store.put(blobs[index], payload);
  return { filename: info.filename, mime: info.mime, size: info.size, chunks: info.chunks, blobs };
}

function pluginSnapshot(plugin: PluginPackage): PluginSyncSnapshot {
  // Enabled/disabled is a device-local execution decision. Receiving package
  // bytes must never cause code to become runnable on another device.
  return structuredClone({ manifest: plugin.manifest, source: plugin.source });
}

function recordValue(value: SyncJson, label: string): Record<string, SyncJson> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} sync snapshot must be an object.`);
  }
  return value;
}

function requiredString(value: SyncJson | undefined, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} must be a string.`);
  return value;
}

function parseNoteSnapshot(value: SyncJson): NoteSyncSnapshot {
  const raw = recordValue(value, "Note");
  const aliases = raw.aliases;
  const tags = raw.tags;
  const properties = raw.properties;
  if (!Array.isArray(aliases) || aliases.some((item) => typeof item !== "string")) {
    throw new Error("Note sync aliases must be strings.");
  }
  if (!Array.isArray(tags) || tags.some((item) => typeof item !== "string")) {
    throw new Error("Note sync tags must be strings.");
  }
  if (!properties || typeof properties !== "object" || Array.isArray(properties)) {
    throw new Error("Note sync properties must be an object.");
  }
  const createdAt = requiredString(raw.createdAt, "Note sync createdAt");
  if (!Number.isFinite(Date.parse(createdAt))) throw new Error("Note sync createdAt must be an ISO timestamp.");
  const snapshot: NoteSyncSnapshot = {
    path: requiredString(raw.path, "Note sync path"),
    title: requiredString(raw.title, "Note sync title"),
    body: requiredString(raw.body, "Note sync body"),
    aliases: aliases as string[],
    tags: tags as string[],
    properties: properties as NoteDocument["properties"],
    createdAt,
  };
  if (raw.frontmatterSource !== undefined) {
    snapshot.frontmatterSource = requiredString(raw.frontmatterSource, "Note sync frontmatterSource");
  }
  return structuredClone(snapshot);
}

function parseCanvasSnapshot(value: SyncJson): CanvasSyncSnapshot {
  const raw = recordValue(value, "Canvas");
  if (!Array.isArray(raw.nodes) || !Array.isArray(raw.edges)) {
    throw new Error("Canvas sync snapshot needs node and edge arrays.");
  }
  const createdAt = requiredString(raw.createdAt, "Canvas sync createdAt");
  if (!Number.isFinite(Date.parse(createdAt))) throw new Error("Canvas sync createdAt must be an ISO timestamp.");
  return structuredClone({
    path: requiredString(raw.path, "Canvas sync path"),
    title: requiredString(raw.title, "Canvas sync title"),
    nodes: raw.nodes as unknown as CanvasDocument["nodes"],
    edges: raw.edges as unknown as CanvasDocument["edges"],
    createdAt,
  });
}

export function isBlobAttachmentSnapshot(
  snapshot: AttachmentSyncSnapshot,
): snapshot is BlobAttachmentSyncSnapshot {
  return "blobs" in snapshot;
}

export function parseAttachmentSnapshot(value: SyncJson): AttachmentSyncSnapshot {
  const raw = recordValue(value, "Attachment");
  const filename = requiredString(raw.filename, "Attachment sync filename");
  const mime = requiredString(raw.mime, "Attachment sync MIME type");
  const hasInline = raw.data !== undefined;
  const hasBlobs = raw.blobs !== undefined || raw.chunks !== undefined || raw.size !== undefined;
  if (hasInline === hasBlobs) {
    throw new Error("An attachment sync snapshot must carry exactly one of inline data or blob references.");
  }

  if (hasInline) {
    const data = requiredString(raw.data, "Attachment sync data");
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(data)) {
      throw new Error("Attachment sync data must be canonical base64.");
    }
    if (Buffer.from(data, "base64").toString("base64") !== data) {
      throw new Error("Attachment sync data must be canonical base64.");
    }
    return { filename, mime, data };
  }

  const { size, chunks, blobs } = raw as { size: unknown; chunks: unknown; blobs: unknown };
  // The blob list is bounded before anything else so hostile input cannot be
  // scanned unboundedly, and so an oversize claim is reported as the cap it
  // breaks rather than as a size error.
  if (!Array.isArray(blobs)) throw new Error("Attachment sync blobs must be an array.");
  if (blobs.length > MAX_ATTACHMENT_BLOBS) {
    throw new Error(`An attachment sync snapshot may reference at most ${MAX_ATTACHMENT_BLOBS} blobs.`);
  }
  for (const blob of blobs) {
    if (typeof blob !== "string" || !BLOB_ID_PATTERN.test(blob)) {
      throw new Error("An attachment sync blob id must be 64 lowercase hexadecimal characters.");
    }
  }
  if (!Number.isSafeInteger(size) || (size as number) < 1 || (size as number) > MAX_ATTACHMENT_SIZE) {
    throw new Error("Attachment sync size must be between 1 byte and 250 MiB.");
  }
  if (
    !Number.isSafeInteger(chunks) ||
    chunks !== blobs.length ||
    chunks !== Math.ceil((size as number) / ATTACHMENT_CHUNK_SIZE)
  ) {
    throw new Error("Attachment sync chunk count must match both its blob list and its size.");
  }
  return { filename, mime, size: size as number, chunks: chunks as number, blobs: blobs as string[] };
}

export function sameAttachmentSnapshot(a: SyncJson, b: SyncJson): boolean {
  const left = parseAttachmentSnapshot(a);
  const right = parseAttachmentSnapshot(b);
  return left.filename === right.filename && left.mime === right.mime;
}

function parsePluginSnapshot(value: SyncJson): PluginSyncSnapshot {
  const raw = recordValue(value, "Plugin");
  if (!raw.manifest || typeof raw.manifest !== "object" || Array.isArray(raw.manifest)) {
    throw new Error("Plugin sync manifest must be an object.");
  }
  if (typeof raw.source !== "string") {
    throw new Error("Plugin sync snapshot has invalid source.");
  }
  return structuredClone({
    manifest: raw.manifest as unknown as PluginPackage["manifest"],
    source: raw.source,
  });
}

function parsePluginLocalStorageInput(value: SyncJson): PluginLocalStorageInput {
  const raw = recordValue(value, "Plugin storage input");
  const snapshot = parsePluginSnapshot(value);
  if (typeof raw.localEnabled !== "boolean") {
    throw new Error("Plugin storage input must declare its device-local enabled state.");
  }
  return { ...snapshot, localEnabled: raw.localEnabled };
}

function parsePluginPolicySnapshot(value: SyncJson): PluginSecurityPolicy {
  const raw = recordValue(value, "Plugin policy");
  if (
    raw.version !== 1 ||
    typeof raw.restrictedMode !== "boolean" ||
    !Array.isArray(raw.revokedSigners) ||
    raw.revokedSigners.some((entry) => typeof entry !== "string" || !/^[a-f0-9]{64}$/u.test(entry))
  ) {
    throw new Error("Plugin policy sync snapshot is invalid.");
  }
  return {
    version: 1,
    restrictedMode: raw.restrictedMode,
    revokedSigners: [...new Set(raw.revokedSigners as string[])].sort(),
  };
}

function validateChangeSet(changes: readonly SyncChange[]): SyncVerification {
  if (changes.length > MAX_CHANGE_COUNT) {
    throw new Error(`A sync change set may contain at most ${MAX_CHANGE_COUNT} changes.`);
  }
  const byId = new Map<string, SyncChange>();
  const deviceSequence = new Map<string, string>();
  for (const change of changes) {
    if (byId.has(change.id)) throw new Error(`Duplicate sync change: ${change.id}`);
    byId.set(change.id, change);
    const sequenceKey = `${change.deviceId}:${change.sequence}`;
    const fork = deviceSequence.get(sequenceKey);
    if (fork && fork !== change.id) throw new Error(`Device chain fork at ${sequenceKey}.`);
    deviceSequence.set(sequenceKey, change.id);
  }
  for (const change of changes) {
    for (const parent of change.parents) {
      if (!byId.has(parent)) throw new Error(`Missing sync parent ${parent} for ${change.id}.`);
      if (parent === change.id) throw new Error("A sync change cannot parent itself.");
    }
    if (change.sequence > 1) {
      const previous = byId.get(change.previousDeviceChange!);
      if (!previous || previous.deviceId !== change.deviceId || previous.sequence !== change.sequence - 1) {
        throw new Error(`Broken device chain before ${change.id}.`);
      }
    }
  }

  const visiting = new Set<string>();
  const visited = new Set<string>();
  const visit = (id: string): void => {
    if (visiting.has(id)) throw new Error("Sync change graph contains a cycle.");
    if (visited.has(id)) return;
    visiting.add(id);
    for (const parent of byId.get(id)!.parents) visit(parent);
    visiting.delete(id);
    visited.add(id);
  };
  for (const id of byId.keys()) visit(id);

  const ancestorMemo = new Map<string, boolean>();
  const isAncestor = (ancestor: string, descendant: string): boolean => {
    const memoKey = `${ancestor}:${descendant}`;
    const cached = ancestorMemo.get(memoKey);
    if (cached !== undefined) return cached;
    const result = byId.get(descendant)!.parents.some((parent) => parent === ancestor || isAncestor(ancestor, parent));
    ancestorMemo.set(memoKey, result);
    return result;
  };
  const grouped = new Map<string, SyncChange[]>();
  for (const change of changes) grouped.set(objectKey(change), [...(grouped.get(objectKey(change)) ?? []), change]);
  for (const objectChanges of grouped.values()) {
    for (const change of objectChanges) {
      const ancestors = objectChanges.filter((candidate) => isAncestor(candidate.id, change.id));
      const expectedBase =
        ancestors.length === 0 ? null : Math.max(...ancestors.map((candidate) => candidate.mutation.revision));
      if (change.mutation.baseRevision !== expectedBase) {
        throw new Error(`Sync change ${change.id} does not advance the causal object revision.`);
      }
    }
  }

  const parentIds = new Set(changes.flatMap((change) => change.parents));
  const heads = [...byId.keys()].filter((id) => !parentIds.has(id)).sort();
  return { changes: changes.length, devices: new Set(changes.map((change) => change.deviceId)).size, heads };
}

export function verifySyncChanges(changes: readonly SyncChange[]): SyncVerification {
  return validateChangeSet(changes);
}

export function resolveSyncObject(
  changes: readonly SyncChange[],
  objectType: SyncObjectType,
  objectId: string,
): SyncResolution {
  validateChangeSet(changes);
  const relevant = changes.filter(
    (change) => change.mutation.objectType === objectType && change.mutation.objectId === objectId,
  );
  if (relevant.length === 0) return { objectType, objectId, status: "missing", conflicts: [], heads: [] };
  const byId = new Map(changes.map((change) => [change.id, change]));
  const isAncestor = (ancestor: string, descendant: string): boolean => {
    const pending = [...byId.get(descendant)!.parents];
    const seen = new Set<string>();
    while (pending.length > 0) {
      const id = pending.pop()!;
      if (id === ancestor) return true;
      if (seen.has(id)) continue;
      seen.add(id);
      pending.push(...byId.get(id)!.parents);
    }
    return false;
  };
  const heads = relevant.filter(
    (candidate) => !relevant.some((other) => candidate.id !== other.id && isAncestor(candidate.id, other.id)),
  );
  heads.sort((left, right) => {
    const revision = right.mutation.revision - left.mutation.revision;
    if (revision !== 0) return revision;
    if (left.mutation.operation !== right.mutation.operation) return left.mutation.operation === "delete" ? -1 : 1;
    return left.id === right.id ? 0 : left.id < right.id ? 1 : -1;
  });
  return {
    objectType,
    objectId,
    status: heads.length === 1 ? "clean" : "conflict",
    winner: heads[0],
    conflicts: heads.slice(1),
    heads: heads.map((change) => change.id).sort(),
  };
}

function changeFilename(id: string): string {
  if (!CHANGE_ID.test(id)) throw new Error("Invalid sync change ID.");
  return `${id}.change.enc`;
}

export class SyncChangeLog {
  private readonly session: DocumentKeySession;
  private readonly changesDir: string;
  private readonly appliedPath: string;
  private closed = false;

  constructor(
    private readonly vaultDir: string,
    passphrase: string,
  ) {
    this.session = openDocumentKey(vaultDir, passphrase);
    this.changesDir = resolveInside(this.session.rootDir, path.join("sync", "changes"));
    this.appliedPath = resolveInside(this.session.rootDir, path.join("sync", "applied.enc"));
    assertNoSymlinkComponents(this.session.rootDir, this.changesDir);
    fs.mkdirSync(this.changesDir, { recursive: true, mode: 0o700 });
  }

  close(): void {
    if (this.closed) return;
    this.session.key.fill(0);
    this.session.attachmentIdKey.fill(0);
    this.session.syncChangeKey.fill(0);
    this.session.syncEnvelopeKey.fill(0);
    this.closed = true;
  }

  private key(): Buffer {
    if (this.closed) throw new Error("Sync change log is closed.");
    return this.session.key;
  }

  /** The write key, then the retiring one of an unfinished re-key. */
  private readKeys(): readonly Buffer[] {
    if (this.closed) throw new Error("Sync change log is closed.");
    return this.session.readKeys;
  }

  private epochResolver(): SyncEpochKeyResolver {
    const vaultKey = this.key();
    const rootDir = this.session.rootDir;
    return (epoch: number): SyncChangeKeyMaterial => {
      if (epoch === 1) {
        return {
          syncChangeKey: this.session.syncChangeKey,
          syncEnvelopeKey: this.session.syncEnvelopeKey,
          retiringSyncEnvelopeKey: this.session.syncEnvelopeReadKeys[1],
          legacyKey: vaultKey,
          legacyIdentityKey: this.session.legacyChangeIdentityKey ?? undefined,
        };
      }
      const key = readEpochKey(rootDir, vaultKey, epoch);
      if (!key) {
        throw new Error(
          `This device holds no content key for sync epoch ${epoch}; import the owner-signed registry that rotated to it.`,
        );
      }
      return key;
    };
  }

  private readAppliedState(): SyncAppliedState {
    this.key();
    if (!fs.existsSync(this.appliedPath)) return { version: 1, objects: {} };
    assertNotSymlink(this.appliedPath);
    const payload = JSON.parse(
      readTextFileLimited(this.appliedPath, 64 * 1024 * 1024, "Sync application state")
    ) as DocumentPayload;
    const parsed = JSON.parse(decryptDocument(payload, this.readKeys(), AAD.syncApplied)) as SyncAppliedState;
    if (parsed?.version !== 1 || !parsed.objects || typeof parsed.objects !== "object") {
      throw new Error("Unsupported or invalid sync application state.");
    }
    for (const [key, entry] of Object.entries(parsed.objects)) {
      if (
        !key.includes("\0") ||
        !entry ||
        !CHANGE_ID.test(entry.changeId) ||
        !Number.isSafeInteger(entry.revision) ||
        entry.revision < 1 ||
        (entry.operation !== "put" && entry.operation !== "delete")
      ) {
        throw new Error("Unsupported or invalid sync application state.");
      }
    }
    return parsed;
  }

  private saveAppliedState(state: SyncAppliedState): void {
    const payload = encryptDocument(JSON.stringify(state), this.key(), AAD.syncApplied);
    writeFileAtomic(this.appliedPath, JSON.stringify(payload), { mode: 0o600 });
  }

  applied(objectType: SyncObjectType, objectId: string): SyncAppliedObject | undefined {
    const entry = this.readAppliedState().objects[syncObjectKey(objectType, objectId)];
    return entry ? structuredClone(entry) : undefined;
  }

  markApplied(change: SyncChange): void {
    const known = this.changes().find((candidate) => candidate.id === change.id);
    if (!known) throw new Error(`Cannot mark an unknown sync change as applied: ${change.id}`);
    const state = this.readAppliedState();
    state.objects[objectKey(known)] = {
      changeId: known.id,
      revision: known.mutation.revision,
      operation: known.mutation.operation,
    };
    this.saveAppliedState(state);
  }

  change(changeId: string): SyncChange | undefined {
    if (!CHANGE_ID.test(changeId)) throw new Error("Invalid sync change ID.");
    return this.changes().find((candidate) => candidate.id === changeId);
  }

  markPreparedLocalChangesApplied(envelopes: readonly EncryptedSyncChange[]): void {
    const known = new Map(this.changes().map((change) => [change.id, change]));
    const state = this.readAppliedState();
    for (const envelope of envelopes) {
      const change = known.get(envelope.id);
      if (!change) throw new Error(`Cannot mark an unknown sync change as applied: ${envelope.id}`);
      state.objects[objectKey(change)] = {
        changeId: change.id,
        revision: change.mutation.revision,
        operation: change.mutation.operation,
      };
    }
    this.saveAppliedState(state);
  }

  private readEnvelopes(): EncryptedSyncChange[] {
    this.key();
    assertNoSymlinkComponents(this.session.rootDir, this.changesDir);
    const names = fs
      .readdirSync(this.changesDir)
      .filter((name) => name.endsWith(".change.enc"))
      .sort();
    if (names.length > MAX_CHANGE_COUNT) {
      throw new Error(`A sync change store may contain at most ${MAX_CHANGE_COUNT} changes.`);
    }
    let totalBytes = 0;
    return names.map((name) => {
        const id = name.slice(0, -".change.enc".length);
        if (!CHANGE_ID.test(id)) throw new Error(`Invalid sync change filename: ${name}`);
        const filePath = resolveInside(this.changesDir, name);
        assertNotSymlink(filePath);
        totalBytes += fs.statSync(filePath).size;
        if (totalBytes > MAX_CHANGE_STORE_BYTES) {
          throw new Error("The sync change store exceeds its 512 MiB safety limit.");
        }
        const envelope = validateEnvelope(
          JSON.parse(readTextFileLimited(filePath, MAX_ENVELOPE_BYTES, `Sync envelope ${id}`))
        );
        if (envelope.id !== id) throw new Error(`Sync change filename does not match its envelope: ${id}`);
        return envelope;
      });
  }

  envelopes(): EncryptedSyncChange[] {
    const envelopes = this.readEnvelopes();
    const changes = envelopes.map((envelope) => openSyncChange(envelope, this.epochResolver()));
    validateChangeSet(changes);
    validateAuthorizedChanges(changes, readDeviceRegistry(this.session.rootDir, this.readKeys()));
    return structuredClone(envelopes);
  }

  changes(): SyncChange[] {
    const changes = this.readEnvelopes().map((envelope) => openSyncChange(envelope, this.epochResolver()));
    validateChangeSet(changes);
    validateAuthorizedChanges(changes, readDeviceRegistry(this.session.rootDir, this.readKeys()));
    return parentFirstChanges(changes);
  }

  verify(): SyncVerification {
    return validateChangeSet(this.changes());
  }

  private storeEnvelope(envelope: EncryptedSyncChange): boolean {
    openSyncChange(envelope, this.epochResolver());
    const destination = resolveInside(this.changesDir, changeFilename(envelope.id));
    assertNotSymlink(destination);
    if (fs.existsSync(destination)) return false;
    const serialized = JSON.stringify(envelope);
    const temporary = resolveInside(this.changesDir, `.${envelope.id}.${process.pid}.${crypto.randomUUID()}.tmp`);
    let descriptor: number | undefined;
    try {
      descriptor = fs.openSync(temporary, "wx", 0o600);
      fs.writeFileSync(descriptor, serialized);
      fs.fsyncSync(descriptor);
      fs.closeSync(descriptor);
      descriptor = undefined;
      try {
        fs.linkSync(temporary, destination);
        return true;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        assertNotSymlink(destination);
        return false;
      }
    } finally {
      if (descriptor !== undefined) fs.closeSync(descriptor);
      if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
    }
  }

  prepareLocalChanges(
    deviceId: string,
    mutations: readonly SyncMutation[],
    createdAt = new Date().toISOString(),
  ): EncryptedSyncChange[] {
    const current = this.changes();
    const prepared: EncryptedSyncChange[] = [];
    const registry = readDeviceRegistry(this.session.rootDir, this.readKeys());
    for (const mutation of mutations) {
      const verification = validateChangeSet(current);
      const previous = current
        .filter((change) => change.deviceId === deviceId)
        .sort((left, right) => left.sequence - right.sequence)
        .at(-1);
      const parents = [...new Set([...verification.heads, ...(previous ? [previous.id] : [])])].sort();
      const unsigned: Omit<SyncChangeBody, "authorization"> = {
        version: changeBodyVersion(mutation, Boolean(registry)),
        deviceId,
        sequence: (previous?.sequence ?? 0) + 1,
        previousDeviceChange: previous?.id ?? null,
        parents,
        createdAt,
        mutation,
      };
      const body = registry
        ? signAuthorizedChange(unsigned, registry, this.session.rootDir, this.readKeys())
        : validateSyncChangeBody(unsigned);
      const epoch = registry?.body.epoch ?? 1;
      // Epoch 1 used to seal under the bare documents key, which made a
      // change's identity depend on a key `vbrain rekey` rotates. The resolver
      // hands back the structured pair instead, so the id comes from the
      // permanent syncChange key and only the body key rotates. Changes an
      // earlier build wrote keep their old ids and still open through the
      // resolver's legacyKey.
      const contentKey = this.epochResolver()(epoch);
      const envelope = sealSyncChange(body, contentKey, epoch);
      const change = openSyncChange(envelope, this.epochResolver());
      current.push(change);
      validateChangeSet(current);
      validateAuthorizedChanges(current, registry);
      prepared.push(envelope);
    }
    return prepared;
  }

  installPreparedLocalChanges(envelopes: readonly EncryptedSyncChange[]): void {
    this.import(envelopes);
  }

  append(deviceId: string, mutation: SyncMutation, createdAt = new Date().toISOString()): SyncChange {
    return withVaultLock(this.vaultDir, () => {
      const current = this.changes();
      const verification = validateChangeSet(current);
      const deviceChanges = current
        .filter((change) => change.deviceId === deviceId)
        .sort((left, right) => left.sequence - right.sequence);
      const previous = deviceChanges.at(-1);
      const parents = [...new Set([...verification.heads, ...(previous ? [previous.id] : [])])].sort();
      const registry = readDeviceRegistry(this.session.rootDir, this.readKeys());
      const unsigned: Omit<SyncChangeBody, "authorization"> = {
        version: changeBodyVersion(mutation, Boolean(registry)),
        deviceId,
        sequence: (previous?.sequence ?? 0) + 1,
        previousDeviceChange: previous?.id ?? null,
        parents,
        createdAt,
        mutation,
      };
      const body = registry
        ? signAuthorizedChange(unsigned, registry, this.session.rootDir, this.readKeys())
        : validateSyncChangeBody(unsigned);
      const epoch = registry?.body.epoch ?? 1;
      // Epoch 1 used to seal under the bare documents key, which made a
      // change's identity depend on a key `vbrain rekey` rotates. The resolver
      // hands back the structured pair instead, so the id comes from the
      // permanent syncChange key and only the body key rotates. Changes an
      // earlier build wrote keep their old ids and still open through the
      // resolver's legacyKey.
      const contentKey = this.epochResolver()(epoch);
      const envelope = sealSyncChange(body, contentKey, epoch);
      const change = openSyncChange(envelope, this.epochResolver());
      validateChangeSet([...current, change]);
      validateAuthorizedChanges([...current, change], registry);
      this.storeEnvelope(envelope);
      return change;
    });
  }

  import(envelopes: readonly EncryptedSyncChange[]): { imported: number; existing: number } {
    return withVaultLock(this.vaultDir, () => {
      const current = this.changes();
      const incoming = envelopes.map((envelope) => openSyncChange(envelope, this.epochResolver()));
      const known = new Set(current.map((change) => change.id));
      const additions = incoming.filter((change) => !known.has(change.id));
      validateChangeSet([...current, ...additions]);
      validateAuthorizedChanges(
        [...current, ...additions],
        readDeviceRegistry(this.session.rootDir, this.readKeys()),
      );
      const incomingEnvelope = new Map(envelopes.map((envelope) => [envelope.id, envelope]));
      const additionIds = new Set(additions.map((change) => change.id));
      const byId = new Map(additions.map((change) => [change.id, change]));
      const ordered: SyncChange[] = [];
      const visited = new Set<string>();
      const visit = (change: SyncChange): void => {
        if (visited.has(change.id)) return;
        for (const parent of change.parents) {
          if (additionIds.has(parent)) visit(byId.get(parent)!);
        }
        visited.add(change.id);
        ordered.push(change);
      };
      for (const change of additions) visit(change);
      let imported = 0;
      let existing = envelopes.length - additions.length;
      for (const change of ordered) {
        if (this.storeEnvelope(incomingEnvelope.get(change.id)!)) imported += 1;
        else existing += 1;
      }
      return { imported, existing };
    });
  }

  resolve(objectType: SyncObjectType, objectId: string): SyncResolution {
    return resolveSyncObject(this.changes(), objectType, objectId);
  }

  conflicts(): SyncResolution[] {
    const changes = this.changes();
    const objects = new Map<string, { objectType: SyncObjectType; objectId: string }>();
    for (const change of changes) {
      const key = objectKey(change);
      objects.set(key, {
        objectType: change.mutation.objectType,
        objectId: change.mutation.objectId,
      });
    }
    return [...objects.values()]
      .map(({ objectType, objectId }) => resolveSyncObject(changes, objectType, objectId))
      .filter((resolution) => resolution.status === "conflict")
      .sort(
        (left, right) =>
          left.objectType.localeCompare(right.objectType) || left.objectId.localeCompare(right.objectId),
      );
  }
}

/**
 * A document session whose successful note, canvas, attachment and plugin mutations
 * are mirrored into the immutable sync DAG. Reads are inherited unchanged.
 * Remote application deliberately calls the base storage methods so receiving
 * a change never manufactures a second local change.
 */
export class SyncedDocumentVault extends DocumentVault {
  readonly changeLog: SyncChangeLog;
  private readonly localTransaction: SyncLocalTransaction;
  private readonly applyEngine: SyncApplyEngine;
  private readonly blobStore: SyncBlobStore;
  /**
   * A key session of this class own, used only to seal and open attachment
   * blobs. `DocumentVault.session` is private, so a subclass cannot borrow it;
   * the keyring caches unwrapped material per process, so this is a copy
   * rather than a second passphrase derivation. Zeroed by `lock()`.
   */
  private readonly blobSession: DocumentKeySession;
  private syncClosed = false;

  constructor(
    private readonly syncVaultDir: string,
    passphrase: string,
    private readonly deviceId?: string,
    transactionOptions: SyncTransactionOptions = {},
  ) {
    super(syncVaultDir, validateOptionalDeviceId(passphrase, deviceId));
    const changeLog = new SyncChangeLog(syncVaultDir, passphrase);
    let localTransaction: SyncLocalTransaction | undefined;
    let applyEngine: SyncApplyEngine | undefined;
    let blobSession: DocumentKeySession | undefined;
    try {
      localTransaction = new SyncLocalTransaction(syncVaultDir, passphrase, transactionOptions);
      applyEngine = new SyncApplyEngine(new SyncApplyReceiptStore(syncVaultDir, passphrase, transactionOptions));
      blobSession = openDocumentKey(syncVaultDir, passphrase);
      this.changeLog = changeLog;
      this.localTransaction = localTransaction;
      this.applyEngine = applyEngine;
      this.blobSession = blobSession;
      this.blobStore = new SyncBlobStore(syncVaultDir);
      withVaultLock(this.syncVaultDir, () => {
        this.localTransaction.recover(this.transactionEffects());
        this.applyEngine.recover(this.applyEffects());
      });
      // Unlock materializes/reconciles the ordinary document index once. A
      // later rejected local preflight can then remain byte-for-byte read-only.
      super.list();
    } catch (error) {
      if (blobSession) zeroBlobSession(blobSession);
      applyEngine?.close();
      localTransaction?.close();
      changeLog.close();
      super.lock();
      throw error;
    }
  }

  override lock(): void {
    if (!this.syncClosed) {
      zeroBlobSession(this.blobSession);
      this.applyEngine.close();
      this.localTransaction.close();
      this.changeLog.close();
      this.syncClosed = true;
    }
    super.lock();
  }

  private localDeviceId(): string {
    if (!this.deviceId) {
      throw new Error("A sync device ID is required for local document mutations.");
    }
    return this.deviceId;
  }

  private tryNote(reference: string): NoteDocument | undefined {
    try {
      return super.get(reference);
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("Note not found:")) return undefined;
      throw error;
    }
  }

  private tryCanvas(reference: string): CanvasDocument | undefined {
    try {
      return super.getCanvas(reference);
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("Canvas not found:")) return undefined;
      throw error;
    }
  }

  private tryPlugin(reference: string): PluginPackage | undefined {
    try {
      return super.getPlugin(reference);
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("Plugin not found:")) return undefined;
      throw error;
    }
  }

  private transactionEffects(): SyncTransactionEffects {
    return {
      writeStorage: (operations) => this.writeLocalStorage(operations),
      installEnvelopes: (changes) => this.changeLog.installPreparedLocalChanges(changes),
      writeCursor: (changes) => this.changeLog.markPreparedLocalChangesApplied(changes),
    };
  }

  private planLocalChanges(
    deviceId: string,
    operations: readonly SyncLocalStorageOperation[],
  ): EncryptedSyncChange[] {
    const current = this.changeLog.changes();
    const revisions = new Map<string, number | null>();
    const mutations: SyncMutation[] = [];
    for (const operation of operations) {
      const key = `${operation.objectType}\0${operation.objectId}`;
      let revision = revisions.get(key);
      if (revision === undefined) {
        const resolution = resolveSyncObject(current, operation.objectType, operation.objectId);
        revision = resolution.winner?.mutation.revision ?? null;
      }
      if (revision === null && operation.beforeValue !== null) {
        mutations.push({
          objectType: operation.objectType,
          objectId: operation.objectId,
          operation: "put",
          baseRevision: null,
          revision: 1,
          value: operation.beforeValue,
        });
        revision = 1;
        if (
          operation.objectType === "attachment" &&
          operation.operation === "put" &&
          operation.targetValue !== null &&
          sameAttachmentSnapshot(operation.beforeValue, operation.targetValue)
        ) {
          revisions.set(key, revision);
          continue;
        }
      }
      const targetRevision = (revision ?? 0) + 1;
      mutations.push({
        objectType: operation.objectType,
        objectId: operation.objectId,
        operation: operation.operation,
        baseRevision: revision,
        revision: targetRevision,
        value: operation.targetValue,
      });
      revisions.set(key, targetRevision);
    }
    return this.changeLog.prepareLocalChanges(deviceId, mutations);
  }

  private runLocalTransaction(
    deviceId: string,
    operations: readonly SyncLocalStorageOperation[],
  ): void {
    const changes = this.planLocalChanges(deviceId, operations);
    this.localTransaction.run({ deviceId, operations: [...operations], changes }, this.transactionEffects());
  }

  private noteOperation(document: NoteDocument, before: NoteDocument | undefined): SyncLocalStorageOperation {
    const targetValue = prevalidateLocalCaptureSnapshot(noteSnapshot(document), "Note snapshot");
    return {
      objectType: "note",
      objectId: document.id,
      operation: "put",
      input: targetValue,
      beforeStorageRevision: before?.revision ?? null,
      targetStorageRevision: document.revision,
      beforeValue: before ? prevalidateLocalCaptureSnapshot(noteSnapshot(before), "Note snapshot") : null,
      targetValue,
    };
  }

  private canvasOperation(document: CanvasDocument, before: CanvasDocument | undefined): SyncLocalStorageOperation {
    const targetValue = prevalidateLocalCaptureSnapshot(canvasSnapshot(document), "Canvas snapshot");
    return {
      objectType: "canvas",
      objectId: document.id,
      operation: "put",
      input: targetValue,
      beforeStorageRevision: before?.revision ?? null,
      targetStorageRevision: document.revision,
      beforeValue: before ? prevalidateLocalCaptureSnapshot(canvasSnapshot(before), "Canvas snapshot") : null,
      targetValue,
    };
  }

  private laterDocumentTargetMatches(
    operations: readonly SyncLocalStorageOperation[],
    index: number,
    revision: number,
    value: SyncJson,
  ): boolean {
    return operations
      .slice(index + 1)
      .some(
        (candidate) =>
          candidate.objectType === operations[index].objectType &&
          candidate.objectId === operations[index].objectId &&
          candidate.operation === "put" &&
          candidate.targetStorageRevision === revision &&
          sameSyncValue(candidate.targetValue, value),
      );
  }

  private appendLocal(
    objectType: SyncObjectType,
    objectId: string,
    operation: SyncOperation,
    value: SyncJson,
  ): SyncChange {
    const resolution = this.changeLog.resolve(objectType, objectId);
    const baseRevision = resolution.winner?.mutation.revision ?? null;
    return this.changeLog.append(this.localDeviceId(), {
      objectType,
      objectId,
      operation,
      baseRevision,
      revision: (baseRevision ?? 0) + 1,
      value,
    });
  }

  private assertExpectedDocumentState(
    operation: SyncLocalStorageOperation,
    currentRevision: number | null,
    currentValue: SyncJson,
  ): void {
    if (
      currentRevision !== operation.beforeStorageRevision ||
      !sameStorageValue(operation.objectType, currentValue, operation.beforeValue)
    ) {
      throw new Error(`Live ${operation.objectType} state does not match its pending sync transaction.`);
    }
  }

  private writeLocalStorage(operations: readonly SyncLocalStorageOperation[]): void {
    for (let index = 0; index < operations.length; index += 1) {
      const operation = operations[index];
      if (operation.objectType === "note") {
        const current = this.tryNote(operation.objectId);
        const currentValue = current ? asSyncJson(noteSnapshot(current)) : null;
        if (operation.operation === "delete") {
          if (!current) continue;
          this.assertExpectedDocumentState(operation, current.revision, currentValue);
          super.remove(operation.objectId);
          continue;
        }
        if (
          current &&
          current.revision === operation.targetStorageRevision &&
          sameSyncValue(currentValue, operation.targetValue)
        ) {
          continue;
        }
        if (current && this.laterDocumentTargetMatches(operations, index, current.revision, currentValue)) continue;
        this.assertExpectedDocumentState(operation, current?.revision ?? null, currentValue);
        const snapshot = parseNoteSnapshot(operation.targetValue);
        const written = super.put({
          id: operation.objectId,
          ...snapshot,
          baseRevision: (operation.targetStorageRevision ?? 1) - 1,
        });
        if (
          written.revision !== operation.targetStorageRevision ||
          !sameSyncValue(asSyncJson(noteSnapshot(written)), operation.targetValue)
        ) {
          throw new Error("A prepared note write did not materialize its intended state.");
        }
        continue;
      }
      if (operation.objectType === "canvas") {
        const current = this.tryCanvas(operation.objectId);
        const currentValue = current ? asSyncJson(canvasSnapshot(current)) : null;
        if (operation.operation === "delete") {
          if (!current) continue;
          this.assertExpectedDocumentState(operation, current.revision, currentValue);
          super.removeCanvas(operation.objectId);
          continue;
        }
        if (
          current &&
          current.revision === operation.targetStorageRevision &&
          sameSyncValue(currentValue, operation.targetValue)
        ) {
          continue;
        }
        if (current && this.laterDocumentTargetMatches(operations, index, current.revision, currentValue)) continue;
        this.assertExpectedDocumentState(operation, current?.revision ?? null, currentValue);
        const snapshot = parseCanvasSnapshot(operation.targetValue);
        const written = super.putCanvas({
          id: operation.objectId,
          ...snapshot,
          baseRevision: (operation.targetStorageRevision ?? 1) - 1,
        });
        if (
          written.revision !== operation.targetStorageRevision ||
          !sameSyncValue(asSyncJson(canvasSnapshot(written)), operation.targetValue)
        ) {
          throw new Error("A prepared canvas write did not materialize its intended state.");
        }
        continue;
      }

      if (operation.objectType === "plugin") {
        const current = this.tryPlugin(operation.objectId);
        const currentValue = current ? asSyncJson(pluginSnapshot(current)) : null;
        if (operation.operation === "delete") {
          if (!current) continue;
          this.assertExpectedDocumentState(operation, current.revision, currentValue);
          super.removePlugin(current.id);
          continue;
        }
        if (
          current &&
          current.revision === operation.targetStorageRevision &&
          sameSyncValue(currentValue, operation.targetValue)
        ) {
          continue;
        }
        if (current && this.laterDocumentTargetMatches(operations, index, current.revision, currentValue)) continue;
        this.assertExpectedDocumentState(operation, current?.revision ?? null, currentValue);
        const target = parsePluginSnapshot(operation.targetValue);
        const input = parsePluginLocalStorageInput(operation.input);
        if (
          !sameSyncValue(
            asSyncJson(target),
            asSyncJson({ manifest: input.manifest, source: input.source }),
          )
        ) {
          throw new Error("Plugin storage input does not match its portable sync snapshot.");
        }
        const written = super.installPlugin({
          manifest: input.manifest,
          source: input.source,
          enabled: input.localEnabled,
          baseRevision: (operation.targetStorageRevision ?? 1) - 1,
        });
        if (
          written.revision !== operation.targetStorageRevision ||
          !sameSyncValue(asSyncJson(pluginSnapshot(written)), operation.targetValue)
        ) {
          throw new Error("A prepared plugin write did not materialize its intended state.");
        }
        continue;
      }

      if (operation.objectType === "vault") {
        if (operation.objectId !== PLUGIN_POLICY_OBJECT_ID || operation.operation !== "put") {
          throw new Error("Unsupported synchronized vault storage operation.");
        }
        const current = super.pluginSecurityPolicy();
        const currentValue = asSyncJson(current);
        if (sameSyncValue(currentValue, operation.targetValue)) continue;
        this.assertExpectedDocumentState(operation, null, currentValue);
        const policy = parsePluginPolicySnapshot(operation.targetValue);
        super.savePluginPolicy(policy);
        for (const summary of super.listPlugins()) {
          const plugin = super.getPlugin(summary.id);
          if (plugin.enabled && plugin.signature && policy.revokedSigners.includes(plugin.signature.keyId)) {
            super.setPluginEnabled(plugin.id, false);
          }
        }
        continue;
      }

      const existing = super.listAttachments().some((item) => item.id === operation.objectId)
        ? super.getAttachment(operation.objectId)
        : undefined;
      const currentValue = existing
        ? asSyncJson(attachmentSnapshot(existing.data, existing.info, blobSealKey(this.blobSession), this.blobStore))
        : null;
      if (operation.operation === "delete") {
        if (!existing) continue;
        this.assertExpectedDocumentState(operation, null, currentValue);
        super.removeAttachment(operation.objectId);
        continue;
      }
      if (
        existing &&
        currentValue !== null &&
        operation.targetValue !== null &&
        sameAttachmentSnapshot(currentValue, operation.targetValue)
      ) {
        continue;
      }
      this.assertExpectedDocumentState(operation, null, currentValue);
      const info = super.putAttachment(
        ...this.attachmentFromSnapshot(operation.objectId, operation.targetValue),
      );
      if (info.id !== operation.objectId) throw new Error("Attachment sync snapshot does not match its content ID.");
    }
  }

  override put(input: NoteInput): NoteDocument {
    const deviceId = this.localDeviceId();
    return withVaultLock(this.syncVaultDir, () => {
      const prepared = this.prepareNotePuts([input])[0];
      const before = this.tryNote(prepared.document.id);
      this.runLocalTransaction(deviceId, [this.noteOperation(prepared.document, before)]);
      return super.get(prepared.document.id);
    });
  }

  override putMany(inputs: NoteInput[]): NoteDocument[] {
    const deviceId = this.localDeviceId();
    return withVaultLock(this.syncVaultDir, () => {
      const prepared = this.prepareNotePuts(inputs);
      if (prepared.length === 0) return super.putMany([]);
      const evolving = new Map<string, NoteDocument>();
      const operations = prepared.map((item) => {
        const before = evolving.get(item.document.id) ?? this.tryNote(item.document.id);
        evolving.set(item.document.id, item.document);
        return this.noteOperation(item.document, before);
      });
      this.runLocalTransaction(deviceId, operations);
      return prepared.map((item) => super.getRevision(item.document.id, item.document.revision));
    });
  }

  override remove(reference: string): NoteSummary {
    const deviceId = this.localDeviceId();
    return withVaultLock(this.syncVaultDir, () => {
      const current = super.get(reference);
      const beforeValue = prevalidateLocalCaptureSnapshot(noteSnapshot(current), "Note snapshot");
      const operation: SyncLocalStorageOperation = {
        objectType: "note",
        objectId: current.id,
        operation: "delete",
        input: null,
        beforeStorageRevision: current.revision,
        targetStorageRevision: null,
        beforeValue,
        targetValue: null,
      };
      this.runLocalTransaction(deviceId, [operation]);
      return noteSummary(current);
    });
  }

  override putCanvas(input: CanvasInput): CanvasDocument {
    const deviceId = this.localDeviceId();
    return withVaultLock(this.syncVaultDir, () => {
      const prepared = this.prepareCanvasPut(input);
      const before = this.tryCanvas(prepared.document.id);
      this.runLocalTransaction(deviceId, [this.canvasOperation(prepared.document, before)]);
      return super.getCanvas(prepared.document.id);
    });
  }

  override removeCanvas(reference: string): CanvasDocument {
    const deviceId = this.localDeviceId();
    return withVaultLock(this.syncVaultDir, () => {
      const current = super.getCanvas(reference);
      const beforeValue = prevalidateLocalCaptureSnapshot(canvasSnapshot(current), "Canvas snapshot");
      const operation: SyncLocalStorageOperation = {
        objectType: "canvas",
        objectId: current.id,
        operation: "delete",
        input: null,
        beforeStorageRevision: current.revision,
        targetStorageRevision: null,
        beforeValue,
        targetValue: null,
      };
      this.runLocalTransaction(deviceId, [operation]);
      return current;
    });
  }

  override putAttachment(data: Buffer, filename: string, mime = "application/octet-stream"): AttachmentInfo {
    const deviceId = this.localDeviceId();
    return withVaultLock(this.syncVaultDir, () => {
      const prepared = this.prepareAttachmentPut(data, filename, mime);
      const before = prepared.existed ? super.getAttachment(prepared.info.id) : undefined;
      const targetValue = prevalidateLocalCaptureSnapshot(
        attachmentSnapshot(prepared.data, prepared.info, blobSealKey(this.blobSession), this.blobStore),
        "Attachment snapshot",
      );
      const resolution = this.changeLog.resolve("attachment", prepared.info.id);
      if (prepared.existed && resolution.status === "clean" && resolution.winner?.mutation.operation === "put") {
        return prepared.info;
      }
      const operation: SyncLocalStorageOperation = {
        objectType: "attachment",
        objectId: prepared.info.id,
        operation: "put",
        input: targetValue,
        beforeStorageRevision: null,
        targetStorageRevision: null,
        beforeValue: before
          ? prevalidateLocalCaptureSnapshot(
              attachmentSnapshot(before.data, before.info, blobSealKey(this.blobSession), this.blobStore),
              "Attachment snapshot",
            )
          : null,
        targetValue,
      };
      this.runLocalTransaction(deviceId, [operation]);
      return super.getAttachment(prepared.info.id).info;
    });
  }

  override removeAttachment(id: string): AttachmentInfo {
    const deviceId = this.localDeviceId();
    return withVaultLock(this.syncVaultDir, () => {
      const attachment = super.getAttachment(id);
      const beforeValue = prevalidateLocalCaptureSnapshot(
        attachmentSnapshot(attachment.data, attachment.info, this.blobSession.key, this.blobStore),
        "Attachment snapshot",
      );
      const operation: SyncLocalStorageOperation = {
        objectType: "attachment",
        objectId: id,
        operation: "delete",
        input: null,
        beforeStorageRevision: null,
        targetStorageRevision: null,
        beforeValue,
        targetValue: null,
      };
      this.runLocalTransaction(deviceId, [operation]);
      return attachment.info;
    });
  }

  override installPlugin(input: {
    manifest: unknown;
    source: string;
    enabled?: boolean;
    baseRevision?: number;
  }): PluginPackage {
    const deviceId = this.localDeviceId();
    return withVaultLock(this.syncVaultDir, () => {
      const prepared = this.preparePluginInstall(input);
      const existing = this.tryPlugin(prepared.manifest.id);
      const targetValue = prevalidateLocalCaptureSnapshot(pluginSnapshot(prepared), "Plugin snapshot");
      const storageInput = prevalidateLocalCaptureSnapshot(
        { ...pluginSnapshot(prepared), localEnabled: prepared.enabled },
        "Plugin storage input",
      );
      const operation: SyncLocalStorageOperation = {
        objectType: "plugin",
        objectId: prepared.manifest.id,
        operation: "put",
        input: storageInput,
        beforeStorageRevision: existing?.revision ?? null,
        targetStorageRevision: prepared.revision,
        beforeValue: existing
          ? prevalidateLocalCaptureSnapshot(pluginSnapshot(existing), "Plugin snapshot")
          : null,
        targetValue,
      };
      this.runLocalTransaction(deviceId, [operation]);
      return super.getPlugin(prepared.manifest.id);
    });
  }

  override setPluginEnabled(reference: string, enabled: boolean): PluginSummary {
    // Execution consent is intentionally local and absent from the sync DAG.
    return super.setPluginEnabled(reference, enabled);
  }

  override removePlugin(reference: string): PluginSummary {
    const deviceId = this.localDeviceId();
    return withVaultLock(this.syncVaultDir, () => {
      const current = super.getPlugin(reference);
      const summary = super.listPlugins().find((candidate) => candidate.id === current.id);
      if (!summary) throw new Error(`Plugin not found: ${reference}`);
      const beforeValue = prevalidateLocalCaptureSnapshot(pluginSnapshot(current), "Plugin snapshot");
      const operation: SyncLocalStorageOperation = {
        objectType: "plugin",
        objectId: current.manifest.id,
        operation: "delete",
        input: null,
        beforeStorageRevision: current.revision,
        targetStorageRevision: null,
        beforeValue,
        targetValue: null,
      };
      this.runLocalTransaction(deviceId, [operation]);
      return summary;
    });
  }

  override setPluginRestrictedMode(restrictedMode: boolean): PluginSecurityPolicy {
    const deviceId = this.localDeviceId();
    return withVaultLock(this.syncVaultDir, () => {
      const previous = super.pluginSecurityPolicy();
      const policy = { ...previous, restrictedMode };
      this.runLocalTransaction(deviceId, [{
        objectType: "vault",
        objectId: PLUGIN_POLICY_OBJECT_ID,
        operation: "put",
        input: asSyncJson(policy),
        beforeStorageRevision: null,
        targetStorageRevision: null,
        beforeValue: asSyncJson(previous),
        targetValue: asSyncJson(policy),
      }]);
      return policy;
    });
  }

  override revokePluginSigner(reference: string): PluginSecurityPolicy {
    const deviceId = this.localDeviceId();
    return withVaultLock(this.syncVaultDir, () => {
      const plugin = super.getPlugin(reference);
      if (!plugin.signature) throw new Error("An unsigned plugin has no signer to revoke.");
      const previous = super.pluginSecurityPolicy();
      const policy = {
        ...previous,
        revokedSigners: [...new Set([...previous.revokedSigners, plugin.signature.keyId])].sort(),
      };
      this.runLocalTransaction(deviceId, [{
        objectType: "vault",
        objectId: PLUGIN_POLICY_OBJECT_ID,
        operation: "put",
        input: asSyncJson(policy),
        beforeStorageRevision: null,
        targetStorageRevision: null,
        beforeValue: asSyncJson(previous),
        targetValue: asSyncJson(policy),
      }]);
      return policy;
    });
  }

  override restorePluginSigner(keyId: string): PluginSecurityPolicy {
    const deviceId = this.localDeviceId();
    return withVaultLock(this.syncVaultDir, () => {
      const normalized = keyId.trim().toLowerCase();
      if (!/^[a-f0-9]{64}$/u.test(normalized)) throw new Error("Invalid plugin signer key ID.");
      const previous = super.pluginSecurityPolicy();
      const policy = {
        ...previous,
        revokedSigners: previous.revokedSigners.filter((entry) => entry !== normalized),
      };
      this.runLocalTransaction(deviceId, [{
        objectType: "vault",
        objectId: PLUGIN_POLICY_OBJECT_ID,
        operation: "put",
        input: asSyncJson(policy),
        beforeStorageRevision: null,
        targetStorageRevision: null,
        beforeValue: asSyncJson(previous),
        targetValue: asSyncJson(policy),
      }]);
      return policy;
    });
  }

  private expectedRemoteLive(change: SyncChange): SyncApplyLiveIdentity {
    const { objectType, objectId, operation } = change.mutation;
    if (operation === "delete") return { objectId, storageRevision: null };
    if (objectType === "note") return { objectId, storageRevision: (this.tryNote(objectId)?.revision ?? 0) + 1 };
    if (objectType === "canvas") return { objectId, storageRevision: (this.tryCanvas(objectId)?.revision ?? 0) + 1 };
    if (objectType === "plugin") return { objectId, storageRevision: (this.tryPlugin(objectId)?.revision ?? 0) + 1 };
    return { objectId, storageRevision: null };
  }

  private remoteChangeMaterialized(change: SyncChange, receipt: SyncApplyReceipt): boolean {
    const { objectType, objectId, operation, value } = change.mutation;
    if (objectType === "note") {
      const current = this.tryNote(objectId);
      return operation === "delete"
        ? !current
        : !!current &&
            current.id === receipt.expectedLive.objectId &&
            current.revision === receipt.expectedLive.storageRevision &&
            sameSyncValue(asSyncJson(noteSnapshot(current)), value);
    }
    if (objectType === "canvas") {
      const current = this.tryCanvas(objectId);
      return operation === "delete"
        ? !current
        : !!current &&
            current.id === receipt.expectedLive.objectId &&
            current.revision === receipt.expectedLive.storageRevision &&
            sameSyncValue(asSyncJson(canvasSnapshot(current)), value);
    }
    if (objectType === "attachment") {
      const present = super.listAttachments().some((attachment) => attachment.id === objectId);
      if (operation === "delete") return !present;
      if (!present) return false;
      const attachment = super.getAttachment(objectId);
      return (
        attachment.info.id === receipt.expectedLive.objectId &&
        value !== null &&
        sameAttachmentSnapshot(
          asSyncJson(attachmentSnapshot(attachment.data, attachment.info, this.blobSession.key, this.blobStore)),
          value,
        )
      );
    }
    if (objectType === "plugin") {
      const current = this.tryPlugin(objectId);
      return operation === "delete"
        ? !current
        : !!current &&
            current.revision === receipt.expectedLive.storageRevision &&
            sameSyncValue(asSyncJson(pluginSnapshot(current)), value);
    }
    if (objectType === "vault" && objectId === PLUGIN_POLICY_OBJECT_ID && operation === "put") {
      return sameSyncValue(asSyncJson(super.pluginSecurityPolicy()), value);
    }
    return false;
  }

  /** Refuse a reassembly that would be partial, naming how much is absent. */
  private assertBlobsStaged(snapshot: BlobAttachmentSyncSnapshot): void {
    const missing = this.blobStore.missing(snapshot.blobs);
    if (missing.length > 0) {
      throw new Error(`${missing.length} of ${snapshot.blobs.length} attachment chunks are missing.`);
    }
    const corrupt = this.blobStore.corrupt(snapshot.blobs);
    if (corrupt.length > 0) {
      throw new Error(`${corrupt.length} of ${snapshot.blobs.length} attachment chunks are corrupt.`);
    }
  }

  /**
   * Refuse a remote attachment change whose chunks have not arrived, before a
   * receipt exists for it. A receipt written first would be rolled forward on
   * every later unlock and fail there too, leaving the vault unopenable until
   * the blobs turned up.
   */
  private assertRemoteChangeIsStaged(change: SyncChange): void {
    const { objectType, operation, value } = change.mutation;
    if (objectType !== "attachment" || operation === "delete") return;
    const snapshot = parseAttachmentSnapshot(value);
    if (isBlobAttachmentSnapshot(snapshot)) this.assertBlobsStaged(snapshot);
  }

  /**
   * Materialize the plaintext an attachment snapshot stands for, as the
   * argument tuple `putAttachment` takes. A blob-form snapshot is reassembled
   * from the local blob store and a missing chunk fails closed, so a partial
   * attachment is never written. `objectId` is passed as the attachment id, so
   * a relay that reorders chunks or substitutes one from another attachment
   * fails the AEAD AAD check before the content-address check is reached.
   */
  private attachmentFromSnapshot(objectId: string, value: SyncJson): [Buffer, string, string] {
    const snapshot = parseAttachmentSnapshot(value);
    if (!isBlobAttachmentSnapshot(snapshot)) {
      return [Buffer.from(snapshot.data, "base64"), snapshot.filename, snapshot.mime];
    }
    this.assertBlobsStaged(snapshot);
    const data = Buffer.concat(
      snapshot.blobs.map((id, index) =>
        openAttachmentBlob(this.blobStore.read(id), objectId, index, blobReadKeys(this.blobSession)),
      ),
    );
    if (data.length !== snapshot.size) throw new Error("Attachment sync size does not match its blobs.");
    return [data, snapshot.filename, snapshot.mime];
  }

  private applyStorageChange(change: SyncChange): void {
    const { objectType, objectId, operation, value } = change.mutation;
    if (objectType === "note") {
      const current = this.tryNote(objectId);
      if (operation === "delete") {
        if (current) super.remove(objectId);
        return;
      }
      const snapshot = parseNoteSnapshot(value);
      super.put({ id: objectId, ...snapshot });
      return;
    }
    if (objectType === "canvas") {
      const current = this.tryCanvas(objectId);
      if (operation === "delete") {
        if (current) super.removeCanvas(objectId);
        return;
      }
      const snapshot = parseCanvasSnapshot(value);
      super.putCanvas({ id: objectId, ...snapshot });
      return;
    }
    if (objectType === "attachment") {
      if (operation === "delete") {
        if (super.listAttachments().some((item) => item.id === objectId)) super.removeAttachment(objectId);
        return;
      }
      const info = super.putAttachment(...this.attachmentFromSnapshot(objectId, value));
      if (info.id !== objectId) throw new Error("Attachment sync snapshot does not match its content ID.");
      return;
    }
    if (objectType === "plugin") {
      const existing = super.listPlugins().find((plugin) => plugin.manifestId === objectId);
      if (operation === "delete") {
        if (existing) super.removePlugin(existing.id);
        return;
      }
      const snapshot = parsePluginSnapshot(value);
      if (snapshot.manifest.id !== objectId) {
        throw new Error("Plugin sync snapshot does not match its manifest identity.");
      }
      super.installPlugin({
        manifest: snapshot.manifest,
        source: snapshot.source,
        enabled: false,
        ...(existing ? { baseRevision: existing.revision } : {}),
      });
      return;
    }
    if (objectType === "vault" && objectId === PLUGIN_POLICY_OBJECT_ID && operation === "put") {
      super.savePluginPolicy(parsePluginPolicySnapshot(value));
      return;
    }
    throw new Error(`Live sync application is not implemented for ${objectType} objects.`);
  }

  private applyEffects(): SyncApplyEffects {
    return {
      // `src/sync/engine.ts` types its change through the extracted
      // `src/sync/protocol.ts`, whose body version is still `1 | 2`. A version 3
      // body is structurally identical, so the widening stays at this boundary.
      findChange: (changeId) => this.changeLog.change(changeId) as ReturnType<SyncApplyEffects["findChange"]>,
      expectedLive: (change) => this.expectedRemoteLive(change),
      isMaterialized: (change, receipt) => this.remoteChangeMaterialized(change, receipt),
      writeStorage: (change) => this.applyStorageChange(change),
      writeCursor: (change) => this.changeLog.markApplied(change),
    };
  }

  applyResolved(objectType: SyncObjectType, objectId: string): SyncApplyResult {
    return withVaultLock(this.syncVaultDir, () => {
      const resolution = this.changeLog.resolve(objectType, objectId);
      if (resolution.status === "missing" || !resolution.winner) {
        throw new Error(`No sync changes exist for ${objectType}:${objectId}.`);
      }
      if (resolution.status === "conflict") {
        return {
          objectType,
          objectId,
          changeId: resolution.winner.id,
          revision: resolution.winner.mutation.revision,
          applied: 0,
          alreadyApplied: false,
          conflict: true,
          heads: resolution.heads,
        };
      }
      const winner = resolution.winner;
      const applied = this.changeLog.applied(objectType, objectId);
      if (applied?.changeId === winner.id) {
        return {
          objectType,
          objectId,
          changeId: winner.id,
          revision: winner.mutation.revision,
          applied: 0,
          alreadyApplied: true,
        };
      }

      const planned = planSyncApplication(
        this.changeLog.changes() as Parameters<typeof planSyncApplication>[0],
        objectType,
        objectId,
        winner as Parameters<typeof planSyncApplication>[3],
        applied,
      );
      for (const next of planned) this.assertRemoteChangeIsStaged(next);
      let appliedCount = 0;
      for (const next of planned) {
        this.applyEngine.apply(next, this.applyEffects());
        appliedCount += 1;
      }
      return {
        objectType,
        objectId,
        changeId: winner.id,
        revision: winner.mutation.revision,
        applied: appliedCount,
        alreadyApplied: false,
      };
    });
  }

  listConflicts(): SyncResolution[] {
    return this.changeLog.conflicts();
  }

  /**
   * Resolve an explicit head, or safely union a concurrent plugin policy.
   * No other object type receives a guessed winner: note/canvas/attachment and
   * plugin package conflicts require the caller to name one preserved head.
   */
  resolveConflict(
    objectType: SyncObjectType,
    objectId: string,
    selectedHeadId?: string,
  ): SyncApplyResult {
    this.localDeviceId();
    return withVaultLock(this.syncVaultDir, () => {
      const resolution = this.changeLog.resolve(objectType, objectId);
      if (resolution.status !== "conflict" || !resolution.winner) {
        throw new Error(`No unresolved sync conflict exists for ${objectType}:${objectId}.`);
      }

      let operation: SyncOperation;
      let value: SyncJson;
      if (selectedHeadId !== undefined) {
        if (!resolution.heads.includes(selectedHeadId)) {
          throw new Error("The selected change is not one of the current conflict heads.");
        }
        const selected = this.changeLog.change(selectedHeadId)!;
        operation = selected.mutation.operation;
        value = selected.mutation.value;
      } else if (objectType === "vault" && objectId === PLUGIN_POLICY_OBJECT_ID) {
        const policies = resolution.heads.map((head) => {
          const change = this.changeLog.change(head)!;
          if (change.mutation.operation !== "put") {
            throw new Error("A plugin policy deletion cannot be merged automatically.");
          }
          return parsePluginPolicySnapshot(change.mutation.value);
        });
        operation = "put";
        value = asSyncJson({
          version: 1,
          restrictedMode: policies.some((policy) => policy.restrictedMode),
          revokedSigners: [...new Set(policies.flatMap((policy) => policy.revokedSigners))].sort(),
        });
      } else {
        throw new Error("This conflict requires an explicit current head selection.");
      }

      this.appendLocal(objectType, objectId, operation, value);
      return this.applyResolved(objectType, objectId);
    });
  }
}
