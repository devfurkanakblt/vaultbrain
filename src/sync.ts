import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  decryptDocument,
  encryptDocument,
  openDocumentKey,
  type DocumentKeySession,
  type DocumentPayload,
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
  DocumentVault,
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

const CHANGE_ID_CONTEXT = "secondbrain-vault:sync-change-id:v1";
const CHANGE_KEY_CONTEXT = "secondbrain-vault:sync-change-key:v1";
const CHANGE_AAD_PREFIX = "secondbrain-vault:sync-change:v1:";
const APPLIED_AAD = "secondbrain-vault:sync-applied:v1";
const DEVICE_REGISTRY_AAD = "secondbrain-vault:sync-device-registry:v1";
const AUTHORITY_KEY_AAD = "secondbrain-vault:sync-authority-key:v1";
const DEVICE_KEY_AAD_PREFIX = "secondbrain-vault:sync-device-key:v1:";
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

/** Base64 plus the change body must remain inside the authenticated 8 MiB envelope limit. */
export const MAX_SYNC_ATTACHMENT_BYTES = Math.floor(((MAX_CHANGE_BYTES - 64 * 1024) * 3) / 4);

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
  version: 1 | 2;
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
  version: 1;
  id: string;
  payload: DocumentPayload;
}

export interface SyncChange extends SyncChangeBody {
  id: string;
}

export interface SyncEnrollmentRequest {
  version: 1;
  deviceId: string;
  name: string;
  publicKey: string;
  requestedAt: string;
  nonce: string;
  proof: string;
}

export interface SyncDeviceCertificate {
  version: 1;
  serial: number;
  deviceId: string;
  name: string;
  publicKey: string;
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
  version: 1;
  revision: number;
  epoch: number;
  authorityPublicKey: string;
  updatedAt: string;
  legacyChangeIds: string[];
  devices: SyncDeviceRecord[];
}

export interface SignedSyncDeviceRegistry {
  body: SyncDeviceRegistryBody;
  signature: string;
}

export interface EncryptedSyncDeviceRegistry {
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

interface AttachmentSyncSnapshot {
  filename: string;
  mime: string;
  data: string;
}

interface PluginSyncSnapshot {
  manifest: PluginPackage["manifest"];
  source: string;
  enabled: boolean;
}

const PLUGIN_POLICY_OBJECT_ID = "plugin-policy";

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

export function validateSyncChangeBody(value: unknown): SyncChangeBody {
  const body = value as SyncChangeBody | undefined;
  if (!body || typeof body !== "object" || Array.isArray(body) || (body.version !== 1 && body.version !== 2)) {
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
  const bytes = Buffer.byteLength(canonicalSyncJson(normalized as unknown as SyncJson), "utf8");
  if (bytes > MAX_CHANGE_BYTES) throw new Error("Sync change exceeds 8 MiB.");
  return normalized;
}

function changeAuthorizationPayload(body: SyncChangeBody): Buffer {
  if (body.version !== 2 || !body.authorization) {
    throw new Error("Only version 2 sync changes have a device signature payload.");
  }
  const payload = {
    version: 2,
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

function changeId(body: SyncChangeBody, key: Buffer): string {
  return crypto
    .createHmac("sha256", key)
    .update(CHANGE_ID_CONTEXT)
    .update("\0")
    .update(canonicalSyncJson(body as unknown as SyncJson))
    .digest("hex");
}

function changeEncryptionKey(key: Buffer, id: string): Buffer {
  return crypto.createHmac("sha256", key).update(CHANGE_KEY_CONTEXT).update("\0").update(id).digest();
}

export function sealSyncChange(body: SyncChangeBody, key: Buffer): EncryptedSyncChange {
  const normalized = validateSyncChangeBody(body);
  const canonical = canonicalSyncJson(normalized as unknown as SyncJson);
  const id = changeId(normalized, key);
  const envelopeKey = changeEncryptionKey(key, id);
  try {
    return {
      version: 1,
      id,
      payload: encryptDocument(canonical, envelopeKey, `${CHANGE_AAD_PREFIX}${id}`),
    };
  } finally {
    envelopeKey.fill(0);
  }
}

function canonicalBase64(value: unknown, expectedBytes: number | undefined, label: string): string {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) {
    throw new Error(`Encrypted sync payload has malformed ${label}.`);
  }
  const decoded = Buffer.from(value, "base64");
  if (expectedBytes !== undefined && decoded.length !== expectedBytes) {
    throw new Error(`Encrypted sync payload has invalid ${label} length.`);
  }
  if (decoded.toString("base64") !== value) throw new Error(`Encrypted sync payload has non-canonical ${label}.`);
  return value;
}

function validateEnvelope(value: unknown): EncryptedSyncChange {
  const envelope = value as EncryptedSyncChange | undefined;
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope) || envelope.version !== 1) {
    throw new Error("Unsupported or invalid encrypted sync envelope.");
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
  if (!request || typeof request !== "object" || Array.isArray(request) || request.version !== 1) {
    throw new Error("Unsupported or invalid sync enrollment request.");
  }
  if (typeof request.deviceId !== "string" || !DEVICE_ID.test(request.deviceId)) {
    throw new Error("Enrollment device ID must be a lowercase UUID.");
  }
  const normalized: SyncEnrollmentRequest = {
    version: 1,
    deviceId: request.deviceId,
    name: deviceName(request.name),
    publicKey: canonicalBase64(request.publicKey, 44, "enrollment public key"),
    requestedAt: canonicalTimestamp(request.requestedAt, "Enrollment request time"),
    nonce: canonicalBase64(request.nonce, 32, "enrollment nonce"),
    proof: canonicalBase64(request.proof, 64, "enrollment proof"),
  };
  const publicKey = publicKeyFromBase64(normalized.publicKey, "Enrollment public key");
  verifyCanonical(
    enrollmentRequestPayload({
      version: 1,
      deviceId: normalized.deviceId,
      name: normalized.name,
      publicKey: normalized.publicKey,
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
  if (!certificate || typeof certificate !== "object" || Array.isArray(certificate) || certificate.version !== 1) {
    throw new Error("Unsupported or invalid sync device certificate.");
  }
  if (typeof certificate.deviceId !== "string" || !DEVICE_ID.test(certificate.deviceId)) {
    throw new Error("Certificate device ID must be a lowercase UUID.");
  }
  return {
    version: 1,
    serial: integer(certificate.serial, 1, "Device certificate serial"),
    deviceId: certificate.deviceId,
    name: deviceName(certificate.name),
    publicKey: canonicalBase64(certificate.publicKey, 44, "certificate public key"),
    enrolledAt: canonicalTimestamp(certificate.enrolledAt, "Device enrollment time"),
    epoch: integer(certificate.epoch, 1, "Device certificate epoch"),
  };
}

function registryBodyPayload(body: SyncDeviceRegistryBody): SyncJson {
  return structuredClone(body) as unknown as SyncJson;
}

function validateSignedDeviceRegistry(value: unknown): SignedSyncDeviceRegistry {
  const registry = value as SignedSyncDeviceRegistry | undefined;
  const raw = registry?.body;
  if (!registry || typeof registry !== "object" || Array.isArray(registry) || !raw || raw.version !== 1) {
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
    version: 1,
    revision: integer(raw.revision, 1, "Device registry revision"),
    epoch: integer(raw.epoch, 1, "Device registry epoch"),
    authorityPublicKey,
    updatedAt: canonicalTimestamp(raw.updatedAt, "Device registry update time"),
    legacyChangeIds,
    devices,
  };
  for (const record of devices) {
    if (record.certificate.epoch > body.epoch) {
      throw new Error("A device certificate cannot target a future registry epoch.");
    }
  }
  const signature = verifyCanonical(registryBodyPayload(body), registry.signature, authorityKey, "Device registry signature");
  return { body, signature };
}

function registryFingerprint(registry: SignedSyncDeviceRegistry): string {
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

function encryptPrivateKey(key: crypto.KeyObject, vaultKey: Buffer, aad: string): DocumentPayload {
  return encryptDocument(exportPrivateKey(key), vaultKey, aad);
}

function readPrivateKey(filePath: string, vaultKey: Buffer, aad: string, label: string): crypto.KeyObject {
  if (!fs.existsSync(filePath)) throw new Error(`${label} is not available on this device.`);
  assertNotSymlink(filePath);
  const payload = JSON.parse(readTextFileLimited(filePath, 64 * 1024, label)) as DocumentPayload;
  return privateKeyFromBase64(decryptDocument(payload, vaultKey, aad), label);
}

function savePrivateKey(filePath: string, key: crypto.KeyObject, vaultKey: Buffer, aad: string): void {
  writeFileAtomic(filePath, JSON.stringify(encryptPrivateKey(key, vaultKey, aad)), { mode: 0o600 });
}

function readDeviceRegistry(rootDir: string, vaultKey: Buffer): SignedSyncDeviceRegistry | undefined {
  const filePath = registryPath(rootDir);
  if (!fs.existsSync(filePath)) return undefined;
  assertNotSymlink(filePath);
  const envelope = JSON.parse(
    readTextFileLimited(filePath, MAX_DEVICE_REGISTRY_BYTES, "Sync device registry"),
  ) as EncryptedSyncDeviceRegistry;
  if (!envelope || envelope.version !== 1 || !envelope.payload) {
    throw new Error("Unsupported or invalid encrypted sync device registry.");
  }
  const plaintext = decryptDocument(envelope.payload, vaultKey, DEVICE_REGISTRY_AAD);
  return validateSignedDeviceRegistry(JSON.parse(plaintext));
}

function encryptedRegistry(registry: SignedSyncDeviceRegistry, vaultKey: Buffer): EncryptedSyncDeviceRegistry {
  return {
    version: 1,
    payload: encryptDocument(canonicalSyncJson(registry as unknown as SyncJson), vaultKey, DEVICE_REGISTRY_AAD),
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

function enrollmentLegacyChanges(rootDir: string, vaultKey: Buffer): SyncChange[] {
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
    const change = openSyncChange(envelope, vaultKey);
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
  vaultKey: Buffer,
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
    `${DEVICE_KEY_AAD_PREFIX}${body.deviceId}`,
    "Sync device private key",
  );
  if (exportPublicKey(crypto.createPublicKey(privateKey)) !== record.certificate.publicKey) {
    throw new Error("The local sync private key does not match the enrolled device certificate.");
  }
  const unsigned: SyncChangeBody = {
    ...body,
    version: 2,
    authorization: { certificateSerial: record.certificate.serial, signature: Buffer.alloc(64).toString("base64") },
  };
  unsigned.authorization!.signature = crypto
    .sign(null, changeAuthorizationPayload(unsigned), privateKey)
    .toString("base64");
  return validateSyncChangeBody(unsigned);
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

  state(): SignedSyncDeviceRegistry | undefined {
    const registry = readDeviceRegistry(this.session.rootDir, this.key());
    return registry ? structuredClone(registry) : undefined;
  }

  fingerprint(): string | undefined {
    const registry = this.state();
    return registry ? registryFingerprint(registry) : undefined;
  }

  initializeOwner(
    name: string,
    deviceId = crypto.randomUUID(),
    now = new Date().toISOString(),
  ): SignedSyncDeviceRegistry {
    return withVaultLock(this.vaultDir, () => {
      if (readDeviceRegistry(this.session.rootDir, this.key())) {
        throw new Error("Sync device enrollment is already initialized.");
      }
      if (fs.existsSync(authorityKeyPath(this.session.rootDir))) {
        throw new Error("A local sync enrollment authority key already exists; explicit recovery is required.");
      }
      if (!DEVICE_ID.test(deviceId)) throw new Error("Sync device ID must be a lowercase UUID.");
      const normalizedTime = canonicalTimestamp(now, "Device enrollment time");
      const legacy = enrollmentLegacyChanges(this.session.rootDir, this.key()).map((change) => change.id);
      const authority = crypto.generateKeyPairSync("ed25519");
      const device = crypto.generateKeyPairSync("ed25519");
      const certificate: SyncDeviceCertificate = {
        version: 1,
        serial: 1,
        deviceId,
        name: deviceName(name),
        publicKey: exportPublicKey(device.publicKey),
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
      savePrivateKey(authorityKeyPath(this.session.rootDir), authority.privateKey, this.key(), AUTHORITY_KEY_AAD);
      savePrivateKey(
        deviceKeyPath(this.session.rootDir, deviceId),
        device.privateKey,
        this.key(),
        `${DEVICE_KEY_AAD_PREFIX}${deviceId}`,
      );
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
      const registry = readDeviceRegistry(this.session.rootDir, this.key());
      if (!registry) throw new Error("Initialize or import a trusted sync device registry first.");
      if (!DEVICE_ID.test(deviceId)) throw new Error("Sync device ID must be a lowercase UUID.");
      if (registry.body.devices.some((record) => record.certificate.deviceId === deviceId)) {
        throw new Error(`Sync device ${deviceId} is already enrolled.`);
      }
      if (fs.existsSync(deviceKeyPath(this.session.rootDir, deviceId))) {
        throw new Error(`A pending private key already exists for sync device ${deviceId}.`);
      }
      const pair = crypto.generateKeyPairSync("ed25519");
      const unsigned: Omit<SyncEnrollmentRequest, "proof"> = {
        version: 1,
        deviceId,
        name: deviceName(name),
        publicKey: exportPublicKey(pair.publicKey),
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
        `${DEVICE_KEY_AAD_PREFIX}${deviceId}`,
      );
      return validateEnrollmentRequest(request);
    });
  }

  enroll(requestValue: unknown, now = new Date().toISOString()): SignedSyncDeviceRegistry {
    return withVaultLock(this.vaultDir, () => {
      const registry = readDeviceRegistry(this.session.rootDir, this.key());
      if (!registry) throw new Error("Sync device enrollment is not initialized.");
      const request = validateEnrollmentRequest(requestValue);
      if (registry.body.devices.some((record) => record.certificate.deviceId === request.deviceId)) {
        throw new Error(`Sync device ${request.deviceId} is already enrolled.`);
      }
      const authorityKey = readPrivateKey(
        authorityKeyPath(this.session.rootDir),
        this.key(),
        AUTHORITY_KEY_AAD,
        "Sync enrollment authority private key",
      );
      if (exportPublicKey(crypto.createPublicKey(authorityKey)) !== registry.body.authorityPublicKey) {
        throw new Error("The local enrollment authority key does not match the pinned registry authority.");
      }
      const certificate: SyncDeviceCertificate = {
        version: 1,
        serial: Math.max(0, ...registry.body.devices.map((record) => record.certificate.serial)) + 1,
        deviceId: request.deviceId,
        name: request.name,
        publicKey: request.publicKey,
        enrolledAt: canonicalTimestamp(now, "Device enrollment time"),
        epoch: registry.body.epoch,
      };
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
      const registry = readDeviceRegistry(this.session.rootDir, this.key());
      if (!registry) throw new Error("Sync device enrollment is not initialized.");
      const record = registry.body.devices.find((candidate) => candidate.certificate.deviceId === deviceId);
      if (!record) throw new Error(`Sync device ${deviceId} is not enrolled.`);
      if (record.revokedAt) throw new Error(`Sync device ${deviceId} is already revoked.`);
      const cutoff = integer(revokedAfterSequence, 0, "Device revocation sequence");
      const authorityKey = readPrivateKey(
        authorityKeyPath(this.session.rootDir),
        this.key(),
        AUTHORITY_KEY_AAD,
        "Sync enrollment authority private key",
      );
      const revokedAt = canonicalTimestamp(now, "Device revocation time");
      const nextBody: SyncDeviceRegistryBody = {
        ...registry.body,
        revision: registry.body.revision + 1,
        updatedAt: revokedAt,
        devices: registry.body.devices.map((candidate) =>
          candidate.certificate.deviceId === deviceId
            ? { ...candidate, revokedAt, revokedAfterSequence: cutoff }
            : candidate,
        ),
      };
      const next = signRegistryBody(nextBody, authorityKey);
      saveDeviceRegistry(this.session.rootDir, this.key(), next);
      return structuredClone(next);
    });
  }

  exportRegistry(): EncryptedSyncDeviceRegistry {
    const registry = readDeviceRegistry(this.session.rootDir, this.key());
    if (!registry) throw new Error("Sync device enrollment is not initialized.");
    return encryptedRegistry(registry, this.key());
  }

  importRegistry(value: unknown, expectedAuthorityFingerprint?: string): SignedSyncDeviceRegistry {
    return withVaultLock(this.vaultDir, () => {
      const envelope = value as EncryptedSyncDeviceRegistry | undefined;
      if (!envelope || envelope.version !== 1 || !envelope.payload) {
        throw new Error("Unsupported or invalid encrypted sync device registry bundle.");
      }
      const incoming = validateSignedDeviceRegistry(
        JSON.parse(decryptDocument(envelope.payload, this.key(), DEVICE_REGISTRY_AAD)),
      );
      const current = readDeviceRegistry(this.session.rootDir, this.key());
      const fingerprint = registryFingerprint(incoming);
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
      saveDeviceRegistry(this.session.rootDir, this.key(), incoming);
      return structuredClone(incoming);
    });
  }
}

export function openSyncChange(value: unknown, key: Buffer): SyncChange {
  const envelope = validateEnvelope(value);
  const envelopeKey = changeEncryptionKey(key, envelope.id);
  let plaintext: string;
  try {
    plaintext = decryptDocument(envelope.payload, envelopeKey, `${CHANGE_AAD_PREFIX}${envelope.id}`);
  } finally {
    envelopeKey.fill(0);
  }
  if (Buffer.byteLength(plaintext, "utf8") > MAX_CHANGE_BYTES) throw new Error("Sync change exceeds 8 MiB.");
  const body = validateSyncChangeBody(JSON.parse(plaintext));
  const actual = Buffer.from(changeId(body, key), "hex");
  const expected = Buffer.from(envelope.id, "hex");
  if (!crypto.timingSafeEqual(actual, expected)) throw new Error("Sync change ID does not match its content.");
  if (plaintext !== canonicalSyncJson(body as unknown as SyncJson)) {
    throw new Error("Sync change plaintext is not canonically encoded.");
  }
  return { id: envelope.id, ...body };
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

function attachmentSnapshot(data: Buffer, info: AttachmentInfo): AttachmentSyncSnapshot {
  return { filename: info.filename, mime: info.mime, data: data.toString("base64") };
}

function pluginSnapshot(plugin: PluginPackage): PluginSyncSnapshot {
  return structuredClone({ manifest: plugin.manifest, source: plugin.source, enabled: plugin.enabled });
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

function parseAttachmentSnapshot(value: SyncJson): AttachmentSyncSnapshot {
  const raw = recordValue(value, "Attachment");
  const data = requiredString(raw.data, "Attachment sync data");
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(data)) {
    throw new Error("Attachment sync data must be canonical base64.");
  }
  if (Buffer.from(data, "base64").toString("base64") !== data) {
    throw new Error("Attachment sync data must be canonical base64.");
  }
  return {
    filename: requiredString(raw.filename, "Attachment sync filename"),
    mime: requiredString(raw.mime, "Attachment sync MIME type"),
    data,
  };
}

function parsePluginSnapshot(value: SyncJson): PluginSyncSnapshot {
  const raw = recordValue(value, "Plugin");
  if (!raw.manifest || typeof raw.manifest !== "object" || Array.isArray(raw.manifest)) {
    throw new Error("Plugin sync manifest must be an object.");
  }
  if (typeof raw.source !== "string" || typeof raw.enabled !== "boolean") {
    throw new Error("Plugin sync snapshot has invalid source or enabled state.");
  }
  return structuredClone({
    manifest: raw.manifest as unknown as PluginPackage["manifest"],
    source: raw.source,
    enabled: raw.enabled,
  });
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
    this.closed = true;
  }

  private key(): Buffer {
    if (this.closed) throw new Error("Sync change log is closed.");
    return this.session.key;
  }

  private readAppliedState(): SyncAppliedState {
    this.key();
    if (!fs.existsSync(this.appliedPath)) return { version: 1, objects: {} };
    assertNotSymlink(this.appliedPath);
    const payload = JSON.parse(
      readTextFileLimited(this.appliedPath, 64 * 1024 * 1024, "Sync application state")
    ) as DocumentPayload;
    const parsed = JSON.parse(decryptDocument(payload, this.key(), APPLIED_AAD)) as SyncAppliedState;
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
    const payload = encryptDocument(JSON.stringify(state), this.key(), APPLIED_AAD);
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
    const changes = envelopes.map((envelope) => openSyncChange(envelope, this.key()));
    validateChangeSet(changes);
    validateAuthorizedChanges(changes, readDeviceRegistry(this.session.rootDir, this.key()));
    return structuredClone(envelopes);
  }

  changes(): SyncChange[] {
    const changes = this.readEnvelopes().map((envelope) => openSyncChange(envelope, this.key()));
    validateChangeSet(changes);
    validateAuthorizedChanges(changes, readDeviceRegistry(this.session.rootDir, this.key()));
    return changes.sort(
      (left, right) => left.createdAt.localeCompare(right.createdAt) || left.id.localeCompare(right.id),
    );
  }

  verify(): SyncVerification {
    return validateChangeSet(this.changes());
  }

  private storeEnvelope(envelope: EncryptedSyncChange): boolean {
    openSyncChange(envelope, this.key());
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

  append(deviceId: string, mutation: SyncMutation, createdAt = new Date().toISOString()): SyncChange {
    return withVaultLock(this.vaultDir, () => {
      const current = this.changes();
      const verification = validateChangeSet(current);
      const deviceChanges = current
        .filter((change) => change.deviceId === deviceId)
        .sort((left, right) => left.sequence - right.sequence);
      const previous = deviceChanges.at(-1);
      const parents = [...new Set([...verification.heads, ...(previous ? [previous.id] : [])])].sort();
      const registry = readDeviceRegistry(this.session.rootDir, this.key());
      const unsigned: Omit<SyncChangeBody, "authorization"> = {
        version: registry ? 2 : 1,
        deviceId,
        sequence: (previous?.sequence ?? 0) + 1,
        previousDeviceChange: previous?.id ?? null,
        parents,
        createdAt,
        mutation,
      };
      const body = registry
        ? signAuthorizedChange(unsigned, registry, this.session.rootDir, this.key())
        : validateSyncChangeBody(unsigned);
      const envelope = sealSyncChange(body, this.key());
      const change = openSyncChange(envelope, this.key());
      validateChangeSet([...current, change]);
      validateAuthorizedChanges([...current, change], registry);
      this.storeEnvelope(envelope);
      return change;
    });
  }

  import(envelopes: readonly EncryptedSyncChange[]): { imported: number; existing: number } {
    return withVaultLock(this.vaultDir, () => {
      const current = this.changes();
      const incoming = envelopes.map((envelope) => openSyncChange(envelope, this.key()));
      const known = new Set(current.map((change) => change.id));
      const additions = incoming.filter((change) => !known.has(change.id));
      validateChangeSet([...current, ...additions]);
      validateAuthorizedChanges(
        [...current, ...additions],
        readDeviceRegistry(this.session.rootDir, this.key()),
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
}

/**
 * A document session whose successful note, canvas, attachment and plugin mutations
 * are mirrored into the immutable sync DAG. Reads are inherited unchanged.
 * Remote application deliberately calls the base storage methods so receiving
 * a change never manufactures a second local change.
 */
export class SyncedDocumentVault extends DocumentVault {
  readonly changeLog: SyncChangeLog;
  private syncClosed = false;

  constructor(
    private readonly syncVaultDir: string,
    passphrase: string,
    private readonly deviceId?: string,
  ) {
    super(syncVaultDir, passphrase);
    if (deviceId !== undefined && !DEVICE_ID.test(deviceId)) {
      super.lock();
      throw new Error("Sync device ID must be a lowercase UUID.");
    }
    this.changeLog = new SyncChangeLog(syncVaultDir, passphrase);
  }

  override lock(): void {
    if (!this.syncClosed) {
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

  private appendLocal(
    objectType: SyncObjectType,
    objectId: string,
    operation: SyncOperation,
    value: SyncJson,
  ): SyncChange {
    const resolution = this.changeLog.resolve(objectType, objectId);
    const baseRevision = resolution.winner?.mutation.revision ?? null;
    const change = this.changeLog.append(this.localDeviceId(), {
      objectType,
      objectId,
      operation,
      baseRevision,
      revision: (baseRevision ?? 0) + 1,
      value,
    });
    this.changeLog.markApplied(change);
    return change;
  }

  private ensureNoteBaseline(note: NoteDocument): void {
    if (this.changeLog.resolve("note", note.id).status !== "missing") return;
    this.appendLocal("note", note.id, "put", asSyncJson(noteSnapshot(note)));
  }

  private ensureCanvasBaseline(canvas: CanvasDocument): void {
    if (this.changeLog.resolve("canvas", canvas.id).status !== "missing") return;
    this.appendLocal("canvas", canvas.id, "put", asSyncJson(canvasSnapshot(canvas)));
  }

  private ensurePluginBaseline(plugin: PluginPackage): void {
    if (this.changeLog.resolve("plugin", plugin.manifest.id).status !== "missing") return;
    this.appendLocal("plugin", plugin.manifest.id, "put", asSyncJson(pluginSnapshot(plugin)));
  }

  private ensurePluginPolicyBaseline(policy: PluginSecurityPolicy): void {
    if (this.changeLog.resolve("vault", PLUGIN_POLICY_OBJECT_ID).status !== "missing") return;
    this.appendLocal("vault", PLUGIN_POLICY_OBJECT_ID, "put", asSyncJson(policy));
  }

  override put(input: NoteInput): NoteDocument {
    return withVaultLock(this.syncVaultDir, () => {
      assertSyncSnapshotSize(input, "Note snapshot");
      const existing = this.tryNote(input.id ?? input.path);
      if (existing) this.ensureNoteBaseline(existing);
      const note = super.put(input);
      this.appendLocal("note", note.id, "put", asSyncJson(noteSnapshot(note)));
      return note;
    });
  }

  override putMany(inputs: NoteInput[]): NoteDocument[] {
    return withVaultLock(this.syncVaultDir, () => {
      for (const input of inputs) {
        assertSyncSnapshotSize(input, "Note snapshot");
        const existing = this.tryNote(input.id ?? input.path);
        if (existing) this.ensureNoteBaseline(existing);
      }
      const notes = super.putMany(inputs);
      for (const note of notes) {
        this.appendLocal("note", note.id, "put", asSyncJson(noteSnapshot(note)));
      }
      return notes;
    });
  }

  override remove(reference: string): NoteSummary {
    return withVaultLock(this.syncVaultDir, () => {
      const current = super.get(reference);
      this.ensureNoteBaseline(current);
      const removed = super.remove(reference);
      this.appendLocal("note", current.id, "delete", null);
      return removed;
    });
  }

  override putCanvas(input: CanvasInput): CanvasDocument {
    return withVaultLock(this.syncVaultDir, () => {
      assertSyncSnapshotSize(input, "Canvas snapshot");
      const existing = this.tryCanvas(input.id ?? input.path);
      if (existing) this.ensureCanvasBaseline(existing);
      const canvas = super.putCanvas(input);
      this.appendLocal("canvas", canvas.id, "put", asSyncJson(canvasSnapshot(canvas)));
      return canvas;
    });
  }

  override removeCanvas(reference: string): CanvasDocument {
    return withVaultLock(this.syncVaultDir, () => {
      const current = super.getCanvas(reference);
      this.ensureCanvasBaseline(current);
      const removed = super.removeCanvas(reference);
      this.appendLocal("canvas", current.id, "delete", null);
      return removed;
    });
  }

  override putAttachment(data: Buffer, filename: string, mime = "application/octet-stream"): AttachmentInfo {
    if (data.length > MAX_SYNC_ATTACHMENT_BYTES) {
      throw new Error(
        `A synchronized attachment cannot exceed ${MAX_SYNC_ATTACHMENT_BYTES} bytes until blob transport is available.`,
      );
    }
    return withVaultLock(this.syncVaultDir, () => {
      const before = new Set(super.listAttachments().map((item) => item.id));
      const info = super.putAttachment(data, filename, mime);
      const resolution = this.changeLog.resolve("attachment", info.id);
      if (!before.has(info.id) || resolution.status !== "clean" || resolution.winner?.mutation.operation === "delete") {
        this.appendLocal("attachment", info.id, "put", asSyncJson(attachmentSnapshot(data, info)));
      }
      return info;
    });
  }

  override removeAttachment(id: string): AttachmentInfo {
    return withVaultLock(this.syncVaultDir, () => {
      const attachment = super.getAttachment(id);
      if (this.changeLog.resolve("attachment", id).status === "missing") {
        this.appendLocal("attachment", id, "put", asSyncJson(attachmentSnapshot(attachment.data, attachment.info)));
      }
      const removed = super.removeAttachment(id);
      this.appendLocal("attachment", id, "delete", null);
      return removed;
    });
  }

  override installPlugin(input: {
    manifest: unknown;
    source: string;
    enabled?: boolean;
    baseRevision?: number;
  }): PluginPackage {
    return withVaultLock(this.syncVaultDir, () => {
      const manifestId =
        input.manifest && typeof input.manifest === "object" && !Array.isArray(input.manifest)
          ? String((input.manifest as { id?: unknown }).id ?? "")
          : "";
      const existing = manifestId ? this.tryPlugin(manifestId) : undefined;
      if (existing) this.ensurePluginBaseline(existing);
      const plugin = super.installPlugin(input);
      this.appendLocal("plugin", plugin.manifest.id, "put", asSyncJson(pluginSnapshot(plugin)));
      return plugin;
    });
  }

  override setPluginEnabled(reference: string, enabled: boolean): PluginSummary {
    return withVaultLock(this.syncVaultDir, () => {
      const current = super.getPlugin(reference);
      this.ensurePluginBaseline(current);
      const summary = super.setPluginEnabled(reference, enabled);
      const plugin = super.getPlugin(summary.id);
      this.appendLocal("plugin", plugin.manifest.id, "put", asSyncJson(pluginSnapshot(plugin)));
      return summary;
    });
  }

  override removePlugin(reference: string): PluginSummary {
    return withVaultLock(this.syncVaultDir, () => {
      const current = super.getPlugin(reference);
      this.ensurePluginBaseline(current);
      const summary = super.removePlugin(reference);
      this.appendLocal("plugin", current.manifest.id, "delete", null);
      return summary;
    });
  }

  override setPluginRestrictedMode(restrictedMode: boolean): PluginSecurityPolicy {
    return withVaultLock(this.syncVaultDir, () => {
      this.ensurePluginPolicyBaseline(super.pluginSecurityPolicy());
      const policy = super.setPluginRestrictedMode(restrictedMode);
      this.appendLocal("vault", PLUGIN_POLICY_OBJECT_ID, "put", asSyncJson(policy));
      return policy;
    });
  }

  override revokePluginSigner(reference: string): PluginSecurityPolicy {
    return withVaultLock(this.syncVaultDir, () => {
      this.ensurePluginPolicyBaseline(super.pluginSecurityPolicy());
      const policy = super.revokePluginSigner(reference);
      this.appendLocal("vault", PLUGIN_POLICY_OBJECT_ID, "put", asSyncJson(policy));
      return policy;
    });
  }

  override restorePluginSigner(keyId: string): PluginSecurityPolicy {
    return withVaultLock(this.syncVaultDir, () => {
      this.ensurePluginPolicyBaseline(super.pluginSecurityPolicy());
      const policy = super.restorePluginSigner(keyId);
      this.appendLocal("vault", PLUGIN_POLICY_OBJECT_ID, "put", asSyncJson(policy));
      return policy;
    });
  }

  private isAncestor(changes: Map<string, SyncChange>, ancestor: string, descendant: string): boolean {
    const pending = [...(changes.get(descendant)?.parents ?? [])];
    const seen = new Set<string>();
    while (pending.length > 0) {
      const id = pending.pop()!;
      if (id === ancestor) return true;
      if (seen.has(id)) continue;
      seen.add(id);
      pending.push(...(changes.get(id)?.parents ?? []));
    }
    return false;
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
      const snapshot = parseAttachmentSnapshot(value);
      const info = super.putAttachment(Buffer.from(snapshot.data, "base64"), snapshot.filename, snapshot.mime);
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
        enabled: snapshot.enabled,
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

  applyResolved(objectType: SyncObjectType, objectId: string): SyncApplyResult {
    return withVaultLock(this.syncVaultDir, () => {
      const resolution = this.changeLog.resolve(objectType, objectId);
      if (resolution.status === "missing" || !resolution.winner) {
        throw new Error(`No sync changes exist for ${objectType}:${objectId}.`);
      }
      if (resolution.status === "conflict") {
        throw new Error(
          `Cannot apply ${objectType}:${objectId}: ${resolution.heads.length} unresolved sync heads remain.`,
        );
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

      const all = this.changeLog.changes();
      const byId = new Map(all.map((change) => [change.id, change]));
      if (applied && !byId.has(applied.changeId)) {
        throw new Error(`Applied sync cursor refers to a missing change: ${applied.changeId}`);
      }
      const appliedChange = applied ? byId.get(applied.changeId) : undefined;
      if (
        appliedChange &&
        (appliedChange.mutation.objectType !== objectType || appliedChange.mutation.objectId !== objectId)
      ) {
        throw new Error("Applied sync cursor refers to a change for another object.");
      }
      if (applied && !this.isAncestor(byId, applied.changeId, winner.id)) {
        throw new Error("The resolved sync winner does not descend from the locally applied change.");
      }

      const relevant = all.filter(
        (change) =>
          change.mutation.objectType === objectType &&
          change.mutation.objectId === objectId &&
          (change.id === winner.id || this.isAncestor(byId, change.id, winner.id)),
      );
      let cursor = applied;
      let appliedCount = 0;
      for (let revision = (cursor?.revision ?? 0) + 1; revision <= winner.mutation.revision; revision += 1) {
        const candidates = relevant
          .filter(
            (change) =>
              change.mutation.revision === revision &&
              (!cursor || this.isAncestor(byId, cursor.changeId, change.id)),
          )
          .sort((left, right) => {
            if (left.mutation.operation !== right.mutation.operation) {
              return left.mutation.operation === "delete" ? -1 : 1;
            }
            return left.id === right.id ? 0 : left.id < right.id ? 1 : -1;
          });
        const next = candidates[0];
        if (!next) throw new Error(`Resolved sync history is missing object revision ${revision}.`);
        this.applyStorageChange(next);
        this.changeLog.markApplied(next);
        cursor = {
          changeId: next.id,
          revision: next.mutation.revision,
          operation: next.mutation.operation,
        };
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
}
