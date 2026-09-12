import crypto from "node:crypto";
import { decryptDocument, encryptDocument, type DocumentPayload } from "../document-crypto.js";
import { AAD, canonicalBase64, syncChangeAad } from "../format-version.js";
export const MAX_CHANGE_BYTES = 8 * 1024 * 1024;
export const MAX_ENVELOPE_BYTES = 12 * 1024 * 1024;
export const MAX_PARENTS = 256;
export const MAX_JSON_DEPTH = 32;
export const MAX_JSON_NODES = 100_000;
export const CHANGE_ID = /^[a-f0-9]{64}$/u;
export const DEVICE_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
export const OBJECT_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/u;

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

export function assertUnicode(value: string, label: string): void {
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

export function validateJson(value: unknown, depth = 0, counter = { nodes: 0 }): asserts value is SyncJson {
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

export function integer(value: unknown, minimum: number, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) {
    throw new Error(`${label} must be a safe integer of at least ${minimum}.`);
  }
  return value as number;
}

export function validateMutation(value: unknown): SyncMutation {
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
export function changeBodyVersion(mutation: SyncMutation, authorized: boolean): 1 | 2 | 3 {
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

export function changeAuthorizationPayload(body: SyncChangeBody): Buffer {
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

export function changeEncryptionKey(key: Buffer, id: string, epoch = 1): Buffer {
  return crypto
    .createHmac("sha256", key)
    .update(epoch === 1 ? AAD.syncChangeKey : AAD.syncChangeKeyV2)
    .update("\0")
    .update(id)
    .digest();
}

function splitSyncKeys(keys: SyncChangeKeyMaterial): SyncChangeKeys {
  return Buffer.isBuffer(keys) ? { syncChangeKey: keys, syncEnvelopeKey: keys } : keys;
}

export function sealSyncChange(body: SyncChangeBody, keys: SyncChangeKeyMaterial, epoch = 1): EncryptedSyncChange {
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

export function validateEnvelope(value: unknown): EncryptedSyncChange {
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

export function openSyncChange(value: unknown, key: SyncChangeKeyMaterial | SyncEpochKeyResolver): SyncChange {
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

export { validateJson as assertSyncJson, validateEnvelope as validateEncryptedSyncChange };
export const CHANGE_ID_CONTEXT = AAD.syncChangeId;
export const CHANGE_KEY_CONTEXT = AAD.syncChangeKey;
export const CHANGE_AAD_PREFIX = AAD.syncChangePrefix;
export const APPLIED_AAD = AAD.syncApplied;
