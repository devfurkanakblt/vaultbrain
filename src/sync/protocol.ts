import crypto from "node:crypto";

import { decryptDocument, encryptDocument, type DocumentPayload } from "../document-crypto.js";

export const CHANGE_ID_CONTEXT = "secondbrain-vault:sync-change-id:v1";
export const CHANGE_KEY_CONTEXT = "secondbrain-vault:sync-change-key:v1";
export const CHANGE_AAD_PREFIX = "secondbrain-vault:sync-change:v1:";
export const APPLIED_AAD = "secondbrain-vault:sync-applied:v1";
export const MAX_CHANGE_BYTES = 8 * 1024 * 1024;
export const MAX_ENVELOPE_BYTES = 12 * 1024 * 1024;
export const MAX_PARENTS = 256;
export const MAX_JSON_DEPTH = 32;
export const MAX_JSON_NODES = 100_000;
export const CHANGE_ID = /^[a-f0-9]{64}$/u;
export const DEVICE_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[0-9a-f]{12}$/u;
export const OBJECT_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/u;

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
  version: 1;
  deviceId: string;
  sequence: number;
  previousDeviceChange: string | null;
  parents: string[];
  createdAt: string;
  mutation: SyncMutation;
}

export interface EncryptedSyncChange {
  version: 1;
  id: string;
  payload: DocumentPayload;
}

export interface SyncChange extends SyncChangeBody {
  id: string;
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

export function assertSyncJson(value: unknown, depth = 0, counter = { nodes: 0 }): asserts value is SyncJson {
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
    for (const item of value) assertSyncJson(item, depth + 1, counter);
    return;
  }
  if (typeof value !== "object") throw new Error("Sync changes may contain JSON values only.");
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new Error("Sync change JSON must use plain objects.");
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    assertUnicode(key, "Sync change key");
    if (key === "__proto__" || key === "prototype" || key === "constructor") throw new Error(`Unsafe sync change key: ${key}`);
    assertSyncJson(item, depth + 1, counter);
  }
}

/** RFC 8785-compatible canonical JSON for the JSON subset accepted above. */
export function canonicalSyncJson(value: SyncJson): string {
  assertSyncJson(value);
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
  if (!Number.isSafeInteger(value) || (value as number) < minimum) throw new Error(`${label} must be a safe integer of at least ${minimum}.`);
  return value as number;
}

function validateMutation(value: unknown): SyncMutation {
  const mutation = value as SyncMutation | undefined;
  if (!mutation || typeof mutation !== "object" || Array.isArray(mutation)) throw new Error("Sync change mutation must be an object.");
  if (!["note", "canvas", "attachment", "plugin", "vault"].includes(mutation.objectType)) throw new Error("Unsupported sync object type.");
  if (typeof mutation.objectId !== "string" || !OBJECT_ID.test(mutation.objectId)) throw new Error("Invalid sync object ID.");
  if (mutation.operation !== "put" && mutation.operation !== "delete") throw new Error("Unsupported sync operation.");
  const revision = integer(mutation.revision, 1, "Sync revision");
  const baseRevision = mutation.baseRevision === null ? null : integer(mutation.baseRevision, 0, "Sync base revision");
  if ((baseRevision === null && revision !== 1) || (baseRevision !== null && revision !== baseRevision + 1)) throw new Error("A sync revision must advance exactly one step from its base revision.");
  assertSyncJson(mutation.value);
  if (mutation.operation === "delete" && mutation.value !== null) throw new Error("A delete sync change cannot carry a value.");
  if (mutation.operation === "put" && mutation.value === null) throw new Error("A put sync change must carry a value.");
  return { objectType: mutation.objectType, objectId: mutation.objectId, operation: mutation.operation, baseRevision, revision, value: structuredClone(mutation.value) };
}

export function validateSyncChangeBody(value: unknown): SyncChangeBody {
  const body = value as SyncChangeBody | undefined;
  if (!body || typeof body !== "object" || Array.isArray(body) || body.version !== 1) throw new Error("Unsupported or invalid sync change.");
  if (typeof body.deviceId !== "string" || !DEVICE_ID.test(body.deviceId)) throw new Error("Sync device ID must be a lowercase UUID.");
  const sequence = integer(body.sequence, 1, "Sync device sequence");
  const previousDeviceChange = body.previousDeviceChange;
  if (previousDeviceChange !== null && (typeof previousDeviceChange !== "string" || !CHANGE_ID.test(previousDeviceChange))) throw new Error("Invalid previous device change ID.");
  if (!Array.isArray(body.parents) || body.parents.length > MAX_PARENTS) throw new Error(`A sync change may have at most ${MAX_PARENTS} parents.`);
  const parents = [...new Set(body.parents)];
  if (parents.length !== body.parents.length || parents.some((id) => typeof id !== "string" || !CHANGE_ID.test(id))) throw new Error("Sync parents must be unique change IDs.");
  parents.sort();
  if ((sequence === 1) !== (previousDeviceChange === null)) throw new Error("Only the first device change may omit its previous device change.");
  if (previousDeviceChange && !parents.includes(previousDeviceChange)) throw new Error("The previous device change must also be a causal parent.");
  const timestamp = typeof body.createdAt === "string" ? Date.parse(body.createdAt) : Number.NaN;
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== body.createdAt) throw new Error("Sync change timestamp must be a canonical ISO timestamp.");
  const normalized: SyncChangeBody = { version: 1, deviceId: body.deviceId, sequence, previousDeviceChange, parents, createdAt: body.createdAt, mutation: validateMutation(body.mutation) };
  if (Buffer.byteLength(canonicalSyncJson(normalized as unknown as SyncJson), "utf8") > MAX_CHANGE_BYTES) throw new Error("Sync change exceeds 8 MiB.");
  return normalized;
}

function changeId(body: SyncChangeBody, key: Buffer): string {
  return crypto.createHmac("sha256", key).update(CHANGE_ID_CONTEXT).update("\0").update(canonicalSyncJson(body as unknown as SyncJson)).digest("hex");
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
    return { version: 1, id, payload: encryptDocument(canonical, envelopeKey, `${CHANGE_AAD_PREFIX}${id}`) };
  } finally {
    envelopeKey.fill(0);
  }
}

function canonicalBase64(value: unknown, expectedBytes: number | undefined, label: string): string {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) throw new Error(`Encrypted sync payload has malformed ${label}.`);
  const decoded = Buffer.from(value, "base64");
  if (expectedBytes !== undefined && decoded.length !== expectedBytes) throw new Error(`Encrypted sync payload has invalid ${label} length.`);
  if (decoded.toString("base64") !== value) throw new Error(`Encrypted sync payload has non-canonical ${label}.`);
  return value;
}

export function validateEncryptedSyncChange(value: unknown): EncryptedSyncChange {
  const envelope = value as EncryptedSyncChange | undefined;
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope) || envelope.version !== 1) throw new Error("Unsupported or invalid encrypted sync envelope.");
  if (typeof envelope.id !== "string" || !CHANGE_ID.test(envelope.id)) throw new Error("Invalid encrypted sync change ID.");
  const payload = envelope.payload as DocumentPayload | undefined;
  if (!payload || payload.version !== 1 || typeof payload.ciphertext !== "string" || payload.ciphertext.length > Math.ceil((MAX_CHANGE_BYTES * 4) / 3) + 16) throw new Error("Invalid encrypted sync payload.");
  canonicalBase64(payload.iv, 12, "nonce");
  canonicalBase64(payload.authTag, 16, "authentication tag");
  canonicalBase64(payload.ciphertext, undefined, "ciphertext");
  return structuredClone(envelope);
}

export function openSyncChange(value: unknown, key: Buffer): SyncChange {
  const envelope = validateEncryptedSyncChange(value);
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
  if (plaintext !== canonicalSyncJson(body as unknown as SyncJson)) throw new Error("Sync change plaintext is not canonically encoded.");
  return { id: envelope.id, ...body };
}
