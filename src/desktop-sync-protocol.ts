export const DESKTOP_SYNC_PROTOCOL_VERSION = 1;
const MAX_SECRET_BYTES = 4096;
const MAX_JSON_BYTES = 256 * 1024;

export type DesktopSyncOperation = "init" | "request" | "approve" | "revoke" | "push" | "pull" | "conflicts" | "apply" | "resolve";
export type DesktopSyncProgressState = "running" | "complete" | "cancelled" | "failed";

export interface DesktopSyncRequest {
  version: 1;
  operation: DesktopSyncOperation;
  vaultPath: string;
  passphrase: string;
  deviceName?: string;
  deviceId?: string;
  enrollmentRequest?: unknown;
  selectedHeadId?: string;
  objectType?: string;
  objectId?: string;
  relayUrl?: string;
  relayToken?: string;
  authorityFingerprint?: string;
  checkpointId?: string;
}

export interface DesktopSyncProgress {
  version: 1;
  operation: DesktopSyncOperation;
  state: DesktopSyncProgressState;
  message?: string;
  result?: unknown;
}

const allowed = new Set(["version", "operation", "vaultPath", "passphrase", "deviceName", "deviceId", "enrollmentRequest", "selectedHeadId", "objectType", "objectId", "relayUrl", "relayToken", "authorityFingerprint", "checkpointId"]);
const operations = new Set<DesktopSyncOperation>(["init", "request", "approve", "revoke", "push", "pull", "conflicts", "apply", "resolve"]);
function string(value: unknown, label: string, limit = MAX_JSON_BYTES): string {
  if (typeof value !== "string" || !value || Buffer.byteLength(value, "utf8") > limit) throw new Error(`Invalid ${label}.`);
  return value;
}

/** Strict private-stdin protocol. It deliberately contains no logging shape for secrets. */
export function parseDesktopSyncRequest(value: unknown): DesktopSyncRequest {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Desktop sync request must be an object.");
  const raw = value as Record<string, unknown>;
  for (const key of Object.keys(raw)) if (!allowed.has(key)) throw new Error(`Unknown desktop sync request field: ${key}.`);
  if (raw.version !== DESKTOP_SYNC_PROTOCOL_VERSION || !operations.has(raw.operation as DesktopSyncOperation)) throw new Error("Unsupported desktop sync request version or operation.");
  const request: DesktopSyncRequest = { version: 1, operation: raw.operation as DesktopSyncOperation, vaultPath: string(raw.vaultPath, "vault path"), passphrase: string(raw.passphrase, "passphrase", MAX_SECRET_BYTES) };
  for (const field of ["deviceName", "deviceId", "selectedHeadId", "objectType", "objectId", "relayUrl", "relayToken", "authorityFingerprint", "checkpointId"] as const) if (raw[field] !== undefined) request[field] = string(raw[field], field, field === "relayToken" ? MAX_SECRET_BYTES : MAX_JSON_BYTES);
  if (raw.enrollmentRequest !== undefined) request.enrollmentRequest = raw.enrollmentRequest;
  if (request.deviceId && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(request.deviceId)) throw new Error("Invalid device ID.");
  if (request.operation === "pull" && !request.authorityFingerprint) throw new Error("A relay pull requires the verified authority fingerprint.");
  if (["push", "pull"].includes(request.operation)) {
    if (!request.relayUrl || !request.relayToken) throw new Error("Relay URL and token are required for relay sync.");
  }
  if (["init", "request"].includes(request.operation) && !request.deviceName) throw new Error("A device name is required.");
  if (request.operation === "revoke" && !request.deviceId) throw new Error("A device ID is required.");
  return request;
}

export function syncProgress(operation: DesktopSyncOperation, state: DesktopSyncProgressState, source?: DesktopSyncRequest, message?: string, result?: unknown): DesktopSyncProgress {
  void source;
  return { version: 1, operation, state, ...(message ? { message } : {}), ...(result === undefined ? {} : { result }) };
}
