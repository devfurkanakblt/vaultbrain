import fs from "node:fs";

import {
  decryptDocument,
  encryptDocument,
  openDocumentKey,
  type DocumentKeySession,
  type DocumentPayload,
} from "../document-crypto.js";
import { assertNoSymlinkComponents, assertNotSymlink, writeFileAtomic } from "../fs-safe.js";
import { forgetVaultKeys } from "../keyring.js";
import { resolveInside } from "../safety.js";
import {
  CHANGE_ID,
  DEVICE_ID,
  OBJECT_ID,
  assertSyncJson,
  canonicalSyncJson,
  validateEncryptedSyncChange,
  type EncryptedSyncChange,
  type SyncChange,
  type SyncJson,
  type SyncObjectType,
  type SyncOperation,
} from "./protocol.js";

export const LOCAL_TRANSACTION_AAD = "secondbrain-vault:sync-local-transaction:v1";
export const MAX_LOCAL_TRANSACTION_BYTES = 64 * 1024 * 1024;
const MAX_LOCAL_TRANSACTION_FILE_BYTES = 96 * 1024 * 1024;
const TRANSACTION_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;

export type SyncTransactionPhase = "prepared" | "storage-written" | "envelope-installed" | "cursor-written" | "cleared";

export interface SyncTransactionFaultPoint {
  phase: SyncTransactionPhase;
  timing: "after-effect" | "after-marker";
}

export type SyncTransactionFaultInjector = (point: SyncTransactionFaultPoint) => void;

export interface SyncTransactionOptions {
  faultInjector?: SyncTransactionFaultInjector;
  applyFaultInjector?: SyncApplyFaultInjector;
}

export const APPLY_RECEIPT_AAD = "secondbrain-vault:sync-apply-receipt:v1";
export type SyncApplyPhase = "prepared" | "storage-written" | "cursor-written" | "cleared";

export interface SyncApplyFaultPoint {
  phase: SyncApplyPhase;
  timing: "after-effect" | "after-marker";
}

export type SyncApplyFaultInjector = (point: SyncApplyFaultPoint) => void;

export interface SyncApplyLiveIdentity {
  objectId: string;
  storageRevision: number | null;
}

export interface SyncApplyReceipt {
  version: 1;
  changeId: string;
  objectType: Extract<SyncObjectType, "note" | "canvas" | "attachment">;
  objectId: string;
  operation: SyncOperation;
  expectedLive: SyncApplyLiveIdentity;
  phase: Exclude<SyncApplyPhase, "cleared">;
}

export interface SyncLocalStorageOperation {
  objectType: "note" | "canvas" | "attachment";
  objectId: string;
  operation: "put" | "delete";
  input: SyncJson;
  beforeStorageRevision: number | null;
  targetStorageRevision: number | null;
  beforeValue: SyncJson;
  targetValue: SyncJson;
}

export interface SyncPendingIntent {
  version: 1;
  transactionId: string;
  deviceId: string;
  createdAt: string;
  phase: Exclude<SyncTransactionPhase, "cleared">;
  operations: SyncLocalStorageOperation[];
  changes: EncryptedSyncChange[];
}

export interface SyncTransactionEffects {
  writeStorage(operations: readonly SyncLocalStorageOperation[]): void;
  installEnvelopes(changes: readonly EncryptedSyncChange[]): void;
  writeCursor(changes: readonly EncryptedSyncChange[]): void;
}

function canonicalTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function storageRevision(value: unknown, label: string): number | null {
  if (value === null) return null;
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new Error(`${label} must be null or a positive safe integer.`);
  }
  return value as number;
}

function validateStorageOperation(value: unknown): SyncLocalStorageOperation {
  const operation = value as SyncLocalStorageOperation | undefined;
  if (!operation || typeof operation !== "object" || Array.isArray(operation)) {
    throw new Error("A pending sync storage operation must be an object.");
  }
  if (operation.objectType !== "note" && operation.objectType !== "canvas" && operation.objectType !== "attachment") {
    throw new Error("A pending sync storage operation has an unsupported object type.");
  }
  if (typeof operation.objectId !== "string" || !OBJECT_ID.test(operation.objectId)) {
    throw new Error("A pending sync storage operation has an invalid object ID.");
  }
  if (operation.operation !== "put" && operation.operation !== "delete") {
    throw new Error("A pending sync storage operation has an unsupported operation.");
  }
  assertSyncJson(operation.input);
  assertSyncJson(operation.beforeValue);
  assertSyncJson(operation.targetValue);
  const beforeStorageRevision = storageRevision(operation.beforeStorageRevision, "Expected storage revision");
  const targetStorageRevision = storageRevision(operation.targetStorageRevision, "Target storage revision");
  if (operation.objectType === "attachment" && (beforeStorageRevision !== null || targetStorageRevision !== null)) {
    throw new Error("Attachment storage operations cannot carry document revisions.");
  }
  if (operation.objectType !== "attachment" && operation.operation === "put" && targetStorageRevision === null) {
    throw new Error("A note or canvas put needs a target storage revision.");
  }
  if (operation.objectType !== "attachment" && (operation.beforeValue === null) !== (beforeStorageRevision === null)) {
    throw new Error("A pending document operation has an inconsistent expected revision and snapshot.");
  }
  if (operation.objectType !== "attachment" && operation.operation === "delete" && targetStorageRevision !== null) {
    throw new Error("A pending document delete cannot carry a target storage revision.");
  }
  if (operation.operation === "delete" && operation.targetValue !== null) {
    throw new Error("A pending delete cannot carry a target snapshot.");
  }
  if (operation.operation === "delete" && operation.input !== null) {
    throw new Error("A pending delete cannot carry stable put input.");
  }
  if (operation.operation === "put" && operation.targetValue === null) {
    throw new Error("A pending put must carry a target snapshot.");
  }
  if (
    operation.operation === "put" &&
    canonicalSyncJson(operation.input) !== canonicalSyncJson(operation.targetValue)
  ) {
    throw new Error("A pending put's stable input does not match its target snapshot.");
  }
  return {
    objectType: operation.objectType,
    objectId: operation.objectId,
    operation: operation.operation,
    input: structuredClone(operation.input),
    beforeStorageRevision,
    targetStorageRevision,
    beforeValue: structuredClone(operation.beforeValue),
    targetValue: structuredClone(operation.targetValue),
  };
}

function validatePendingIntent(value: unknown): SyncPendingIntent {
  const pending = value as SyncPendingIntent | undefined;
  if (!pending || typeof pending !== "object" || Array.isArray(pending) || pending.version !== 1) {
    throw new Error("Unsupported or invalid pending sync transaction.");
  }
  if (typeof pending.transactionId !== "string" || !TRANSACTION_ID.test(pending.transactionId)) {
    throw new Error("A pending sync transaction has an invalid transaction ID.");
  }
  if (typeof pending.deviceId !== "string" || !DEVICE_ID.test(pending.deviceId)) {
    throw new Error("A pending sync transaction has an invalid device ID.");
  }
  if (!canonicalTimestamp(pending.createdAt)) {
    throw new Error("A pending sync transaction has an invalid timestamp.");
  }
  if (
    pending.phase !== "prepared" &&
    pending.phase !== "storage-written" &&
    pending.phase !== "envelope-installed" &&
    pending.phase !== "cursor-written"
  ) {
    throw new Error("A pending sync transaction has an invalid durable phase.");
  }
  if (!Array.isArray(pending.operations) || pending.operations.length < 1 || pending.operations.length > 100_000) {
    throw new Error("A pending sync transaction has an invalid operation count.");
  }
  if (!Array.isArray(pending.changes) || pending.changes.length < 1 || pending.changes.length > 200_000) {
    throw new Error("A pending sync transaction has an invalid change count.");
  }
  return {
    version: 1,
    transactionId: pending.transactionId,
    deviceId: pending.deviceId,
    createdAt: pending.createdAt,
    phase: pending.phase,
    operations: pending.operations.map(validateStorageOperation),
    changes: pending.changes.map(validateEncryptedSyncChange),
  };
}

/** Encrypted, bounded single-writer journal for one acknowledged local capture. */
export class SyncLocalTransaction {
  private readonly session: DocumentKeySession;
  private readonly syncDir: string;
  private readonly pendingPath: string;
  private closed = false;

  constructor(
    private readonly vaultDir: string,
    passphrase: string,
    private readonly options: SyncTransactionOptions = {},
  ) {
    this.session = openDocumentKey(vaultDir, passphrase);
    this.syncDir = resolveInside(this.session.rootDir, "sync");
    this.pendingPath = resolveInside(this.syncDir, "pending-local.enc");
    assertNoSymlinkComponents(this.session.rootDir, this.syncDir);
    fs.mkdirSync(this.syncDir, { recursive: true, mode: 0o700 });
  }

  close(): void {
    if (this.closed) return;
    this.session.key.fill(0);
    this.session.attachmentIdKey.fill(0);
    this.session.syncChangeKey.fill(0);
    this.session.syncEnvelopeKey.fill(0);
    forgetVaultKeys(this.vaultDir);
    this.closed = true;
  }

  private key(): Buffer {
    if (this.closed) throw new Error("Sync local transaction store is closed.");
    return this.session.key;
  }

  private fault(phase: SyncTransactionPhase, timing: SyncTransactionFaultPoint["timing"]): void {
    this.options.faultInjector?.({ phase, timing });
  }

  private save(intent: SyncPendingIntent): void {
    const normalized = validatePendingIntent(intent);
    const plaintext = JSON.stringify(normalized);
    if (Buffer.byteLength(plaintext, "utf8") > MAX_LOCAL_TRANSACTION_BYTES) {
      throw new Error(`A pending sync transaction cannot exceed ${MAX_LOCAL_TRANSACTION_BYTES} bytes.`);
    }
    const payload = encryptDocument(plaintext, this.key(), LOCAL_TRANSACTION_AAD);
    const serialized = JSON.stringify(payload);
    if (Buffer.byteLength(serialized, "utf8") > MAX_LOCAL_TRANSACTION_FILE_BYTES) {
      throw new Error("The encrypted pending sync transaction is too large.");
    }
    assertNoSymlinkComponents(this.session.rootDir, this.pendingPath);
    writeFileAtomic(this.pendingPath, serialized, { mode: 0o600 });
  }

  private read(): SyncPendingIntent | undefined {
    this.key();
    assertNoSymlinkComponents(this.session.rootDir, this.pendingPath);
    if (!fs.existsSync(this.pendingPath)) return undefined;
    assertNotSymlink(this.pendingPath);
    const stat = fs.statSync(this.pendingPath);
    if (!stat.isFile() || stat.size > MAX_LOCAL_TRANSACTION_FILE_BYTES) {
      throw new Error("The encrypted pending sync transaction is invalid or too large.");
    }
    const payload = JSON.parse(fs.readFileSync(this.pendingPath, "utf8")) as DocumentPayload;
    const plaintext = decryptDocument(payload, this.key(), LOCAL_TRANSACTION_AAD);
    if (Buffer.byteLength(plaintext, "utf8") > MAX_LOCAL_TRANSACTION_BYTES) {
      throw new Error("The pending sync transaction is too large.");
    }
    return validatePendingIntent(JSON.parse(plaintext));
  }

  private advance(intent: SyncPendingIntent, phase: SyncPendingIntent["phase"]): SyncPendingIntent {
    const advanced: SyncPendingIntent = { ...intent, phase };
    this.save(advanced);
    this.fault(phase, "after-marker");
    return advanced;
  }

  private clear(): void {
    assertNoSymlinkComponents(this.session.rootDir, this.pendingPath);
    assertNotSymlink(this.pendingPath);
    if (fs.existsSync(this.pendingPath)) fs.unlinkSync(this.pendingPath);
    this.fault("cleared", "after-marker");
  }

  private rollForward(intent: SyncPendingIntent, effects: SyncTransactionEffects): void {
    let current = intent;
    if (current.phase === "prepared") {
      effects.writeStorage(current.operations);
      this.fault("storage-written", "after-effect");
      current = this.advance(current, "storage-written");
    }
    if (current.phase === "storage-written") {
      effects.installEnvelopes(current.changes);
      this.fault("envelope-installed", "after-effect");
      current = this.advance(current, "envelope-installed");
    }
    if (current.phase === "envelope-installed") {
      effects.writeCursor(current.changes);
      this.fault("cursor-written", "after-effect");
      current = this.advance(current, "cursor-written");
    }
    if (current.phase === "cursor-written") this.clear();
  }

  run(
    input: Omit<SyncPendingIntent, "version" | "transactionId" | "createdAt" | "phase">,
    effects: SyncTransactionEffects,
  ): void {
    if (this.read()) throw new Error("A pending local sync transaction must be recovered before another starts.");
    const intent: SyncPendingIntent = {
      version: 1,
      transactionId: crypto.randomUUID(),
      deviceId: input.deviceId,
      createdAt: new Date().toISOString(),
      phase: "prepared",
      operations: input.operations.map((operation) => structuredClone(operation)),
      changes: input.changes.map((change) => structuredClone(change)),
    };
    this.save(intent);
    this.fault("prepared", "after-marker");
    this.rollForward(intent, effects);
  }

  recover(effects: SyncTransactionEffects): boolean {
    const intent = this.read();
    if (!intent) return false;
    this.rollForward(intent, effects);
    return true;
  }
}

function validateApplyReceipt(value: unknown): SyncApplyReceipt {
  const receipt = value as SyncApplyReceipt | undefined;
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt) || receipt.version !== 1) {
    throw new Error("Unsupported or invalid sync apply receipt.");
  }
  if (!CHANGE_ID.test(receipt.changeId)) throw new Error("A sync apply receipt has an invalid change ID.");
  if (receipt.objectType !== "note" && receipt.objectType !== "canvas" && receipt.objectType !== "attachment") {
    throw new Error("A sync apply receipt has an unsupported object type.");
  }
  if (typeof receipt.objectId !== "string" || !OBJECT_ID.test(receipt.objectId)) {
    throw new Error("A sync apply receipt has an invalid object ID.");
  }
  if (receipt.operation !== "put" && receipt.operation !== "delete") {
    throw new Error("A sync apply receipt has an invalid operation.");
  }
  if (
    !receipt.expectedLive ||
    typeof receipt.expectedLive !== "object" ||
    receipt.expectedLive.objectId !== receipt.objectId ||
    !(
      receipt.expectedLive.storageRevision === null ||
      (Number.isSafeInteger(receipt.expectedLive.storageRevision) && receipt.expectedLive.storageRevision >= 1)
    )
  ) {
    throw new Error("A sync apply receipt has an invalid expected live identity.");
  }
  if (receipt.phase !== "prepared" && receipt.phase !== "storage-written" && receipt.phase !== "cursor-written") {
    throw new Error("A sync apply receipt has an invalid phase.");
  }
  return structuredClone(receipt);
}

/**
 * The remote-apply receipt is intentionally separate from the local capture
 * transaction. It records one storage mutation at a time, allowing recovery
 * to recognize a completed write before it advances the public sync cursor.
 */
export class SyncApplyReceiptStore {
  private readonly session: DocumentKeySession;
  private readonly syncDir: string;
  private readonly receiptPath: string;
  private closed = false;

  constructor(
    private readonly vaultDir: string,
    passphrase: string,
    private readonly options: SyncTransactionOptions = {},
  ) {
    this.session = openDocumentKey(vaultDir, passphrase);
    this.syncDir = resolveInside(this.session.rootDir, "sync");
    this.receiptPath = resolveInside(this.syncDir, "apply-receipt.enc");
    assertNoSymlinkComponents(this.session.rootDir, this.syncDir);
    fs.mkdirSync(this.syncDir, { recursive: true, mode: 0o700 });
  }

  close(): void {
    if (this.closed) return;
    this.session.key.fill(0);
    this.session.attachmentIdKey.fill(0);
    this.session.syncChangeKey.fill(0);
    this.session.syncEnvelopeKey.fill(0);
    forgetVaultKeys(this.vaultDir);
    this.closed = true;
  }

  private key(): Buffer {
    if (this.closed) throw new Error("Sync apply receipt store is closed.");
    return this.session.key;
  }

  fault(phase: SyncApplyPhase, timing: SyncApplyFaultPoint["timing"]): void {
    this.options.applyFaultInjector?.({ phase, timing });
  }

  private save(receipt: SyncApplyReceipt): void {
    const plaintext = JSON.stringify(validateApplyReceipt(receipt));
    const payload = encryptDocument(plaintext, this.key(), APPLY_RECEIPT_AAD);
    assertNoSymlinkComponents(this.session.rootDir, this.receiptPath);
    writeFileAtomic(this.receiptPath, JSON.stringify(payload), { mode: 0o600 });
  }

  read(): SyncApplyReceipt | undefined {
    this.key();
    assertNoSymlinkComponents(this.session.rootDir, this.receiptPath);
    if (!fs.existsSync(this.receiptPath)) return undefined;
    assertNotSymlink(this.receiptPath);
    const payload = JSON.parse(fs.readFileSync(this.receiptPath, "utf8")) as DocumentPayload;
    return validateApplyReceipt(JSON.parse(decryptDocument(payload, this.key(), APPLY_RECEIPT_AAD)));
  }

  begin(change: SyncChange, expectedLive: SyncApplyLiveIdentity): SyncApplyReceipt {
    if (this.read()) throw new Error("A pending sync apply receipt must be recovered before another starts.");
    if (
      change.mutation.objectType !== "note" &&
      change.mutation.objectType !== "canvas" &&
      change.mutation.objectType !== "attachment"
    ) {
      throw new Error(`Live sync application is not implemented for ${change.mutation.objectType} objects.`);
    }
    const receipt: SyncApplyReceipt = {
      version: 1,
      changeId: change.id,
      objectType: change.mutation.objectType,
      objectId: change.mutation.objectId,
      operation: change.mutation.operation,
      expectedLive: structuredClone(expectedLive),
      phase: "prepared",
    };
    this.save(receipt);
    this.fault("prepared", "after-marker");
    return receipt;
  }

  advance(receipt: SyncApplyReceipt, phase: SyncApplyReceipt["phase"]): SyncApplyReceipt {
    const advanced = { ...receipt, phase };
    this.save(advanced);
    this.fault(phase, "after-marker");
    return advanced;
  }

  clear(): void {
    assertNoSymlinkComponents(this.session.rootDir, this.receiptPath);
    assertNotSymlink(this.receiptPath);
    if (fs.existsSync(this.receiptPath)) fs.unlinkSync(this.receiptPath);
    this.fault("cleared", "after-marker");
  }
}
