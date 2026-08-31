import { withVaultLock } from "./vault-lock.js";
import {
  DocumentVault,
  type AttachmentInfo,
  type CanvasDocument,
  type CanvasInput,
  type NoteDocument,
  type NoteInput,
  type NoteSummary,
} from "./documents.js";
import { SyncChangeLog, resolveSyncObject } from "./sync/change-log.js";
import {
  DEVICE_ID,
  MAX_SYNC_ATTACHMENT_BYTES,
  canonicalSyncJson,
  type EncryptedSyncChange,
  type SyncChange,
  type SyncJson,
  type SyncMutation,
} from "./sync/protocol.js";
import {
  asSyncJson,
  attachmentSnapshot,
  canvasSnapshot,
  noteSnapshot,
  parseAttachmentSnapshot,
  parseCanvasSnapshot,
  parseNoteSnapshot,
  prevalidateLocalCaptureSnapshot,
} from "./sync/snapshots.js";
import {
  SyncLocalTransaction,
  type SyncLocalStorageOperation,
  type SyncTransactionEffects,
  type SyncTransactionOptions,
} from "./sync/transaction.js";

export {
  APPLIED_AAD,
  CHANGE_AAD_PREFIX,
  CHANGE_ID,
  CHANGE_ID_CONTEXT,
  CHANGE_KEY_CONTEXT,
  DEVICE_ID,
  MAX_CHANGE_BYTES,
  MAX_ENVELOPE_BYTES,
  MAX_JSON_DEPTH,
  MAX_JSON_NODES,
  MAX_PARENTS,
  MAX_SYNC_ATTACHMENT_BYTES,
  OBJECT_ID,
  assertSyncJson,
  canonicalSyncJson,
  openSyncChange,
  sealSyncChange,
  validateEncryptedSyncChange,
  validateSyncChangeBody,
} from "./sync/protocol.js";
export type {
  EncryptedSyncChange,
  SyncChange,
  SyncChangeBody,
  SyncJson,
  SyncMutation,
  SyncObjectType,
  SyncOperation,
} from "./sync/protocol.js";
export { SyncChangeLog, resolveSyncObject, verifySyncChanges } from "./sync/change-log.js";
export type { SyncAppliedObject, SyncResolution, SyncVerification } from "./sync/change-log.js";
export type {
  SyncTransactionFaultInjector,
  SyncTransactionFaultPoint,
  SyncTransactionOptions,
  SyncTransactionPhase,
} from "./sync/transaction.js";

export interface SyncApplyResult {
  objectType: "note" | "canvas" | "attachment";
  objectId: string;
  changeId: string;
  revision: number;
  applied: number;
  alreadyApplied: boolean;
}

function validateOptionalDeviceId(passphrase: string, deviceId: string | undefined): string {
  if (deviceId !== undefined && !DEVICE_ID.test(deviceId)) {
    throw new Error("Sync device ID must be a lowercase UUID.");
  }
  return passphrase;
}

function sameSyncValue(left: SyncJson, right: SyncJson): boolean {
  return canonicalSyncJson(left) === canonicalSyncJson(right);
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

/**
 * A document session whose successful note, canvas and attachment mutations
 * are mirrored into the immutable sync DAG. Reads are inherited unchanged.
 * Remote application deliberately calls the base storage methods so receiving
 * a change never manufactures a second local change.
 */
export class SyncedDocumentVault extends DocumentVault {
  readonly changeLog: SyncChangeLog;
  private readonly localTransaction: SyncLocalTransaction;
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
    try {
      localTransaction = new SyncLocalTransaction(syncVaultDir, passphrase, transactionOptions);
      this.changeLog = changeLog;
      this.localTransaction = localTransaction;
      withVaultLock(this.syncVaultDir, () => this.localTransaction.recover(this.transactionEffects()));
      // Unlock materializes/reconciles the ordinary document index once. A
      // later rejected local preflight can then remain byte-for-byte read-only.
      super.list();
    } catch (error) {
      localTransaction?.close();
      changeLog.close();
      super.lock();
      throw error;
    }
  }

  override lock(): void {
    if (!this.syncClosed) {
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

  private transactionEffects(): SyncTransactionEffects {
    return {
      writeStorage: (operations) => this.writeLocalStorage(operations),
      installEnvelopes: (changes) => this.changeLog.installPreparedLocalChanges(changes),
      writeCursor: (changes) => this.changeLog.markPreparedLocalChangesApplied(changes),
    };
  }

  private planLocalChanges(deviceId: string, operations: readonly SyncLocalStorageOperation[]): EncryptedSyncChange[] {
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
          sameSyncValue(operation.beforeValue, operation.targetValue)
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

  private runLocalTransaction(deviceId: string, operations: readonly SyncLocalStorageOperation[]): void {
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

  private assertExpectedDocumentState(
    operation: SyncLocalStorageOperation,
    currentRevision: number | null,
    currentValue: SyncJson,
  ): void {
    if (currentRevision !== operation.beforeStorageRevision || !sameSyncValue(currentValue, operation.beforeValue)) {
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

      const existing = super.listAttachments().some((item) => item.id === operation.objectId)
        ? super.getAttachment(operation.objectId)
        : undefined;
      const currentValue = existing ? asSyncJson(attachmentSnapshot(existing.data, existing.info)) : null;
      if (operation.operation === "delete") {
        if (!existing) continue;
        this.assertExpectedDocumentState(operation, null, currentValue);
        super.removeAttachment(operation.objectId);
        continue;
      }
      if (existing && sameSyncValue(currentValue, operation.targetValue)) continue;
      this.assertExpectedDocumentState(operation, null, currentValue);
      const snapshot = parseAttachmentSnapshot(operation.targetValue);
      const info = super.putAttachment(Buffer.from(snapshot.data, "base64"), snapshot.filename, snapshot.mime);
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
    if (data.length > MAX_SYNC_ATTACHMENT_BYTES) {
      throw new Error(
        `A synchronized attachment cannot exceed ${MAX_SYNC_ATTACHMENT_BYTES} bytes until blob transport is available.`,
      );
    }
    return withVaultLock(this.syncVaultDir, () => {
      const prepared = this.prepareAttachmentPut(data, filename, mime);
      const before = prepared.existed ? super.getAttachment(prepared.info.id) : undefined;
      const targetValue = prevalidateLocalCaptureSnapshot(
        attachmentSnapshot(prepared.data, prepared.info),
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
          ? prevalidateLocalCaptureSnapshot(attachmentSnapshot(before.data, before.info), "Attachment snapshot")
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
        attachmentSnapshot(attachment.data, attachment.info),
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
    throw new Error(`Live sync application is not implemented for ${objectType} objects.`);
  }

  applyResolved(objectType: "note" | "canvas" | "attachment", objectId: string): SyncApplyResult {
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
              change.mutation.revision === revision && (!cursor || this.isAncestor(byId, cursor.changeId, change.id)),
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
