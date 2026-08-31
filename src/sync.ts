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
import { SyncChangeLog } from "./sync/change-log.js";
import {
  DEVICE_ID,
  MAX_SYNC_ATTACHMENT_BYTES,
  type SyncChange,
  type SyncJson,
  type SyncOperation,
} from "./sync/protocol.js";
import {
  asSyncJson,
  assertSyncSnapshotSize,
  attachmentSnapshot,
  canvasSnapshot,
  noteSnapshot,
  parseAttachmentSnapshot,
  parseCanvasSnapshot,
  parseNoteSnapshot,
} from "./sync/snapshots.js";

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

export interface SyncApplyResult {
  objectType: "note" | "canvas" | "attachment";
  objectId: string;
  changeId: string;
  revision: number;
  applied: number;
  alreadyApplied: boolean;
}
/**
 * A document session whose successful note, canvas and attachment mutations
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

  private appendLocal(
    objectType: "note" | "canvas" | "attachment",
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
