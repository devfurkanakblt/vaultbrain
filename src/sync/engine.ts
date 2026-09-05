import type { SyncAppliedObject } from "./change-log.js";
import { SyncApplyReceiptStore, type SyncApplyLiveIdentity, type SyncApplyReceipt } from "./transaction.js";
import type { SyncChange, SyncObjectType } from "./protocol.js";

type LiveObjectType = SyncObjectType;

function sameObject(change: SyncChange, objectType: LiveObjectType, objectId: string): boolean {
  return change.mutation.objectType === objectType && change.mutation.objectId === objectId;
}

function ancestry(changes: Map<string, SyncChange>, start: string): Set<string> {
  const included = new Set<string>();
  const visiting = new Set<string>();
  const visit = (id: string): void => {
    if (included.has(id)) return;
    if (visiting.has(id)) throw new Error("Sync change graph contains a cycle.");
    const change = changes.get(id);
    if (!change) throw new Error(`Missing sync parent ${id}.`);
    visiting.add(id);
    for (const parent of [...change.parents].sort()) visit(parent);
    visiting.delete(id);
    included.add(id);
  };
  visit(start);
  return included;
}

/**
 * Return the required same-object ancestry in a stable storage order. The
 * applied cursor's ancestry is already materialized, but a different merged
 * branch is not discarded merely because it does not descend from that cursor.
 */
export function planSyncApplication(
  changes: readonly SyncChange[],
  objectType: LiveObjectType,
  objectId: string,
  winner: SyncChange,
  applied?: SyncAppliedObject,
): SyncChange[] {
  const byId = new Map(changes.map((change) => [change.id, change]));
  if (!sameObject(winner, objectType, objectId)) throw new Error("Resolved sync winner is for another object.");
  if (applied && !byId.has(applied.changeId)) {
    throw new Error(`Applied sync cursor refers to a missing change: ${applied.changeId}`);
  }
  if (applied && !sameObject(byId.get(applied.changeId)!, objectType, objectId)) {
    throw new Error("Applied sync cursor refers to a change for another object.");
  }

  const required = ancestry(byId, winner.id);
  const materialized = applied ? ancestry(byId, applied.changeId) : new Set<string>();
  return [...required]
    .map((id) => byId.get(id)!)
    .filter((change) => sameObject(change, objectType, objectId) && !materialized.has(change.id))
    .sort((left, right) => left.mutation.revision - right.mutation.revision || left.id.localeCompare(right.id));
}

export interface SyncApplyEffects {
  findChange(changeId: string): SyncChange | undefined;
  expectedLive(change: SyncChange): SyncApplyLiveIdentity;
  isMaterialized(change: SyncChange, receipt: SyncApplyReceipt): boolean;
  writeStorage(change: SyncChange): void;
  writeCursor(change: SyncChange): void;
}

/** Durable, one-change remote application driven by an encrypted receipt. */
export class SyncApplyEngine {
  constructor(private readonly receipts: SyncApplyReceiptStore) {}

  close(): void {
    this.receipts.close();
  }

  private changeFor(receipt: SyncApplyReceipt, effects: SyncApplyEffects): SyncChange {
    const change = effects.findChange(receipt.changeId);
    if (!change) throw new Error(`Sync apply receipt refers to a missing change: ${receipt.changeId}`);
    if (!sameObject(change, receipt.objectType, receipt.objectId) || change.mutation.operation !== receipt.operation) {
      throw new Error("Sync apply receipt does not match its target change.");
    }
    return change;
  }

  private rollForward(receipt: SyncApplyReceipt, effects: SyncApplyEffects): void {
    const change = this.changeFor(receipt, effects);
    let current = receipt;
    if (current.phase === "prepared") {
      if (!effects.isMaterialized(change, current)) {
        effects.writeStorage(change);
        this.receipts.fault("storage-written", "after-effect");
        if (!effects.isMaterialized(change, current)) {
          throw new Error("A remote sync mutation did not materialize its intended live state.");
        }
      }
      current = this.receipts.advance(current, "storage-written");
    }
    if (current.phase === "storage-written") {
      effects.writeCursor(change);
      this.receipts.fault("cursor-written", "after-effect");
      current = this.receipts.advance(current, "cursor-written");
    }
    if (current.phase === "cursor-written") this.receipts.clear();
  }

  apply(change: SyncChange, effects: SyncApplyEffects): void {
    const receipt = this.receipts.begin(change, effects.expectedLive(change));
    this.rollForward(receipt, effects);
  }

  recover(effects: SyncApplyEffects): boolean {
    const receipt = this.receipts.read();
    if (!receipt) return false;
    this.rollForward(receipt, effects);
    return true;
  }
}
