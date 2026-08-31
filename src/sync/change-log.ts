import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  decryptDocument,
  encryptDocument,
  openDocumentKey,
  type DocumentKeySession,
  type DocumentPayload,
} from "../document-crypto.js";
import { assertNoSymlinkComponents, assertNotSymlink, writeFileAtomic } from "../fs-safe.js";
import { resolveInside } from "../safety.js";
import { withVaultLock } from "../vault-lock.js";
import {
  APPLIED_AAD,
  CHANGE_ID,
  MAX_ENVELOPE_BYTES,
  openSyncChange,
  sealSyncChange,
  validateEncryptedSyncChange,
  validateSyncChangeBody,
  type EncryptedSyncChange,
  type SyncChange,
  type SyncObjectType,
  type SyncOperation,
  type SyncMutation,
} from "./protocol.js";

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

function objectKey(change: SyncChange): string {
  return `${change.mutation.objectType}\0${change.mutation.objectId}`;
}

function syncObjectKey(objectType: SyncObjectType, objectId: string): string {
  return `${objectType}\0${objectId}`;
}

function validateChangeSet(changes: readonly SyncChange[]): SyncVerification {
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
      if (!previous || previous.deviceId !== change.deviceId || previous.sequence !== change.sequence - 1)
        throw new Error(`Broken device chain before ${change.id}.`);
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
      if (change.mutation.baseRevision !== expectedBase)
        throw new Error(`Sync change ${change.id} does not advance the causal object revision.`);
    }
  }
  const parentIds = new Set(changes.flatMap((change) => change.parents));
  const heads = [...byId.keys()].filter((id) => !parentIds.has(id)).sort();
  return { changes: changes.length, devices: new Set(changes.map((change) => change.deviceId)).size, heads };
}

/** Structural-graph compatibility alias; it does not authenticate encrypted envelopes. */
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
    const payload = JSON.parse(fs.readFileSync(this.appliedPath, "utf8")) as DocumentPayload;
    const parsed = JSON.parse(decryptDocument(payload, this.key(), APPLIED_AAD)) as SyncAppliedState;
    if (parsed?.version !== 1 || !parsed.objects || typeof parsed.objects !== "object")
      throw new Error("Unsupported or invalid sync application state.");
    for (const [key, entry] of Object.entries(parsed.objects)) {
      if (
        !key.includes("\0") ||
        !entry ||
        !CHANGE_ID.test(entry.changeId) ||
        !Number.isSafeInteger(entry.revision) ||
        entry.revision < 1 ||
        (entry.operation !== "put" && entry.operation !== "delete")
      )
        throw new Error("Unsupported or invalid sync application state.");
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
    return fs
      .readdirSync(this.changesDir)
      .filter((name) => name.endsWith(".change.enc"))
      .sort()
      .map((name) => {
        const id = name.slice(0, -".change.enc".length);
        if (!CHANGE_ID.test(id)) throw new Error(`Invalid sync change filename: ${name}`);
        const filePath = resolveInside(this.changesDir, name);
        assertNotSymlink(filePath);
        if (fs.statSync(filePath).size > MAX_ENVELOPE_BYTES) throw new Error(`Sync envelope is too large: ${id}`);
        const envelope = validateEncryptedSyncChange(JSON.parse(fs.readFileSync(filePath, "utf8")));
        if (envelope.id !== id) throw new Error(`Sync change filename does not match its envelope: ${id}`);
        return envelope;
      });
  }

  envelopes(): EncryptedSyncChange[] {
    const envelopes = this.readEnvelopes();
    validateChangeSet(envelopes.map((envelope) => openSyncChange(envelope, this.key())));
    return structuredClone(envelopes);
  }

  changes(): SyncChange[] {
    const changes = this.readEnvelopes().map((envelope) => openSyncChange(envelope, this.key()));
    validateChangeSet(changes);
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
      const body = validateSyncChangeBody({
        version: 1,
        deviceId,
        sequence: (previous?.sequence ?? 0) + 1,
        previousDeviceChange: previous?.id ?? null,
        parents,
        createdAt,
        mutation,
      });
      const envelope = sealSyncChange(body, this.key());
      const change = openSyncChange(envelope, this.key());
      validateChangeSet([...current, change]);
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
      const incomingEnvelope = new Map(envelopes.map((envelope) => [envelope.id, envelope]));
      const additionIds = new Set(additions.map((change) => change.id));
      const byId = new Map(additions.map((change) => [change.id, change]));
      const ordered: SyncChange[] = [];
      const visited = new Set<string>();
      const visit = (change: SyncChange): void => {
        if (visited.has(change.id)) return;
        for (const parent of change.parents) if (additionIds.has(parent)) visit(byId.get(parent)!);
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
