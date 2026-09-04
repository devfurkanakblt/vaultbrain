import crypto from "node:crypto";
import { appendAudit, appendAuditWithKey, type AuditEntry } from "./audit.js";

export type KeyringAuditOperation =
  | "migrate"
  | "passphrase-change"
  | "rekey"
  | "recovery-create"
  | "recovery-remove"
  | "recovery-restore";

export type KeyringAuditOutcome = Extract<AuditEntry["outcome"], "pending" | "allowed" | "denied">;

export function newKeyringAuditKey(operation: KeyringAuditOperation): string {
  return `${operation}:${crypto.randomUUID()}`;
}

export function appendKeyringAudit(
  vaultDir: string,
  passphrase: string,
  key: string,
  outcome: KeyringAuditOutcome,
): void {
  appendAudit(vaultDir, { actor: "cli-keyring", file: "keyring", key, outcome }, passphrase);
}

export function appendKeyringAuditWithKey(
  vaultDir: string,
  auditKey: Buffer,
  key: string,
  outcome: KeyringAuditOutcome,
): void {
  appendAuditWithKey(vaultDir, { actor: "cli-keyring", file: "keyring", key, outcome }, auditKey);
}

