import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { assertNotSymlink, writeFileAtomic } from "./fs-safe.js";
import {
  DEFAULT_SCRYPT_N,
  KEY_NAMES,
  KEYRING_VERSION,
  detectVaultFormat,
  forgetVaultKeys,
  keyringPath,
  readKeyring,
  unwrapKeyring,
  unwrapSlot,
  unwrapSlotKeySet,
  validateSlot,
  wrapKeySet,
  wrapKeySetSlot,
  writeKeyring,
  zeroKeySet,
  zeroRetiringKeys,
  type KeyringSlot,
  type KeyringFile,
  type KeySet,
  type RetiringKeys,
} from "./keyring.js";
import {
  appendKeyringAudit,
  appendKeyringAuditWithKey,
  newKeyringAuditKey,
} from "./keyring-audit.js";
import { MIN_PASSPHRASE_LENGTH } from "./keyring-passphrase.js";
import { verifyRecoveryKeySet } from "./keyring-recovery-verify.js";
import { withVaultLock } from "./vault-lock.js";

const RECOVERY_PREFIX = "vbr1";
const RECOVERY_LABEL = "recovery";
const RECOVERY_KIT_KIND = "vaultbrain-recovery-kit";

export interface RecoveryKit {
  version: 1;
  kind: typeof RECOVERY_KIT_KIND;
  createdAt: string;
  slot: KeyringSlot;
}

export interface RecoveryCreateReport {
  slotId: string;
  kitPath: string;
  recoveryCode: string;
}

export interface RecoveryRestoreReport {
  slotId: string;
  backupCreated: boolean;
  backupPath?: string;
  verifiedObjects: number;
}

export interface RecoveryRemoveReport {
  slotId: string;
  remainingSlots: number;
}

export interface RekeyRecoveryInput {
  kitPath: string;
  code: string;
}

export interface PreparedRecoveryRekey {
  kitPath: string;
  kitCreatedAt: string;
  slot: KeyringSlot;
}

function checksum(secret: Buffer): string {
  return crypto.createHash("sha256").update(secret).digest("hex").slice(0, 8);
}

export function generateRecoveryCode(): string {
  const secret = crypto.randomBytes(32);
  return `${RECOVERY_PREFIX}_${secret.toString("base64url")}_${checksum(secret)}`;
}

export function parseRecoveryCode(value: string): Buffer {
  const match = /^vbr1_([A-Za-z0-9_-]{43})_([a-f0-9]{8})$/u.exec(value);
  if (!match) throw new Error("The recovery code has an invalid format.");
  const secret = Buffer.from(match[1], "base64url");
  if (secret.length !== 32 || checksum(secret) !== match[2]) {
    secret.fill(0);
    throw new Error("The recovery code checksum does not match.");
  }
  return secret;
}

function sameKeySet(left: KeySet, right: KeySet): boolean {
  return KEY_NAMES.every(
    (name) => left[name].length === right[name].length && crypto.timingSafeEqual(left[name], right[name]),
  );
}

function sameSlot(left: KeyringSlot, right: KeyringSlot): boolean {
  const digest = (slot: KeyringSlot) => crypto.createHash("sha256").update(JSON.stringify(slot), "utf8").digest();
  return crypto.timingSafeEqual(digest(left), digest(right));
}

function assertOutsideVault(vaultDir: string, targetPath: string): void {
  const vault = path.resolve(vaultDir);
  const target = path.resolve(targetPath);
  const relative = path.relative(vault, target);
  if (relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative))) {
    throw new Error("The recovery kit must be stored outside the vault directory.");
  }
}

function readRecoveryKit(kitPath: string): RecoveryKit {
  assertNotSymlink(kitPath);
  const parsed = JSON.parse(fs.readFileSync(kitPath, "utf8")) as Partial<RecoveryKit>;
  if (parsed.version !== 1 || parsed.kind !== RECOVERY_KIT_KIND || typeof parsed.createdAt !== "string") {
    throw new Error("Invalid Vault Brain recovery kit.");
  }
  if (Number.isNaN(Date.parse(parsed.createdAt))) throw new Error("Invalid recovery kit timestamp.");
  const slot = validateSlot(parsed.slot);
  if (slot.label !== RECOVERY_LABEL) throw new Error("The recovery kit does not contain a recovery slot.");
  return { version: 1, kind: RECOVERY_KIT_KIND, createdAt: parsed.createdAt, slot };
}

/** Validate the optional recovery sidecar before a re-key mutates either file. */
export function prepareRecoveryForRekey(
  keyring: KeyringFile,
  expectedKeys: KeySet,
  input?: RekeyRecoveryInput,
): PreparedRecoveryRekey | null {
  const recoverySlots = keyring.slots.filter((slot) => slot.label === RECOVERY_LABEL);
  if (recoverySlots.length === 0) {
    if (input) throw new Error("This keyring has no recovery slot for the supplied recovery kit.");
    return null;
  }
  if (recoverySlots.length !== 1) throw new Error("This keyring has more than one managed recovery slot.");
  if (!input) throw new Error("A matching recovery kit and code are required before re-keying this vault.");
  const parsedSecret = parseRecoveryCode(input.code);
  parsedSecret.fill(0);
  const kit = readRecoveryKit(input.kitPath);
  if (!sameSlot(kit.slot, recoverySlots[0])) {
    throw new Error("The recovery kit does not match the recovery slot in this keyring.");
  }
  verifySlotCarries(kit.slot, input.code, expectedKeys);
  return { kitPath: path.resolve(input.kitPath), kitCreatedAt: kit.createdAt, slot: kit.slot };
}

/** Atomically advance the offline kit and return the exact slot the coordinator must install. */
export function rewriteRecoveryKitForRekey(
  prepared: PreparedRecoveryRekey,
  recoveryCode: string,
  keys: KeySet,
): KeyringSlot {
  const parsedSecret = parseRecoveryCode(recoveryCode);
  parsedSecret.fill(0);
  const slot = wrapKeySetSlot(keys, recoveryCode, {
    label: RECOVERY_LABEL,
    id: prepared.slot.id,
    createdAt: prepared.slot.createdAt,
    N: prepared.slot.kdf.N,
  });
  verifySlotCarries(slot, recoveryCode, keys);
  const kit: RecoveryKit = {
    version: 1,
    kind: RECOVERY_KIT_KIND,
    createdAt: prepared.kitCreatedAt,
    slot,
  };
  assertNotSymlink(prepared.kitPath);
  writeFileAtomic(prepared.kitPath, `${JSON.stringify(kit, null, 2)}\n`, { mode: 0o600 });
  return slot;
}

function verifySlotCarries(slot: KeyringSlot, secret: string, expected: KeySet): void {
  const opened = unwrapSlot(slot, secret);
  try {
    if (!sameKeySet(opened, expected)) throw new Error("The recovery slot carries a different vault keyset.");
  } finally {
    zeroKeySet(opened);
  }
}

export function createRecoveryKit(
  vaultDir: string,
  passphrase: string,
  outputPath: string,
  options: { recoveryCode?: string } = {},
): RecoveryCreateReport {
  if (!passphrase) throw new Error("A non-empty vault passphrase is required.");
  assertOutsideVault(vaultDir, outputPath);
  if (fs.existsSync(outputPath)) throw new Error("Refusing to overwrite an existing recovery kit.");

  return withVaultLock(vaultDir, () => {
    if (detectVaultFormat(vaultDir) !== "keyring") {
      throw new Error("This vault is not in the keyring format yet. Run 'vbrain migrate' first.");
    }
    const file = readKeyring(vaultDir);
    if (!file) throw new Error("This vault has no keyring.");
    if (file.slots.some((slot) => slot.label === RECOVERY_LABEL)) {
      throw new Error("This vault already has a recovery slot.");
    }
    if (file.slots.length >= 16) throw new Error("This vault keyring already has the maximum number of slots.");

    const keys = unwrapKeyring(file, passphrase);
    const recoveryCode = options.recoveryCode ?? generateRecoveryCode();
    const parsedSecret = parseRecoveryCode(recoveryCode);
    parsedSecret.fill(0);
    const auditOperation = newKeyringAuditKey("recovery-create");
    let auditStarted = false;
    try {
      appendKeyringAudit(vaultDir, passphrase, auditOperation, "pending");
      auditStarted = true;
      const slot = wrapKeySetSlot(keys, recoveryCode, { label: RECOVERY_LABEL });
      verifySlotCarries(slot, recoveryCode, keys);
      const kit: RecoveryKit = {
        version: 1,
        kind: RECOVERY_KIT_KIND,
        createdAt: new Date().toISOString(),
        slot,
      };
      writeFileAtomic(outputPath, `${JSON.stringify(kit, null, 2)}\n`, { mode: 0o600 });
      writeKeyring(vaultDir, { version: KEYRING_VERSION, slots: [...file.slots, slot] });
      forgetVaultKeys(vaultDir);
      appendKeyringAudit(vaultDir, passphrase, auditOperation, "allowed");
      return { slotId: slot.id, kitPath: path.resolve(outputPath), recoveryCode };
    } catch (error) {
      if (auditStarted) appendKeyringAuditWithKey(vaultDir, keys.audit, auditOperation, "denied");
      throw error;
    } finally {
      zeroKeySet(keys);
    }
  });
}

function backupKeyring(vaultDir: string): string | undefined {
  const source = keyringPath(vaultDir);
  if (!fs.existsSync(source)) return undefined;
  assertNotSymlink(source);
  const stamp = new Date().toISOString().replace(/[:.]/gu, "-");
  const backup = `${source}.before-recovery-${stamp}.bak`;
  writeFileAtomic(backup, fs.readFileSync(source), { mode: 0o600 });
  return backup;
}

export function restoreVaultKeyring(
  vaultDir: string,
  kitPath: string,
  recoveryCode: string,
  newPassphrase: string,
): RecoveryRestoreReport {
  if (newPassphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(`The new passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters.`);
  }
  const parsedSecret = parseRecoveryCode(recoveryCode);
  parsedSecret.fill(0);
  const kit = readRecoveryKit(kitPath);
  let keys: KeySet;
  // Carried through unchanged into the freshly wrapped primary slot below:
  // a recovery kit can itself be restored while a re-key is still mid-flight
  // (the recovery slot the kit mirrors is never touched by staging), and
  // dropping either one here would silently discard the retiring keys of
  // that in-progress re-key or the legacy identity key that recomputes older
  // sync-change ids — the same bug `changeVaultPassphrase` already fixed.
  let retiring: RetiringKeys | null;
  let legacyChangeIdentity: Buffer | null;
  try {
    const unwrapped = unwrapSlotKeySet(kit.slot, recoveryCode);
    keys = unwrapped.keys;
    retiring = unwrapped.retiring;
    legacyChangeIdentity = unwrapped.legacyChangeIdentity;
  } catch {
    throw new Error("The recovery code could not authenticate this recovery kit.");
  }

  try {
    let verifiedObjects: number;
    try {
      verifiedObjects = verifyRecoveryKeySet(vaultDir, keys);
    } catch {
      throw new Error("This recovery kit does not authenticate the selected vault.");
    }
    return withVaultLock(vaultDir, () => {
      const auditOperation = newKeyringAuditKey("recovery-restore");
      appendKeyringAuditWithKey(vaultDir, keys.audit, auditOperation, "pending");
      try {
        const primary = wrapKeySet(keys, newPassphrase, DEFAULT_SCRYPT_N, retiring, legacyChangeIdentity);
        verifySlotCarries(primary, newPassphrase, keys);
        const backupPath = backupKeyring(vaultDir);
        writeKeyring(vaultDir, { version: KEYRING_VERSION, slots: [primary, kit.slot] });
        forgetVaultKeys(vaultDir);
        const written = readKeyring(vaultDir);
        if (!written) throw new Error("The restored keyring could not be read back.");
        const verified = unwrapKeyring(written, newPassphrase);
        try {
          if (!sameKeySet(verified, keys)) throw new Error("The restored keyring carries the wrong keyset.");
        } finally {
          zeroKeySet(verified);
        }
        appendKeyringAuditWithKey(vaultDir, keys.audit, auditOperation, "allowed");
        return {
          slotId: kit.slot.id,
          backupCreated: backupPath !== undefined,
          ...(backupPath ? { backupPath } : {}),
          verifiedObjects,
        };
      } catch (error) {
        appendKeyringAuditWithKey(vaultDir, keys.audit, auditOperation, "denied");
        throw error;
      }
    });
  } finally {
    zeroKeySet(keys);
    if (retiring) zeroRetiringKeys(retiring);
    legacyChangeIdentity?.fill(0);
  }
}

export function removeRecoverySlot(
  vaultDir: string,
  passphrase: string,
  slotId: string,
): RecoveryRemoveReport {
  return withVaultLock(vaultDir, () => {
    const file = readKeyring(vaultDir);
    if (!file) throw new Error("This vault has no keyring.");
    const target = file.slots.find((slot) => slot.id === slotId);
    if (!target || target.label !== RECOVERY_LABEL) throw new Error("Recovery slot not found.");
    const remaining = file.slots.filter((slot) => slot.id !== slotId);
    const expected = unwrapKeyring(file, passphrase);
    const auditOperation = newKeyringAuditKey("recovery-remove");
    let auditStarted = false;
    try {
      appendKeyringAudit(vaultDir, passphrase, auditOperation, "pending");
      auditStarted = true;
      const accessible = remaining.some((slot) => {
        try {
          const opened = unwrapSlot(slot, passphrase);
          try {
            return sameKeySet(opened, expected);
          } finally {
            zeroKeySet(opened);
          }
        } catch {
          return false;
        }
      });
      if (!accessible) throw new Error("Removing this slot would leave no primary slot this passphrase can open.");
      writeKeyring(vaultDir, { version: KEYRING_VERSION, slots: remaining });
      forgetVaultKeys(vaultDir);
      appendKeyringAudit(vaultDir, passphrase, auditOperation, "allowed");
      return { slotId, remainingSlots: remaining.length };
    } catch (error) {
      if (auditStarted) appendKeyringAuditWithKey(vaultDir, expected.audit, auditOperation, "denied");
      throw error;
    } finally {
      zeroKeySet(expected);
    }
  });
}
