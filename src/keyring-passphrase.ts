import crypto from "node:crypto";
import {
  DEFAULT_SCRYPT_N,
  KEYRING_VERSION,
  KEY_NAMES,
  detectVaultFormat,
  forgetVaultKeys,
  readKeyring,
  unwrapKeyring,
  unwrapSlot,
  wrapKeySet,
  writeKeyring,
  zeroKeySet,
  type KeyringSlot,
  type KeySet,
} from "./keyring.js";
import { withVaultLock } from "./vault-lock.js";

/**
 * NIST SP 800-63B's floor for a user-chosen secret. It applies to the new
 * passphrase only: an existing vault whose passphrase is shorter still opens,
 * because refusing it would lock its owner out rather than protect them.
 */
export const MIN_PASSPHRASE_LENGTH = 12;

export interface PassphraseChangeReport {
  /** Slots re-wrapped under the new passphrase. */
  slotsRewritten: number;
  /** Slots the current passphrase could not open, carried across untouched. */
  slotsPreserved: number;
  /** The scrypt cost of the first slot that opened, before the change. */
  previousN: number;
  /** The cost every rewritten slot now carries. */
  newN: number;
}

function sameKeySet(a: KeySet, b: KeySet): boolean {
  return KEY_NAMES.every(
    (name) => a[name].length === b[name].length && crypto.timingSafeEqual(a[name], b[name]),
  );
}

/**
 * Re-wraps the vault keyset under a new passphrase. Nothing under
 * `documents/`, no attachment, no sync change and no audit entry is read or
 * rewritten: only the wrapping layer changes, so attachment identities, sync
 * change IDs and the audit chain all survive untouched. Because every slot is
 * written at `DEFAULT_SCRYPT_N` with a fresh salt, this is also how a vault
 * created at a lower cost raises its work factor.
 *
 * A slot the current passphrase cannot open — the recovery slot the format
 * reserves — is carried across byte for byte rather than discarded.
 */
export function changeVaultPassphrase(
  vaultDir: string,
  currentPassphrase: string,
  newPassphrase: string,
  options: { allowSamePassphrase?: boolean } = {},
): PassphraseChangeReport {
  if (!currentPassphrase) throw new Error("A non-empty vault passphrase is required.");
  if (newPassphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(`The new passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters.`);
  }
  if (newPassphrase === currentPassphrase && !options.allowSamePassphrase) {
    throw new Error(
      "The new passphrase is the same as the current one. Pass --allow-same-passphrase to re-wrap the keyring at the current cost without changing it.",
    );
  }

  return withVaultLock(vaultDir, () => {
    if (detectVaultFormat(vaultDir) !== "keyring") {
      throw new Error("This vault is not in the keyring format yet. Run 'vbrain migrate' first.");
    }
    const file = readKeyring(vaultDir);
    if (!file) throw new Error("This vault has no keyring to change.");

    let opened: KeySet | undefined;
    let previousN = 0;
    let slotsPreserved = 0;
    const slots: KeyringSlot[] = [];
    const newlyWrapped: KeyringSlot[] = [];

    try {
      for (const slot of file.slots) {
        let keys: KeySet;
        try {
          keys = unwrapSlot(slot, currentPassphrase);
        } catch {
          // Not this passphrase's slot. Preserving it is what keeps a recovery
          // slot alive across a passphrase change.
          slots.push(slot);
          slotsPreserved += 1;
          continue;
        }
        if (opened) zeroKeySet(keys);
        else {
          opened = keys;
          previousN = slot.kdf.N;
        }
        const wrapped = wrapKeySet(opened, newPassphrase);
        slots.push(wrapped);
        newlyWrapped.push(wrapped);
      }

      if (!opened) {
        throw new Error("Unable to unlock this vault: wrong passphrase, or the keyring is damaged.");
      }

      // Prove every freshly wrapped slot unwraps back to the same keyset
      // under the new passphrase before anything touches disk. A refusal
      // here must leave keyring.json byte-identical to before the call.
      for (const wrapped of newlyWrapped) {
        const check = unwrapSlot(wrapped, newPassphrase);
        try {
          if (!sameKeySet(check, opened)) {
            throw new Error(
              "The re-wrapped slot does not carry the vault's keyset; refusing to write the keyring.",
            );
          }
        } finally {
          zeroKeySet(check);
        }
      }

      writeKeyring(vaultDir, { version: KEYRING_VERSION, slots });
      forgetVaultKeys(vaultDir);

      // Prove the file actually on disk opens under the passphrase the user
      // was just given, and carries the same keyset, before reporting
      // success. This catches a bad write (truncation, corruption) that the
      // pre-write check above cannot, since that check never touches disk.
      const written = readKeyring(vaultDir);
      if (!written) throw new Error("The new keyring could not be read back.");
      const verified = unwrapKeyring(written, newPassphrase);
      try {
        if (!sameKeySet(verified, opened)) {
          throw new Error(
            "The keyring written to disk does not carry the vault's keyset; the vault may be corrupted.",
          );
        }
      } finally {
        zeroKeySet(verified);
      }

      const rewritten = slots.length - slotsPreserved;
      return { slotsRewritten: rewritten, slotsPreserved, previousN, newN: DEFAULT_SCRYPT_N };
    } finally {
      if (opened) zeroKeySet(opened);
    }
  });
}
