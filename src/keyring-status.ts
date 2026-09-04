import { DEFAULT_SCRYPT_N, detectVaultFormat, readKeyring, type VaultFormat } from "./keyring.js";

export type KeyringCostStatus = "below-default" | "default" | "above-default";

export interface KeyringStatusSlot {
  id: string;
  type: "passphrase";
  label: string;
  createdAt: string;
  recovery: boolean;
  kdf: {
    name: "scrypt";
    N: number;
    r: number;
    p: number;
    cost: KeyringCostStatus;
  };
}

export interface KeyringStatus {
  format: VaultFormat;
  version: number | null;
  recommendedScryptN: number;
  recoveryConfigured: boolean;
  slots: KeyringStatusSlot[];
}

export function readKeyringStatus(vaultDir: string): KeyringStatus {
  const format = detectVaultFormat(vaultDir);
  if (format !== "keyring") {
    return {
      format,
      version: null,
      recommendedScryptN: DEFAULT_SCRYPT_N,
      recoveryConfigured: false,
      slots: [],
    };
  }

  const keyring = readKeyring(vaultDir);
  if (!keyring) throw new Error("This vault has no keyring.");
  const slots = keyring.slots.map((slot): KeyringStatusSlot => ({
    id: slot.id,
    type: slot.type,
    label: slot.label,
    createdAt: slot.createdAt,
    recovery: slot.label === "recovery",
    kdf: {
      name: slot.kdf.name,
      N: slot.kdf.N,
      r: slot.kdf.r,
      p: slot.kdf.p,
      cost:
        slot.kdf.N < DEFAULT_SCRYPT_N
          ? "below-default"
          : slot.kdf.N > DEFAULT_SCRYPT_N
            ? "above-default"
            : "default",
    },
  }));
  return {
    format,
    version: keyring.version,
    recommendedScryptN: DEFAULT_SCRYPT_N,
    recoveryConfigured: slots.some((slot) => slot.recovery),
    slots,
  };
}

