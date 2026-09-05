const MIN_PASSPHRASE_LENGTH = 12;
const COMMON = new Set([
  "123456789012",
  "password1234",
  "password12345",
  "qwertyuiop12",
  "letmein12345",
]);

/** Applied to newly written encrypted material; decryption stays migration-compatible. */
export function assertStrongPassphrase(passphrase: string): void {
  if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(`Vault passphrases must contain at least ${MIN_PASSPHRASE_LENGTH} characters.`);
  }
  if (passphrase.length > 1024) {
    throw new Error("Vault passphrases must not exceed 1024 characters.");
  }
  const lowered = passphrase.toLocaleLowerCase();
  if (COMMON.has(lowered) || new Set(passphrase).size < 4 || /^(.+)\1+$/u.test(lowered)) {
    throw new Error("Choose a less predictable vault passphrase.");
  }
}
