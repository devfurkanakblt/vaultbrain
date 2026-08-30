import path from "node:path";

const WINDOWS_DEVICE_NAME = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i;
const SAFE_VAULT_NAME = /^[\p{L}\p{N}][\p{L}\p{N} _.-]*$/u;
const SAFE_ENTRY_KEY = /^[\p{L}\p{N}_][\p{L}\p{N}_.:-]*$/u;

/**
 * Convert the user-facing category/file argument into a single safe filename.
 * Vault categories are deliberately flat for now. Folder support will be added
 * with a typed note path model instead of accepting arbitrary filesystem paths.
 */
export function normalizeVaultName(input: string): string {
  let name = input.trim();
  if (name.endsWith(".kv.enc")) name = name.slice(0, -7);
  else if (name.endsWith(".kv")) name = name.slice(0, -3);

  if (
    !name ||
    name.length > 128 ||
    name === "." ||
    name === ".." ||
    path.isAbsolute(name) ||
    name.includes("/") ||
    name.includes("\\") ||
    name.includes("\0") ||
    /[\u0000-\u001f\u007f]/u.test(name) ||
    !SAFE_VAULT_NAME.test(name) ||
    WINDOWS_DEVICE_NAME.test(name)
  ) {
    throw new Error(
      "Invalid vault category. Use a single filename made of letters, numbers, spaces, '.', '_' or '-'."
    );
  }
  return name;
}

export function normalizeEntryKey(input: string): string {
  const key = input.trim();
  if (!key || key.length > 160 || !SAFE_ENTRY_KEY.test(key)) {
    throw new Error(
      "Invalid key. Use up to 160 letters, numbers, '_', '.', ':' or '-', starting with a letter, number or '_'."
    );
  }
  return key;
}

export function normalizeDescription(input: string): string {
  const desc = input.trim();
  if (desc.length > 240 || /[\r\n\u0000]/u.test(desc)) {
    throw new Error("Description must be a single line of at most 240 characters.");
  }
  return desc;
}

export function assertValueSize(value: string): void {
  const size = Buffer.byteLength(value, "utf8");
  if (size > 10 * 1024 * 1024) {
    throw new Error("A single value cannot exceed 10 MiB.");
  }
}

/** Defense in depth for every path assembled below a selected vault root. */
export function resolveInside(rootDir: string, filename: string): string {
  const root = path.resolve(rootDir);
  const candidate = path.resolve(root, filename);
  const relative = path.relative(root, candidate);
  if (relative.startsWith(`..${path.sep}`) || relative === ".." || path.isAbsolute(relative)) {
    throw new Error("Refusing to access a path outside the vault.");
  }
  return candidate;
}
