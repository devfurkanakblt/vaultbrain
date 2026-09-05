import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { AAD, VAULT_FORMAT_VERSION, backupEntryAad, backupManifestAad } from "./format-version.js";
import { assertNoSymlinkComponents, assertNotSymlink } from "./fs-safe.js";
import {
  KEYRING_FILENAME,
  type KeySet,
  detectVaultFormat,
  keyringPath,
  parseKeyring,
  unwrapKeyring,
  zeroKeySet,
} from "./keyring.js";
import { withVaultLock } from "./vault-lock.js";

export const BACKUP_VERSION = 1;
export const BACKUP_KIND = "vaultbrain-backup";

/** AES-256-GCM: a 12-byte nonce ahead of the ciphertext, a 16-byte tag after. */
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const ENTRY_OVERHEAD = NONCE_BYTES + TAG_BYTES;

const MAX_HEADER_BYTES = 64 * 1024 * 1024;
const MAX_ENTRIES = 2_000_000;
const MAX_ENTRY_BYTES = 512 * 1024 * 1024;
const COPY_CHUNK_BYTES = 4 * 1024 * 1024;

/** Names that belong to a running session, not to the vault's contents. */
const EXCLUDED_NAMES = new Set([".sbrain.lock"]);
const EXCLUDED_PATTERN = /\.tmp$/u;

export interface BackupEntry {
  /** Vault-relative path, always with forward slashes. */
  path: string;
  /** Plaintext size in bytes. */
  size: number;
  /** SHA-256 of the plaintext bytes, hex. */
  sha256: string;
}

/**
 * The only part of an archive that is readable without the passphrase.
 *
 * It carries the keyring because a reader needs it before it can decrypt
 * anything else, and the keyring's own protection is its passphrase wrapping.
 * Everything that would describe the vault's contents — how many objects it
 * holds, how many revisions each one has, how large they are — is in the
 * sealed manifest instead. An archive is meant to be stored somewhere the
 * owner does not control, and a plaintext list of every object in a vault is
 * a description of that vault.
 */
export interface BackupPreamble {
  version: number;
  kind: string;
  /** The vault format the archive was taken from, for a later reader. */
  formatVersion: string;
  createdAt: string;
  /** The vault's `keyring.json`, verbatim. */
  keyring: string;
}

export interface BackupManifest {
  files: BackupEntry[];
}

export interface BackupReport {
  version: 1;
  vault: string;
  archive: string;
  createdAt: string;
  files: number;
  /** Plaintext bytes carried, excluding the keyring in the header. */
  bytes: number;
  /** Size of the archive on disk. */
  archiveBytes: number;
}

export interface BackupVerification {
  version: 1;
  archive: string;
  createdAt: string;
  formatVersion: string;
  files: number;
  bytes: number;
}

export interface RestoreReport extends BackupVerification {
  destination: string;
}

function backupKey(keys: KeySet): Buffer {
  return crypto.createHmac("sha256", keys.audit).update(AAD.backupKey, "utf8").digest();
}

function toPortablePath(value: string): string {
  return value.split(path.sep).join("/");
}

function isInside(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

/**
 * Every file in the vault except the ones that describe a running session.
 * `keyring.json` is left out too: it travels in the header.
 */
function collectFiles(vaultDir: string): BackupEntry[] {
  const entries: BackupEntry[] = [];
  const visit = (directory: string): void => {
    assertNoSymlinkComponents(vaultDir, directory);
    for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const absolute = path.join(directory, entry.name);
      const relative = toPortablePath(path.relative(vaultDir, absolute));
      const stat = fs.lstatSync(absolute);
      if (stat.isSymbolicLink()) {
        throw new Error(`Refusing to back up a symbolic link: ${relative}`);
      }
      if (stat.isDirectory()) {
        visit(absolute);
        continue;
      }
      if (!stat.isFile()) continue;
      if (relative === KEYRING_FILENAME) continue;
      if (EXCLUDED_NAMES.has(entry.name) || EXCLUDED_PATTERN.test(entry.name)) continue;
      if (stat.size > MAX_ENTRY_BYTES) {
        throw new Error(`A single vault file exceeds the backup entry limit: ${relative}`);
      }
      const hash = crypto.createHash("sha256");
      const handle = fs.openSync(absolute, "r");
      try {
        const buffer = Buffer.allocUnsafe(COPY_CHUNK_BYTES);
        for (;;) {
          const read = fs.readSync(handle, buffer, 0, buffer.length, null);
          if (read === 0) break;
          hash.update(buffer.subarray(0, read));
        }
      } finally {
        fs.closeSync(handle);
      }
      entries.push({ path: relative, size: stat.size, sha256: hash.digest("hex") });
    }
  };
  visit(vaultDir);
  if (entries.length > MAX_ENTRIES) throw new Error("This vault holds more files than a backup can carry.");
  return entries;
}

function seal(data: Buffer, key: Buffer, aad: string): Buffer {
  const nonce = crypto.randomBytes(NONCE_BYTES);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(aad, "utf8"));
  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
  return Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]);
}

function open(sealed: Buffer, key: Buffer, aad: string): Buffer {
  const nonce = sealed.subarray(0, NONCE_BYTES);
  const tag = sealed.subarray(sealed.length - TAG_BYTES);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(Buffer.from(aad, "utf8"));
  decipher.setAuthTag(tag);
  return Buffer.concat([
    decipher.update(sealed.subarray(NONCE_BYTES, sealed.length - TAG_BYTES)),
    decipher.final(),
  ]);
}

/** The manifest's AAD binds it to the exact preamble it was written under. */
function manifestAadFor(preambleLine: Buffer): string {
  return backupManifestAad(crypto.createHash("sha256").update(preambleLine).digest("hex"));
}

/**
 * Writes a self-contained encrypted copy of the vault.
 *
 * The archive is one file: a header line naming every entry with its plaintext
 * SHA-256, a MAC over the literal bytes of that line, and then each file sealed
 * under a key derived from the vault's own permanent audit key. The keyring
 * travels in the header, so the archive carries the key-derivation metadata a
 * restore needs and depends on nothing outside itself except the passphrase.
 *
 * What that gets you: the archive cannot be opened without the passphrase,
 * entries cannot be reordered or swapped between paths, and a truncated or
 * edited archive is refused rather than half-restored.
 */
export function createBackup(vaultDir: string, outputPath: string, passphrase: string): BackupReport {
  const vault = path.resolve(vaultDir);
  const output = path.resolve(outputPath);
  if (isInside(vault, output)) {
    throw new Error("A backup must be written outside the vault it protects.");
  }
  if (fs.existsSync(output)) {
    throw new Error(`Refusing to overwrite an existing file: ${output}`);
  }
  const format = detectVaultFormat(vault);
  if (format !== "keyring") {
    throw new Error(
      format === "empty"
        ? `There is no vault to back up at ${vault}.`
        : "This vault predates the keyring format. Run 'vbrain migrate' before backing it up."
    );
  }

  const createdAt = new Date().toISOString();
  // The lock is held across both passes, so the hashes in the manifest describe
  // the same bytes the second pass seals.
  const { count, bytes } = withVaultLock(vault, () => {
    const keyringText = fs.readFileSync(keyringPath(vault), "utf8");
    const keys = unwrapKeyring(parseKeyring(keyringText), passphrase);
    try {
      const key = backupKey(keys);
      const files = collectFiles(vault);
      const preamble: BackupPreamble = {
        version: BACKUP_VERSION,
        kind: BACKUP_KIND,
        formatVersion: VAULT_FORMAT_VERSION,
        createdAt,
        keyring: keyringText,
      };
      const preambleLine = Buffer.from(`${JSON.stringify(preamble)}\n`, "utf8");
      const sealedManifest = seal(
        Buffer.from(JSON.stringify({ files } satisfies BackupManifest), "utf8"),
        key,
        manifestAadFor(preambleLine),
      );
      const manifestLength = Buffer.allocUnsafe(4);
      manifestLength.writeUInt32BE(sealedManifest.length);

      const temporary = `${output}.${process.pid}.${crypto.randomUUID()}.part`;
      const handle = fs.openSync(temporary, "wx", 0o600);
      let carried = 0;
      try {
        fs.writeSync(handle, preambleLine);
        fs.writeSync(handle, manifestLength);
        fs.writeSync(handle, sealedManifest);
        for (const [index, entry] of files.entries()) {
          const absolute = path.join(vault, ...entry.path.split("/"));
          const data = fs.readFileSync(absolute);
          if (data.byteLength !== entry.size) {
            throw new Error(`A vault file changed while the backup was running: ${entry.path}`);
          }
          fs.writeSync(handle, seal(data, key, backupEntryAad(index, entry.path)));
          data.fill(0);
          carried += entry.size;
        }
        fs.fsyncSync(handle);
        fs.closeSync(handle);
        fs.renameSync(temporary, output);
      } catch (error) {
        try {
          fs.closeSync(handle);
        } catch {
          // Already closed on the success path.
        }
        if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
        throw error;
      }
      key.fill(0);
      return { count: files.length, bytes: carried };
    } finally {
      zeroKeySet(keys);
    }
  });

  // A backup nobody has opened is a belief, not a backup. The artifact is read
  // back through exactly the code a restore uses before this call returns.
  verifyBackup(output, passphrase);

  return {
    version: 1,
    vault,
    archive: output,
    createdAt,
    files: count,
    bytes,
    archiveBytes: fs.statSync(output).size,
  };
}

interface OpenedArchive {
  preamble: BackupPreamble;
  files: BackupEntry[];
  key: Buffer;
  keys: KeySet;
  dataOffset: number;
}

function readLine(handle: number, start: number, limit: number, label: string): { text: string; end: number } {
  const chunk = Buffer.allocUnsafe(64 * 1024);
  const parts: Buffer[] = [];
  let offset = start;
  for (;;) {
    const read = fs.readSync(handle, chunk, 0, chunk.length, offset);
    if (read === 0) throw new Error(`${label} is truncated: this file is not a complete Vault Brain backup.`);
    const newline = chunk.subarray(0, read).indexOf(0x0a);
    if (newline >= 0) {
      parts.push(Buffer.from(chunk.subarray(0, newline)));
      return { text: Buffer.concat(parts).toString("utf8"), end: offset + newline + 1 };
    }
    parts.push(Buffer.from(chunk.subarray(0, read)));
    offset += read;
    if (offset - start > limit) throw new Error(`${label} exceeds the size this build will read.`);
  }
}

function parsePreamble(text: string): BackupPreamble {
  const parsed = JSON.parse(text) as BackupPreamble;
  if (parsed?.kind !== BACKUP_KIND) throw new Error("This file is not a Vault Brain backup.");
  if (parsed.version !== BACKUP_VERSION) {
    throw new Error(
      `This backup uses version ${String(parsed.version)}; this build understands ${BACKUP_VERSION}.`
    );
  }
  if (typeof parsed.keyring !== "string" || typeof parsed.createdAt !== "string") {
    throw new Error("This backup header is missing the fields a restore needs.");
  }
  return parsed;
}

/**
 * The manifest is authenticated by the time this runs, so these checks are not
 * about an attacker: they stop a path this build would refuse to write from
 * being restored by a build that reads it, and they keep `..` out of a
 * destination directory whatever produced the archive.
 */
function parseManifest(text: string): BackupEntry[] {
  const parsed = JSON.parse(text) as BackupManifest;
  if (!Array.isArray(parsed?.files) || parsed.files.length > MAX_ENTRIES) {
    throw new Error("This backup does not list its contents.");
  }
  const seen = new Set<string>();
  for (const entry of parsed.files) {
    if (
      typeof entry?.path !== "string" ||
      !Number.isSafeInteger(entry.size) ||
      entry.size < 0 ||
      entry.size > MAX_ENTRY_BYTES ||
      typeof entry.sha256 !== "string" ||
      !/^[a-f0-9]{64}$/u.test(entry.sha256)
    ) {
      throw new Error("This backup describes an entry this build cannot read.");
    }
    const segments = entry.path.split("/");
    if (
      !entry.path ||
      entry.path.startsWith("/") ||
      /^[a-z]:\//iu.test(entry.path) ||
      entry.path.includes("\\") ||
      segments.some((segment) => !segment || segment === "." || segment === "..")
    ) {
      throw new Error(`This backup names an entry outside the vault it restores: ${entry.path}`);
    }
    const key = entry.path.toLocaleLowerCase("en-US");
    if (seen.has(key)) throw new Error(`This backup names one entry twice: ${entry.path}`);
    seen.add(key);
  }
  return parsed.files;
}

function openArchive(handle: number, archiveSize: number, passphrase: string): OpenedArchive {
  const preambleLine = readLine(handle, 0, MAX_HEADER_BYTES, "The backup header");
  const preamble = parsePreamble(preambleLine.text);

  // The passphrase opens the keyring the archive carries. A backup this
  // passphrase cannot open is refused here, before anything is written.
  const keys = unwrapKeyring(parseKeyring(preamble.keyring), passphrase);
  const key = backupKey(keys);
  try {
    const lengthBytes = Buffer.allocUnsafe(4);
    if (fs.readSync(handle, lengthBytes, 0, 4, preambleLine.end) !== 4) {
      throw new Error("This backup is truncated: its file list is not present.");
    }
    const sealedLength = lengthBytes.readUInt32BE();
    const manifestStart = preambleLine.end + 4;
    if (sealedLength <= ENTRY_OVERHEAD || sealedLength > MAX_HEADER_BYTES) {
      throw new Error("This backup's file list is not a size this build will read.");
    }
    if (manifestStart + sealedLength > archiveSize) {
      throw new Error("This backup is truncated: its file list is not fully present.");
    }
    const sealedManifest = Buffer.allocUnsafe(sealedLength);
    if (fs.readSync(handle, sealedManifest, 0, sealedLength, manifestStart) !== sealedLength) {
      throw new Error("This backup is truncated: its file list is not fully present.");
    }

    // The preamble is authenticated here rather than by a separate MAC: it is
    // the manifest's additional data, so altering one byte of it makes the file
    // list refuse to open.
    const preambleBytes = Buffer.allocUnsafe(preambleLine.end);
    if (fs.readSync(handle, preambleBytes, 0, preambleBytes.length, 0) !== preambleBytes.length) {
      throw new Error("The backup header could not be read back for verification.");
    }
    let manifestText: string;
    try {
      manifestText = open(sealedManifest, key, manifestAadFor(preambleBytes)).toString("utf8");
    } catch {
      throw new Error(
        "This backup's file list does not open: the header has been altered, or the two halves come from different backups."
      );
    }
    return {
      preamble,
      files: parseManifest(manifestText),
      key,
      keys,
      dataOffset: manifestStart + sealedLength,
    };
  } catch (error) {
    key.fill(0);
    zeroKeySet(keys);
    throw error;
  }
}

function eachEntry(
  handle: number,
  opened: OpenedArchive,
  archiveSize: number,
  visit: (entry: BackupEntry, data: Buffer) => void
): number {
  let offset = opened.dataOffset;
  let bytes = 0;
  for (const [index, entry] of opened.files.entries()) {
    const sealedLength = entry.size + ENTRY_OVERHEAD;
    if (offset + sealedLength > archiveSize) {
      throw new Error(`This backup is truncated: ${entry.path} is not fully present.`);
    }
    const sealed = Buffer.allocUnsafe(sealedLength);
    const read = fs.readSync(handle, sealed, 0, sealedLength, offset);
    if (read !== sealedLength) throw new Error(`This backup is truncated: ${entry.path} is not fully present.`);
    let data: Buffer;
    try {
      data = open(sealed, opened.key, backupEntryAad(index, entry.path));
    } catch {
      throw new Error(`This backup entry does not open: ${entry.path}`);
    }
    const digest = crypto.createHash("sha256").update(data).digest("hex");
    if (digest !== entry.sha256) {
      throw new Error(`This backup entry does not match the contents it claims: ${entry.path}`);
    }
    visit(entry, data);
    data.fill(0);
    offset += sealedLength;
    bytes += entry.size;
  }
  if (offset !== archiveSize) {
    throw new Error("This backup carries bytes its file list does not describe.");
  }
  return bytes;
}

/**
 * Opens a backup and checks every byte of it: the seal over the file list, the
 * AEAD tag on each entry, and each entry's plaintext hash. Nothing is written.
 */
export function verifyBackup(archivePath: string, passphrase: string): BackupVerification {
  const archive = path.resolve(archivePath);
  assertNotSymlink(archive);
  const handle = fs.openSync(archive, "r");
  try {
    const archiveSize = fs.fstatSync(handle).size;
    const opened = openArchive(handle, archiveSize, passphrase);
    try {
      const bytes = eachEntry(handle, opened, archiveSize, () => {});
      return {
        version: 1,
        archive,
        createdAt: opened.preamble.createdAt,
        formatVersion: opened.preamble.formatVersion,
        files: opened.files.length,
        bytes,
      };
    } finally {
      opened.key.fill(0);
      zeroKeySet(opened.keys);
    }
  } finally {
    fs.closeSync(handle);
  }
}

/**
 * Restores a backup into a new vault directory.
 *
 * The whole archive is verified and written into a staging directory first,
 * and only a complete, verified vault is moved into place. A restore that
 * cannot open the archive leaves the destination exactly as it found it: the
 * failure mode this guards against is replacing a working vault with a broken
 * one, which is worse than not restoring at all.
 */
export function restoreBackup(archivePath: string, destinationDirectory: string, passphrase: string): RestoreReport {
  const archive = path.resolve(archivePath);
  const destination = path.resolve(destinationDirectory);
  if (isInside(destination, archive)) {
    throw new Error("The backup must live outside the directory it restores into.");
  }
  if (fs.existsSync(destination)) {
    const stat = fs.lstatSync(destination);
    if (stat.isSymbolicLink()) throw new Error("Refusing a symbolic link as the restore destination.");
    if (!stat.isDirectory()) throw new Error(`The restore destination is not a directory: ${destination}`);
    if (fs.readdirSync(destination).length > 0) {
      throw new Error(
        `The restore destination is not empty: ${destination}. ` +
          "Restore into a new directory rather than over a vault that may still be good."
      );
    }
  }

  assertNotSymlink(archive);
  const handle = fs.openSync(archive, "r");
  const staging = path.join(path.dirname(destination), `.${path.basename(destination)}.${crypto.randomUUID()}.restoring`);
  try {
    const archiveSize = fs.fstatSync(handle).size;
    const opened = openArchive(handle, archiveSize, passphrase);
    try {
      fs.mkdirSync(staging, { recursive: true, mode: 0o700 });
      const bytes = eachEntry(handle, opened, archiveSize, (entry, data) => {
        const target = path.join(staging, ...entry.path.split("/"));
        fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
        fs.writeFileSync(target, data, { mode: 0o600 });
      });
      fs.writeFileSync(path.join(staging, KEYRING_FILENAME), opened.preamble.keyring, { mode: 0o600 });

      if (fs.existsSync(destination)) fs.rmdirSync(destination);
      fs.renameSync(staging, destination);
      return {
        version: 1,
        archive,
        destination,
        createdAt: opened.preamble.createdAt,
        formatVersion: opened.preamble.formatVersion,
        files: opened.files.length,
        bytes,
      };
    } finally {
      opened.key.fill(0);
      zeroKeySet(opened.keys);
    }
  } catch (error) {
    if (fs.existsSync(staging)) fs.rmSync(staging, { recursive: true, force: true });
    throw error;
  } finally {
    fs.closeSync(handle);
  }
}
