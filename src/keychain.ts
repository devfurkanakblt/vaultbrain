import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { readTextFileLimited } from "./fs-safe.js";

const SERVICE = "secondbrain-vault";
const MACOS_SERVICE = "secondbrain-vault-v2";
const WINDOWS_DPAPI_PREFIX = "dpapi-v2:";

export interface KeychainBackend {
  readonly name: string;
  /** False when this build can only read and remove credentials written previously. */
  readonly writable?: boolean;
  available(): boolean;
  store(account: string, secret: string): void;
  lookup(account: string): string | undefined;
  forget(account: string): boolean;
}

/** One vault directory, one credential. The path itself is never stored. */
export function accountFor(vaultDir: string): string {
  return crypto.createHash("sha256").update(path.resolve(vaultDir)).digest("hex").slice(0, 32);
}

/**
 * Every backend call goes through here, so this is the one place that has to
 * keep a failing command from leaking its arguments. `execFileSync` builds
 * its failure message as "Command failed: <file> <args joined>". A future
 * backend must never turn its arguments into an accidental disclosure, so the
 * message is replaced with one that names only the command and its exit status.
 *
 * Exported only so tests can drive this sanitisation directly with a
 * guaranteed-to-fail command; no backend call site needs the export.
 */
export function run(command: string, args: string[], input?: string): string {
  try {
    return execFileSync(command, args, {
      input,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
      timeout: 20_000,
    });
  } catch (error) {
    const record = error && typeof error === "object" ? (error as Record<string, unknown>) : undefined;
    const status = record && "status" in record ? (record.status as number | null | undefined) : undefined;
    const code = record && "code" in record ? (record.code as string | number | null | undefined) : undefined;
    const signal = record && "signal" in record ? (record.signal as string | null | undefined) : undefined;
    const statusText = status === undefined || status === null ? "unknown" : String(status);
    const codeText = code === undefined || code === null ? "" : ` [${code}]`;
    // `execFileSync`'s own error carries `spawnargs`. Node's default inspection
    // of a thrown error prints `.cause` too, so attaching the raw error as
    // `cause` could leak sensitive arguments when anyone lets this propagate
    // to a default handler or logs `util.inspect(error)` — the
    // sanitised `.message` alone is not enough of a guarantee. Attach only a
    // scrubbed cause carrying the diagnostic fields that cannot themselves
    // contain arguments, so `preserve-caught-error` stays satisfied without
    // re-attaching argv.
    const scrubbedCause = { code, status, signal };
    const symptom = new Error(`Command failed: ${command}${codeText} (exit status ${statusText})`, {
      cause: scrubbedCause,
    });
    throw symptom;
  }
}

function canRun(command: string, args: string[]): boolean {
  try {
    run(command, args);
    return true;
  } catch {
    return false;
  }
}

/**
 * Some command-line tools use a non-zero status for their help/usage screen.
 * Availability only cares whether the executable started, not what that probe
 * chose to return after it started.
 */
export function commandAvailable(
  command: string,
  args: string[] = [],
  execute: typeof execFileSync = execFileSync,
): boolean {
  try {
    execute(command, args, {
      stdio: "ignore",
      windowsHide: true,
      timeout: 20_000,
    });
    return true;
  } catch (error) {
    const record = error && typeof error === "object" ? (error as Record<string, unknown>) : undefined;
    return typeof record?.status === "number" || typeof record?.signal === "string";
  }
}

function credentialDir(): string {
  const base = process.env.LOCALAPPDATA
    ? path.join(process.env.LOCALAPPDATA, SERVICE)
    : path.join(os.homedir(), `.${SERVICE}`);
  return path.join(base, "credentials");
}

function isCanonicalBase64(value: string): boolean {
  try {
    const decoded = Buffer.from(value, "base64");
    return decoded.length > 0 && decoded.toString("base64") === value;
  } catch {
    return false;
  }
}

/** Protect UTF-8 bytes with Windows DPAPI without putting the secret in argv. */
export function protectWindowsCredential(secret: string, execute: typeof run = run): string {
  const blob = execute(
    "powershell",
    [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      "Add-Type -AssemblyName System.Security;" +
        "$plain=[Console]::In.ReadToEnd();" +
        "$bytes=[Text.Encoding]::UTF8.GetBytes($plain);" +
        "$protected=[Security.Cryptography.ProtectedData]::Protect($bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser);" +
        "[Console]::Out.Write([Convert]::ToBase64String($protected))",
    ],
    secret,
  ).trim();
  if (!isCanonicalBase64(blob)) throw new Error("DPAPI did not return a credential blob.");
  return `${WINDOWS_DPAPI_PREFIX}${blob}`;
}

function unprotectWindowsCredential(value: string): string {
  const blob = value.slice(WINDOWS_DPAPI_PREFIX.length);
  if (!isCanonicalBase64(blob)) throw new Error("Invalid DPAPI credential blob.");
  return run(
    "powershell",
    [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      "Add-Type -AssemblyName System.Security;" +
        "$blob=[Console]::In.ReadToEnd().Trim();" +
        "$protected=[Convert]::FromBase64String($blob);" +
        "$bytes=[Security.Cryptography.ProtectedData]::Unprotect($protected,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser);" +
        "[Console]::Out.Write([Text.Encoding]::UTF8.GetString($bytes))",
    ],
    blob,
  );
}

/** Read blobs written before the direct ProtectedData format was introduced. */
function unprotectLegacyWindowsCredential(blob: string): string {
  if (!/^[0-9a-fA-F]+$/u.test(blob)) throw new Error("Invalid legacy DPAPI credential blob.");
  return run(
    "powershell",
    [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      "$blob = [Console]::In.ReadToEnd().Trim(); " +
        "$sec = ConvertTo-SecureString -String $blob; " +
        "[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))",
    ],
    blob,
  ).replace(/\r?\n$/u, "");
}

/**
 * Windows: DPAPI through PowerShell. The blob can only be decrypted by the
 * same Windows user on the same machine, so the file on disk is useless to
 * anyone else — but it is not protected against code running *as that user*,
 * which is the standard limitation of every OS credential store.
 *
 * The secret crosses to PowerShell on stdin, never as an argument, so it does
 * not appear in the process table.
 */
const windowsBackend: KeychainBackend = {
  name: "windows-dpapi",
  available: () =>
    process.platform === "win32" && canRun("powershell", ["-NoProfile", "-NonInteractive", "-Command", "exit 0"]),
  store(account, secret) {
    const blob = protectWindowsCredential(secret);
    const dir = credentialDir();
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(dir, `${account}.dpapi`), blob, { mode: 0o600 });
  },
  lookup(account) {
    const file = path.join(credentialDir(), `${account}.dpapi`);
    if (!fs.existsSync(file)) return undefined;
    const blob = readTextFileLimited(file, 1024 * 1024, "DPAPI credential").trim();
    try {
      return blob.startsWith(WINDOWS_DPAPI_PREFIX)
        ? unprotectWindowsCredential(blob)
        : unprotectLegacyWindowsCredential(blob);
    } catch {
      // Written by a different user or machine: treat as absent, not as an error.
      return undefined;
    }
  },
  forget(account) {
    const file = path.join(credentialDir(), `${account}.dpapi`);
    if (!fs.existsSync(file)) return false;
    fs.rmSync(file, { force: true });
    return true;
  },
};

/** Store through security's interactive stdin, never through its argv. */
export function storeMacosCredential(account: string, secret: string, execute: typeof run = run): void {
  if (!/^[0-9a-f]{32}$/u.test(account)) throw new Error("Invalid macOS Keychain account.");
  const encoded = Buffer.from(secret, "utf8").toString("base64");
  execute("security", ["-i"], `add-generic-password -U -a ${account} -s ${MACOS_SERVICE} -w ${encoded}\n`);
}

function decodeMacosCredential(encoded: string): string | undefined {
  const canonical = encoded.replace(/\r?\n$/u, "");
  try {
    const decoded = Buffer.from(canonical, "base64");
    if (decoded.toString("base64") !== canonical) return undefined;
    return decoded.toString("utf8");
  } catch {
    return undefined;
  }
}

/**
 * macOS stores new credentials under a versioned service as base64 text. The
 * fixed interactive command receives that text on stdin, keeping the user's
 * passphrase out of the child process argument vector. Lookup still falls back
 * to the original service so credentials written by older releases keep working.
 */
const darwinBackend: KeychainBackend = {
  name: "macos-keychain",
  available: () => process.platform === "darwin" && commandAvailable("security", ["-h"]),
  store(account, secret) {
    storeMacosCredential(account, secret);
  },
  lookup(account) {
    try {
      const decoded = decodeMacosCredential(
        run("security", ["find-generic-password", "-a", account, "-s", MACOS_SERVICE, "-w"]),
      );
      if (decoded !== undefined) return decoded;
    } catch {
      // Fall through to the service name used before stdin-safe writes.
    }
    try {
      return run("security", ["find-generic-password", "-a", account, "-s", SERVICE, "-w"]).replace(/\r?\n$/u, "");
    } catch {
      return undefined;
    }
  },
  forget(account) {
    let removed = false;
    try {
      run("security", ["delete-generic-password", "-a", account, "-s", MACOS_SERVICE]);
      removed = true;
    } catch {
      // A missing versioned item is expected for credentials from older releases.
    }
    try {
      run("security", ["delete-generic-password", "-a", account, "-s", SERVICE]);
      removed = true;
    } catch {
      // A missing legacy item is expected for credentials written by this release.
    }
    return removed;
  },
};

/** Linux: libsecret via secret-tool, which reads the secret from stdin. */
const linuxBackend: KeychainBackend = {
  name: "libsecret",
  available: () => process.platform === "linux" && commandAvailable("secret-tool"),
  store(account, secret) {
    run("secret-tool", ["store", "--label=Vault Brain", "service", SERVICE, "account", account], secret);
  },
  lookup(account) {
    try {
      return run("secret-tool", ["lookup", "service", SERVICE, "account", account]).replace(/\n$/u, "");
    } catch {
      return undefined;
    }
  },
  forget(account) {
    try {
      run("secret-tool", ["clear", "service", SERVICE, "account", account]);
      return true;
    } catch {
      return false;
    }
  },
};

const unavailableBackend: KeychainBackend = {
  name: "none",
  writable: false,
  available: () => false,
  store() {
    throw new Error("No OS credential store is available on this system.");
  },
  lookup: () => undefined,
  forget: () => false,
};

let override: KeychainBackend | undefined;

/** Test seam: swap in a fake store instead of touching the real keychain. */
export function setKeychainBackend(backend: KeychainBackend | undefined): void {
  override = backend;
}

export function keychain(): KeychainBackend {
  if (override) return override;
  for (const backend of [windowsBackend, darwinBackend, linuxBackend]) {
    if (backend.available()) return backend;
  }
  return unavailableBackend;
}

export function rememberPassphrase(vaultDir: string, passphrase: string): string {
  const backend = keychain();
  backend.store(accountFor(vaultDir), passphrase);
  return backend.name;
}

export function recallPassphrase(vaultDir: string): string | undefined {
  const secret = keychain().lookup(accountFor(vaultDir));
  return secret ? secret : undefined;
}

export function forgetPassphrase(vaultDir: string): boolean {
  return keychain().forget(accountFor(vaultDir));
}

/**
 * Replaces this vault's remembered passphrase after it has changed. A vault
 * with nothing remembered is left alone: storing a credential the user never
 * asked to store is `vbrain unlock --remember`'s job, not a side effect of a
 * passphrase change. A store that refuses the write is reported rather than
 * thrown, because by the time this runs the vault has already changed and the
 * caller must not report failure for an operation that completed.
 *
 * The failure `error`, if any, is always a short fixed description — never the
 * raw error from the backend. `execFileSync`'s failure message embeds the full
 * command line, so forwarding one unchanged could put sensitive metadata in
 * logs or a terminal. When the update cannot complete, the
 * stale credential is forgotten instead of left behind, since a stale
 * credential makes every later command fail against the *old* passphrase with
 * no indication why; `cleared` reports whether that forget succeeded.
 */
export function updateRememberedPassphrase(
  vaultDir: string,
  passphrase: string,
): { updated: boolean; backend: string; cleared: boolean; error?: string } {
  const backend = keychain();
  const account = accountFor(vaultDir);
  try {
    if (!backend.lookup(account)) return { updated: false, backend: backend.name, cleared: false };
    backend.store(account, passphrase);
    return { updated: true, backend: backend.name, cleared: false };
  } catch {
    let cleared: boolean;
    try {
      cleared = backend.forget(account);
    } catch {
      cleared = false;
    }
    return {
      updated: false,
      backend: backend.name,
      cleared,
      error: "the credential store rejected the write",
    };
  }
}
