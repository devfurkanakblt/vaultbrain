import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const SERVICE = "secondbrain-vault";

export interface KeychainBackend {
  readonly name: string;
  available(): boolean;
  store(account: string, secret: string): void;
  lookup(account: string): string | undefined;
  forget(account: string): boolean;
}

/** One vault directory, one credential. The path itself is never stored. */
export function accountFor(vaultDir: string): string {
  return crypto.createHash("sha256").update(path.resolve(vaultDir)).digest("hex").slice(0, 32);
}

function run(command: string, args: string[], input?: string): string {
  return execFileSync(command, args, {
    input,
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
    timeout: 20_000,
  });
}

function canRun(command: string, args: string[]): boolean {
  try {
    run(command, args);
    return true;
  } catch {
    return false;
  }
}

function credentialDir(): string {
  const base = process.env.LOCALAPPDATA
    ? path.join(process.env.LOCALAPPDATA, SERVICE)
    : path.join(os.homedir(), `.${SERVICE}`);
  return path.join(base, "credentials");
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
    const blob = run(
      "powershell",
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "$plain = [Console]::In.ReadToEnd(); " +
          "ConvertTo-SecureString -String $plain -AsPlainText -Force | ConvertFrom-SecureString",
      ],
      secret,
    ).trim();
    if (!/^[0-9a-fA-F]+$/u.test(blob)) throw new Error("DPAPI did not return a credential blob.");
    const dir = credentialDir();
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(dir, `${account}.dpapi`), blob, { mode: 0o600 });
  },
  lookup(account) {
    const file = path.join(credentialDir(), `${account}.dpapi`);
    if (!fs.existsSync(file)) return undefined;
    const blob = fs.readFileSync(file, "utf8").trim();
    try {
      const secret = run(
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
      );
      return secret.replace(/\r?\n$/u, "");
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

/** macOS Keychain. Note: `security` takes the secret as an argument. */
const darwinBackend: KeychainBackend = {
  name: "macos-keychain",
  available: () => process.platform === "darwin" && canRun("security", ["-h"]),
  store(account, secret) {
    run("security", ["add-generic-password", "-U", "-a", account, "-s", SERVICE, "-w", secret]);
  },
  lookup(account) {
    try {
      return run("security", ["find-generic-password", "-a", account, "-s", SERVICE, "-w"]).replace(/\n$/u, "");
    } catch {
      return undefined;
    }
  },
  forget(account) {
    try {
      run("security", ["delete-generic-password", "-a", account, "-s", SERVICE]);
      return true;
    } catch {
      return false;
    }
  },
};

/** Linux: libsecret via secret-tool, which reads the secret from stdin. */
const linuxBackend: KeychainBackend = {
  name: "libsecret",
  available: () => process.platform === "linux" && canRun("secret-tool", ["--version"]),
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
