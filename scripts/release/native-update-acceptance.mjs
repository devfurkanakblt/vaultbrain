import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SUPPORTED_PLATFORMS = new Set(["linux", "macos", "windows"]);
const TARGETS = Object.freeze({
  "linux-deb": { platform: "linux", matcher: /\.deb$/u },
  "macos-dmg": { platform: "macos", matcher: /\.dmg$/u },
  "windows-msi": { platform: "windows", matcher: /\.msi$/u },
  "windows-nsis": { platform: "windows", matcher: /-setup\.exe$/u },
});
const STABLE_SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u;
const SHA256 = /^[a-f\d]{64}$/u;

function fail(message) {
  throw new Error(message);
}

function sha256File(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function compareVersions(left, right) {
  const a = left.split(".").map(BigInt);
  const b = right.split(".").map(BigInt);
  for (let index = 0; index < 3; index += 1) {
    if (a[index] < b[index]) return -1;
    if (a[index] > b[index]) return 1;
  }
  return 0;
}

function assertStableVersion(version, label) {
  if (typeof version !== "string" || !STABLE_SEMVER.test(version)) fail(`Invalid ${label} version`);
}

function regularFiles(root, relative = "") {
  const directory = path.join(root, relative);
  const entries = fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
  const files = [];
  for (const entry of entries) {
    const child = relative ? path.join(relative, entry.name) : entry.name;
    if (entry.isSymbolicLink()) fail(`Symbolic links are not accepted in native update evidence: ${child}`);
    if (entry.isDirectory()) files.push(...regularFiles(root, child));
    else if (entry.isFile()) files.push(child);
    else fail(`Unsupported vault entry in native update evidence: ${child}`);
  }
  return files;
}

export function captureVaultEvidence(vaultDirectory) {
  const root = path.resolve(vaultDirectory);
  if (!fs.statSync(root, { throwIfNoEntry: false })?.isDirectory()) fail("Vault directory is unavailable");
  const keyring = path.join(root, "keyring.json");
  if (!fs.statSync(keyring, { throwIfNoEntry: false })?.isFile()) fail("Vault identity keyring.json is unavailable");

  const files = regularFiles(root);
  const tree = crypto.createHash("sha256");
  for (const relative of files) {
    const normalized = relative.split(path.sep).join("/");
    const data = fs.readFileSync(path.join(root, relative));
    tree.update(Buffer.from(`${Buffer.byteLength(normalized)}:${normalized}:${data.length}:`, "utf8"));
    tree.update(data);
  }
  return {
    vaultIdentity: sha256File(keyring),
    vaultTreeSha256: tree.digest("hex"),
    vaultFiles: files.length,
  };
}

function defaultTarget(platform) {
  if (platform === "windows") return "windows-msi";
  if (platform === "macos") return "macos-dmg";
  if (platform === "linux") return "linux-deb";
  fail("Unsupported native update platform");
}

function findNativePackage(bundleDirectory, target, version) {
  const root = path.resolve(bundleDirectory);
  if (!fs.statSync(root, { throwIfNoEntry: false })?.isDirectory()) fail("Native bundle directory is unavailable");
  const contract = TARGETS[target];
  if (!contract) fail("Unsupported native update target");
  const matches = regularFiles(root).filter((file) => contract.matcher.test(file));
  if (matches.length !== 1) fail(`Expected exactly one ${target} package, found ${matches.length}`);
  const packageName = path.basename(matches[0]);
  if (!packageName.includes(version)) {
    fail(`Native package filename does not carry requested version ${version}`);
  }
  return path.join(root, matches[0]);
}

function captureInstallEvidence({ platform, version, appIdentifier, packageFile, vaultDirectory }) {
  return {
    platform,
    version,
    appIdentifier,
    packageSha256: sha256File(packageFile),
    ...captureVaultEvidence(vaultDirectory),
  };
}

export function verifyNativeUpdateTransition(before, after) {
  if (!SUPPORTED_PLATFORMS.has(before?.platform) || before.platform !== after?.platform) {
    fail("Native update platform changed across the transition");
  }
  assertStableVersion(before.version, "previous");
  assertStableVersion(after.version, "next");
  if (compareVersions(before.version, after.version) >= 0) fail("Native update must install a newer version");
  if (typeof before.appIdentifier !== "string" || before.appIdentifier.length === 0)
    fail("App identity is unavailable");
  if (before.appIdentifier !== after.appIdentifier) fail("App identity changed across the native update");
  if (!SHA256.test(before.packageSha256) || !SHA256.test(after.packageSha256)) fail("Package evidence is invalid");
  if (before.packageSha256 === after.packageSha256) fail("Native package bytes did not change across versions");
  if (!SHA256.test(before.vaultIdentity) || before.vaultIdentity !== after.vaultIdentity) {
    fail("Vault identity changed across the native update");
  }
  if (!SHA256.test(before.vaultTreeSha256) || before.vaultTreeSha256 !== after.vaultTreeSha256) {
    fail("Vault contents changed across the native update");
  }
  if (!Number.isSafeInteger(before.vaultFiles) || before.vaultFiles < 1 || before.vaultFiles !== after.vaultFiles) {
    fail("Vault file inventory changed across the native update");
  }
  return { before, after, filesVerified: after.vaultFiles };
}

export function runSyntheticNativeUpdateAcceptance({
  platform,
  bundleDirectory,
  vaultDirectory,
  previousVersion,
  nextVersion,
  appIdentifier,
  target = defaultTarget(platform),
}) {
  if (!SUPPORTED_PLATFORMS.has(platform)) fail("Unsupported native update platform");
  if (TARGETS[target]?.platform !== platform) fail("Native update target does not match its platform");
  assertStableVersion(previousVersion, "previous");
  assertStableVersion(nextVersion, "next");
  if (compareVersions(previousVersion, nextVersion) >= 0) fail("Native update must install a newer version");
  if (typeof appIdentifier !== "string" || appIdentifier.trim().length === 0) fail("App identity is unavailable");

  const nextPackage = findNativePackage(bundleDirectory, target, nextVersion);
  const staging = fs.mkdtempSync(path.join(os.tmpdir(), "vault-brain-native-update-"));
  const installedPackage = path.join(staging, path.basename(nextPackage));
  try {
    fs.writeFileSync(
      installedPackage,
      `synthetic installed package\n${platform}\n${previousVersion}\n${appIdentifier}\n`,
    );
    const before = captureInstallEvidence({
      platform,
      version: previousVersion,
      appIdentifier,
      packageFile: installedPackage,
      vaultDirectory,
    });
    fs.copyFileSync(nextPackage, installedPackage);
    const after = captureInstallEvidence({
      platform,
      version: nextVersion,
      appIdentifier,
      packageFile: installedPackage,
      vaultDirectory,
    });
    return verifyNativeUpdateTransition(before, after);
  } finally {
    fs.rmSync(staging, { recursive: true, force: true });
  }
}

function option(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  const packageJson = JSON.parse(fs.readFileSync(path.join(process.cwd(), "package.json"), "utf8"));
  const tauriConfig = JSON.parse(fs.readFileSync(path.join(process.cwd(), "src-tauri", "tauri.conf.json"), "utf8"));
  if (packageJson.version !== tauriConfig.version) fail("Package and Tauri versions do not match");
  const nextVersion = option("--next-version") ?? packageJson.version;
  const [major, minor, patch] = nextVersion.split(".").map(Number);
  const inferredPrevious =
    patch > 0
      ? `${major}.${minor}.${patch - 1}`
      : minor > 0
        ? `${major}.${minor - 1}.0`
        : `${Math.max(0, major - 1)}.0.0`;
  const result = runSyntheticNativeUpdateAcceptance({
    platform: option("--platform"),
    target: option("--target"),
    bundleDirectory: option("--bundle-dir"),
    vaultDirectory: option("--vault-dir"),
    previousVersion: option("--previous-version") ?? inferredPrevious,
    nextVersion,
    appIdentifier: option("--identifier") ?? tauriConfig.identifier,
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}
