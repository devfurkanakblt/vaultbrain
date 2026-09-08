import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const REQUIRED_TARGETS = Object.freeze([
  "darwin-aarch64-app",
  "linux-x86_64-deb",
  "windows-x86_64-msi",
  "windows-x86_64-nsis",
]);

const STABLE_SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u;
const SHA256_LINE = /^([a-f\d]{64}) {2}(.+)$/u;
const FIXED_REPOSITORY = "devfurkanakblt/vaultbrain";
const RELEASE_FEED = `https://github.com/${FIXED_REPOSITORY}/releases/latest/download/latest.json`;

function fail(message) {
  throw new Error(message);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function isSafeAssetName(name) {
  return (
    typeof name === "string" &&
    name.length > 0 &&
    name === path.basename(name) &&
    !name.includes("\\") &&
    !name.includes("/") &&
    name !== "." &&
    name !== ".."
  );
}

function assertSafeAssetName(name) {
  if (!isSafeAssetName(name)) fail(`Unsafe asset name: ${String(name)}`);
}

function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

export function decodeTauriMinisignText(encoded, label) {
  if (
    typeof encoded !== "string" ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(encoded.trim())
  ) {
    fail(`Invalid encoded ${label}`);
  }
  const decoded = Buffer.from(encoded.trim(), "base64");
  const text = decoded.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(decoded) || !text.startsWith("untrusted comment:")) {
    fail(`Invalid Minisign ${label}`);
  }
  return text;
}

export function verifyTauriSignatures({ directory, publicKey, command = "minisign" }) {
  const root = path.resolve(directory);
  const publicKeyText = decodeTauriMinisignText(publicKey, "public key");
  const signatures = listFiles(root).filter((file) => file.endsWith(".sig"));
  if (signatures.length === 0) fail("No Tauri signatures to verify");
  const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "vault-brain-minisign-"));
  try {
    const publicKeyFile = path.join(temporaryDirectory, "updater-public-key.txt");
    fs.writeFileSync(publicKeyFile, publicKeyText, "utf8");
    for (const signature of signatures) {
      const artifact = signature.slice(0, -".sig".length);
      const artifactPath = path.join(root, artifact);
      if (!fs.statSync(artifactPath, { throwIfNoEntry: false })?.isFile()) {
        fail(`Missing signed release artifact: ${artifact}`);
      }
      const signatureText = decodeTauriMinisignText(fs.readFileSync(path.join(root, signature), "utf8"), "signature");
      const signatureFile = path.join(
        temporaryDirectory,
        `${crypto.createHash("sha256").update(signature).digest("hex")}.minisig`,
      );
      fs.writeFileSync(signatureFile, signatureText, "utf8");
      childProcess.execFileSync(command, ["-Vm", artifactPath, "-x", signatureFile, "-p", publicKeyFile], {
        stdio: "inherit",
      });
    }
  } finally {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}

function listFiles(directory, prefix = "") {
  const entries = fs.readdirSync(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...listFiles(absolute, relative));
    } else if (entry.isFile()) {
      files.push(relative);
    } else {
      fail(`Release asset must be a regular file: ${relative}`);
    }
  }
  return files.sort();
}

function exactOne(files, matcher, target) {
  const matches = files.filter((file) => matcher.test(file));
  if (matches.length === 0) fail(`Missing release artifact for ${target}`);
  if (matches.length > 1) fail(`Duplicate release artifacts for ${target}`);
  return matches[0];
}

function readSignature(directory, asset, target) {
  const signature = `${asset}.sig`;
  if (!fs.existsSync(path.join(directory, signature))) fail(`Missing release signature for ${target} (${asset})`);
  const content = fs.readFileSync(path.join(directory, signature), "utf8").trim();
  if (content.length === 0) fail(`Empty release signature for ${target} (${asset})`);
  return { asset, signature, content };
}

function assertRequiredFile(directory, name) {
  if (!fs.statSync(path.join(directory, name), { throwIfNoEntry: false })?.isFile()) {
    fail(`Missing required release asset: ${name}`);
  }
  return name;
}

function writeChecksums(directory, files) {
  const lines = files
    .filter((file) => file !== "checksums.sha256")
    .map((file) => `${sha256(path.join(directory, file))}  ${file}`)
    .sort();
  fs.writeFileSync(path.join(directory, "checksums.sha256"), `${lines.join("\n")}\n`, "utf8");
  return "checksums.sha256";
}

export function writeReleaseChecksums(directory) {
  const root = path.resolve(directory);
  const files = listFiles(root);
  for (const file of files) assertSafeAssetName(file);
  return writeChecksums(root, files);
}

export function validateReleaseVersions({ tag, packageVersion, cargoVersion, tauriVersion }) {
  for (const version of [packageVersion, cargoVersion, tauriVersion]) {
    if (typeof version !== "string" || !STABLE_SEMVER.test(version)) {
      fail("Invalid stable release version");
    }
  }
  if (tag !== `v${packageVersion}` || cargoVersion !== packageVersion || tauriVersion !== packageVersion) {
    fail("Release version sources do not match");
  }
  return { tag, version: packageVersion };
}

export function createReleaseOverlay({ publicKey }) {
  if (typeof publicKey !== "string" || publicKey.trim().length === 0) {
    fail("Missing Tauri updater public key");
  }
  return {
    bundle: { createUpdaterArtifacts: true },
    plugins: {
      updater: {
        pubkey: publicKey.trim(),
        endpoints: [RELEASE_FEED],
        windows: { installMode: "basicUi" },
      },
    },
  };
}

export function isOwnedDraftRelease({ createdReleaseId, observedRelease }) {
  return (
    Number.isSafeInteger(createdReleaseId) &&
    Number.isSafeInteger(observedRelease?.id) &&
    observedRelease.id === createdReleaseId &&
    observedRelease.draft === true
  );
}

export function inspectReleaseArtifacts(directory, { version, requireProvenance = true }) {
  if (!STABLE_SEMVER.test(version)) fail("Invalid stable release version");
  const root = path.resolve(directory);
  const allFiles = listFiles(root);
  for (const file of allFiles) assertSafeAssetName(file);

  const versionPattern = escapeRegExp(version);
  const msi = exactOne(allFiles, new RegExp(`^.+_${versionPattern}_x64_en-US\\.msi$`, "u"), "windows-x86_64-msi");
  const nsis = exactOne(allFiles, new RegExp(`^.+_${versionPattern}_x64-setup\\.exe$`, "u"), "windows-x86_64-nsis");
  const app = exactOne(allFiles, /^.+\.app\.tar\.gz$/u, "darwin-aarch64-app");
  const dmg = exactOne(allFiles, new RegExp(`^.+_${versionPattern}_aarch64\\.dmg$`, "u"), "macOS DMG");
  const deb = exactOne(allFiles, new RegExp(`^.+_${versionPattern}_amd64\\.deb$`, "u"), "linux-x86_64-deb");

  const updaterTargets = {
    "windows-x86_64-msi": readSignature(root, msi, "windows-x86_64-msi"),
    "windows-x86_64-nsis": readSignature(root, nsis, "windows-x86_64-nsis"),
    "darwin-aarch64-app": readSignature(root, app, "darwin-aarch64-app"),
    "linux-x86_64-deb": readSignature(root, deb, "linux-x86_64-deb"),
  };
  const packages = [msi, nsis, app, dmg, deb];
  const signatures = Object.values(updaterTargets).map(({ signature }) => signature);
  const sbom = assertRequiredFile(root, "sbom.spdx.json");
  const provenance = requireProvenance ? assertRequiredFile(root, "provenance.intoto.jsonl") : undefined;
  const allowedAssets = new Set([
    ...packages,
    ...signatures,
    sbom,
    ...(provenance ? [provenance] : []),
    "checksums.sha256",
    "latest.json",
  ]);
  for (const file of allFiles) {
    if (!allowedAssets.has(file)) fail(`Unexpected release asset: ${file}`);
  }
  const checksums = writeChecksums(root, [...packages, ...signatures, sbom]);

  return { packages, signatures, sbom, provenance, checksums, updaterTargets };
}

export function createLatestManifest({ repository, tag, version, publishedAt, artifacts }) {
  if (repository !== FIXED_REPOSITORY) fail("Release must use the fixed repository");
  if (!STABLE_SEMVER.test(version) || tag !== `v${version}`) fail("Invalid stable release version");
  if (!Number.isFinite(Date.parse(publishedAt))) fail("Invalid release publication time");
  const targets = artifacts?.updaterTargets;
  if (!targets || typeof targets !== "object") fail("Missing updater targets");
  const actualTargets = Object.keys(targets).sort();
  if (actualTargets.join(",") !== [...REQUIRED_TARGETS].sort().join(",")) fail("Incomplete updater target set");

  const platforms = {};
  for (const target of REQUIRED_TARGETS) {
    const artifact = targets[target];
    assertSafeAssetName(artifact?.asset);
    if (typeof artifact?.content !== "string" || artifact.content.trim().length === 0) {
      fail(`Missing release signature for ${target}`);
    }
    platforms[target] = {
      signature: artifact.content.trim(),
      url: `https://github.com/${repository}/releases/download/${encodeURIComponent(tag)}/${encodeURIComponent(artifact.asset)}`,
    };
  }
  return { version, notes: "", pub_date: new Date(publishedAt).toISOString(), platforms };
}

function parseChecksums(directory) {
  const checksumFile = path.join(directory, "checksums.sha256");
  if (!fs.existsSync(checksumFile)) fail("Missing downloaded checksums.sha256");
  const checksums = new Map();
  for (const line of fs.readFileSync(checksumFile, "utf8").trim().split(/\r?\n/u)) {
    const match = SHA256_LINE.exec(line);
    if (!match || !isSafeAssetName(match[2])) fail("Invalid checksum manifest");
    if (checksums.has(match[2])) fail("Duplicate checksum entry");
    checksums.set(match[2], match[1]);
  }
  return checksums;
}

export function verifyDownloadedAssets({ expectedDirectory, downloadedDirectory }) {
  const expected = path.resolve(expectedDirectory);
  const downloaded = path.resolve(downloadedDirectory);
  const expectedChecksumFile = path.join(expected, "checksums.sha256");
  const downloadedChecksumFile = path.join(downloaded, "checksums.sha256");
  if (
    !fs.existsSync(downloadedChecksumFile) ||
    !fs.readFileSync(expectedChecksumFile).equals(fs.readFileSync(downloadedChecksumFile))
  ) {
    fail("Checksum manifest changed after draft upload");
  }
  const checksums = parseChecksums(expected);
  const expectedFiles = listFiles(expected);
  const downloadedFiles = listFiles(downloaded);
  if (expectedFiles.join(",") !== downloadedFiles.join(","))
    fail("Downloaded release assets differ from the draft assets");
  const checksummedFiles = [...checksums.keys()].sort();
  const expectedAssetFiles = expectedFiles.filter((file) => file !== "checksums.sha256");
  if (checksummedFiles.join(",") !== expectedAssetFiles.join(",")) {
    fail("Checksum manifest does not cover every release asset");
  }

  for (const [name, expectedHash] of checksums) {
    const downloadedFile = path.join(downloaded, name);
    if (!fs.existsSync(downloadedFile) || sha256(downloadedFile) !== expectedHash) {
      fail(`Checksum mismatch for ${name}`);
    }
  }
  return { verified: checksums.size };
}
