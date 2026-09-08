import assert from "node:assert/strict";
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  createReleaseOverlay,
  createLatestManifest,
  decodeTauriMinisignText,
  inspectReleaseArtifacts,
  isOwnedDraftRelease,
  validateReleaseVersions,
  verifyDownloadedAssets,
  writeReleaseChecksums,
} from "../scripts/release/release.mjs";

const REPOSITORY = "devfurkanakblt/vaultbrain";
const VERSION = "1.2.3";

function temporaryDirectory() {
  return mkdtempSync(path.join(os.tmpdir(), "vault-brain-release-test-"));
}

function writeArtifact(root, name, contents = name) {
  const file = path.join(root, name);
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, contents);
  return file;
}

function releaseFixture(root) {
  const names = [
    "VaultBrain_1.2.3_x64_en-US.msi",
    "VaultBrain_1.2.3_x64_en-US.msi.sig",
    "VaultBrain_1.2.3_x64-setup.exe",
    "VaultBrain_1.2.3_x64-setup.exe.sig",
    "Vault Brain.app.tar.gz",
    "Vault Brain.app.tar.gz.sig",
    "Vault Brain_1.2.3_aarch64.dmg",
    "vault-brain_1.2.3_amd64.deb",
    "vault-brain_1.2.3_amd64.deb.sig",
    "sbom.spdx.json",
    "provenance.intoto.jsonl",
  ];
  for (const name of names) writeArtifact(root, name);
  return names;
}

test("validateReleaseVersions accepts an exact stable tag and matching version sources", () => {
  assert.deepEqual(
    validateReleaseVersions({
      tag: "v1.2.3",
      packageVersion: VERSION,
      cargoVersion: VERSION,
      tauriVersion: VERSION,
    }),
    { tag: "v1.2.3", version: VERSION },
  );
});

test("validateReleaseVersions rejects prerelease, leading-zero, and mismatched release versions", () => {
  for (const input of [
    { tag: "v1.2.3-rc.1", packageVersion: VERSION, cargoVersion: VERSION, tauriVersion: VERSION },
    { tag: "v01.2.3", packageVersion: "01.2.3", cargoVersion: "01.2.3", tauriVersion: "01.2.3" },
    { tag: "v1.2.3", packageVersion: VERSION, cargoVersion: "1.2.4", tauriVersion: VERSION },
  ]) {
    assert.throws(() => validateReleaseVersions(input), /release version/iu);
  }
});

test("createReleaseOverlay embeds only a supplied public key and the fixed HTTPS updater feed", () => {
  assert.throws(() => createReleaseOverlay({ publicKey: "" }), /public key/iu);
  assert.deepEqual(createReleaseOverlay({ publicKey: "PUBLIC KEY" }), {
    bundle: { createUpdaterArtifacts: true },
    plugins: {
      updater: {
        pubkey: "PUBLIC KEY",
        endpoints: ["https://github.com/devfurkanakblt/vaultbrain/releases/latest/download/latest.json"],
        windows: { installMode: "basicUi" },
      },
    },
  });
});

test("decodeTauriMinisignText rejects corrupt encoded Tauri signing material", () => {
  const signedText =
    "untrusted comment: test signing material\nRWQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  assert.equal(decodeTauriMinisignText(Buffer.from(signedText).toString("base64"), "signature"), signedText);
  assert.throws(() => decodeTauriMinisignText("not base64!", "signature"), /encoded signature/iu);
  assert.throws(
    () => decodeTauriMinisignText(Buffer.from("not minisign text").toString("base64"), "signature"),
    /minisign/iu,
  );
});

test("isOwnedDraftRelease accepts only the current still-draft REST release", () => {
  assert.equal(isOwnedDraftRelease({ createdReleaseId: 73, observedRelease: { id: 73, draft: true } }), true);
  assert.equal(isOwnedDraftRelease({ createdReleaseId: 73, observedRelease: { id: 74, draft: true } }), false);
  assert.equal(isOwnedDraftRelease({ createdReleaseId: 73, observedRelease: { id: 73, draft: false } }), false);
  assert.equal(isOwnedDraftRelease({ createdReleaseId: 73, observedRelease: { id: 73, isDraft: true } }), false);
  assert.equal(isOwnedDraftRelease({ createdReleaseId: "73", observedRelease: { id: 73, draft: true } }), false);
});

test("verify-download CLI fails closed when the updater public key is unavailable", () => {
  const result = spawnSync(process.execPath, ["scripts/release/verify-download.mjs", "expected", "downloaded"], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, TAURI_UPDATER_PUBLIC_KEY: "" },
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /public key/iu);
});

test("inspectReleaseArtifacts accepts exactly one safe package and signature for every supported updater target", () => {
  const root = temporaryDirectory();
  try {
    releaseFixture(root);
    const artifacts = inspectReleaseArtifacts(root, { version: VERSION });
    assert.deepEqual(Object.keys(artifacts.updaterTargets).sort(), [
      "darwin-aarch64-app",
      "linux-x86_64-deb",
      "windows-x86_64-msi",
      "windows-x86_64-nsis",
    ]);
    assert.equal(artifacts.packages.length, 5);
    assert.ok(readFileSync(path.join(root, "checksums.sha256"), "utf8").includes("VaultBrain_1.2.3_x64-setup.exe"));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("inspectReleaseArtifacts rejects missing target signatures, duplicate target packages, and unsafe names", () => {
  const missing = temporaryDirectory();
  const duplicate = temporaryDirectory();
  const unexpected = temporaryDirectory();
  const unsafe = temporaryDirectory();
  try {
    releaseFixture(missing);
    rmSync(path.join(missing, "vault-brain_1.2.3_amd64.deb.sig"));
    assert.throws(() => inspectReleaseArtifacts(missing, { version: VERSION }), /linux-x86_64-deb/iu);

    releaseFixture(duplicate);
    writeArtifact(duplicate, "VaultBrainCopy_1.2.3_x64-setup.exe");
    writeArtifact(duplicate, "VaultBrainCopy_1.2.3_x64-setup.exe.sig");
    assert.throws(() => inspectReleaseArtifacts(duplicate, { version: VERSION }), /duplicate/iu);

    releaseFixture(unexpected);
    writeArtifact(unexpected, "unreviewed-extra.bin");
    assert.throws(() => inspectReleaseArtifacts(unexpected, { version: VERSION }), /unexpected release asset/iu);

    releaseFixture(unsafe);
    assert.throws(
      () =>
        createLatestManifest({
          repository: REPOSITORY,
          tag: "v1.2.3",
          version: VERSION,
          publishedAt: "2026-09-08T00:00:00.000Z",
          artifacts: {
            updaterTargets: {
              "darwin-aarch64-app": { asset: "../escape.tar.gz", signature: "sig" },
              "linux-x86_64-deb": { asset: "vault-brain_1.2.3_amd64.deb", signature: "sig" },
              "windows-x86_64-msi": { asset: "VaultBrain_1.2.3_x64_en-US.msi", signature: "sig" },
              "windows-x86_64-nsis": { asset: "VaultBrain_1.2.3_x64-setup.exe", signature: "sig" },
            },
          },
        }),
      /unsafe asset/iu,
    );
  } finally {
    for (const root of [missing, duplicate, unexpected, unsafe]) {
      rmSync(root, { recursive: true, force: true });
    }
  }
});

test("createLatestManifest produces a complete fixed-HTTPS manifest with bundle-specific updater keys", () => {
  const root = temporaryDirectory();
  try {
    releaseFixture(root);
    const manifest = createLatestManifest({
      repository: REPOSITORY,
      tag: "v1.2.3",
      version: VERSION,
      publishedAt: "2026-09-08T00:00:00.000Z",
      artifacts: inspectReleaseArtifacts(root, { version: VERSION }),
    });
    assert.equal(manifest.version, VERSION);
    assert.equal(
      manifest.platforms["windows-x86_64-nsis"].url,
      "https://github.com/devfurkanakblt/vaultbrain/releases/download/v1.2.3/VaultBrain_1.2.3_x64-setup.exe",
    );
    assert.equal(manifest.platforms["linux-x86_64-deb"].signature, "vault-brain_1.2.3_amd64.deb.sig");
    assert.equal(Object.keys(manifest.platforms).length, 4);
    assert.throws(
      () =>
        createLatestManifest({
          repository: "other/repository",
          tag: "v1.2.3",
          version: VERSION,
          publishedAt: "2026-09-08T00:00:00.000Z",
          artifacts: inspectReleaseArtifacts(root, { version: VERSION }),
        }),
      /fixed repository/iu,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("verifyDownloadedAssets rejects a corrupt downloaded release asset", () => {
  const expected = temporaryDirectory();
  const downloaded = temporaryDirectory();
  try {
    const names = releaseFixture(expected);
    const artifacts = inspectReleaseArtifacts(expected, { version: VERSION });
    writeArtifact(
      expected,
      "latest.json",
      JSON.stringify(
        createLatestManifest({
          repository: REPOSITORY,
          tag: "v1.2.3",
          version: VERSION,
          publishedAt: "2026-09-08T00:00:00.000Z",
          artifacts,
        }),
      ),
    );
    writeReleaseChecksums(expected);
    cpSync(expected, downloaded, { recursive: true });
    writeArtifact(downloaded, names[0], "corrupted installer bytes");
    assert.throws(
      () => verifyDownloadedAssets({ expectedDirectory: expected, downloadedDirectory: downloaded }),
      /checksum mismatch/iu,
    );
  } finally {
    rmSync(expected, { recursive: true, force: true });
    rmSync(downloaded, { recursive: true, force: true });
  }
});

test("verifyDownloadedAssets rejects a corrupt latest manifest or provenance bundle", () => {
  const expected = temporaryDirectory();
  const downloaded = temporaryDirectory();
  try {
    releaseFixture(expected);
    const artifacts = inspectReleaseArtifacts(expected, { version: VERSION });
    writeArtifact(
      expected,
      "latest.json",
      JSON.stringify(
        createLatestManifest({
          repository: REPOSITORY,
          tag: "v1.2.3",
          version: VERSION,
          publishedAt: "2026-09-08T00:00:00.000Z",
          artifacts,
        }),
      ),
    );
    writeReleaseChecksums(expected);
    cpSync(expected, downloaded, { recursive: true });
    writeArtifact(downloaded, "provenance.intoto.jsonl", "corrupted provenance");
    assert.throws(
      () => verifyDownloadedAssets({ expectedDirectory: expected, downloadedDirectory: downloaded }),
      /checksum mismatch/iu,
    );
  } finally {
    rmSync(expected, { recursive: true, force: true });
    rmSync(downloaded, { recursive: true, force: true });
  }
});

test("verifyDownloadedAssets rejects a modified checksum manifest", () => {
  const expected = temporaryDirectory();
  const downloaded = temporaryDirectory();
  try {
    releaseFixture(expected);
    const artifacts = inspectReleaseArtifacts(expected, { version: VERSION });
    writeArtifact(
      expected,
      "latest.json",
      JSON.stringify(
        createLatestManifest({
          repository: REPOSITORY,
          tag: "v1.2.3",
          version: VERSION,
          publishedAt: "2026-09-08T00:00:00.000Z",
          artifacts,
        }),
      ),
    );
    writeReleaseChecksums(expected);
    cpSync(expected, downloaded, { recursive: true });
    writeArtifact(downloaded, "checksums.sha256", "tampered checksum manifest\n");
    assert.throws(
      () => verifyDownloadedAssets({ expectedDirectory: expected, downloadedDirectory: downloaded }),
      /checksum manifest changed/iu,
    );
  } finally {
    rmSync(expected, { recursive: true, force: true });
    rmSync(downloaded, { recursive: true, force: true });
  }
});
