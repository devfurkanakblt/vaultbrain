import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  captureVaultEvidence,
  runSyntheticNativeUpdateAcceptance,
  verifyNativeUpdateTransition,
} from "../scripts/release/native-update-acceptance.mjs";

function temporaryDirectory() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "vault-brain-native-update-test-"));
}

function writeVault(root) {
  fs.mkdirSync(path.join(root, "documents", "objects"), { recursive: true });
  fs.writeFileSync(path.join(root, "keyring.json"), JSON.stringify({ version: 2, slots: [{ id: "synthetic" }] }));
  fs.writeFileSync(path.join(root, "documents", "objects", "note.enc"), "encrypted-note-bytes");
}

function writeLinuxBundle(root, version, bytes = "native-deb-package") {
  const directory = path.join(root, "deb");
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, `vault-brain_${version}_amd64.deb`), bytes);
}

test("the native CI harness advances one packaged version without changing vault identity or bytes", () => {
  const root = temporaryDirectory();
  try {
    const bundle = path.join(root, "bundle");
    const vault = path.join(root, "vault");
    writeLinuxBundle(bundle, "1.2.3");
    writeVault(vault);

    const result = runSyntheticNativeUpdateAcceptance({
      platform: "linux",
      bundleDirectory: bundle,
      vaultDirectory: vault,
      previousVersion: "1.2.2",
      nextVersion: "1.2.3",
      appIdentifier: "dev.vaultbrain.desktop",
    });

    assert.equal(result.before.version, "1.2.2");
    assert.equal(result.after.version, "1.2.3");
    assert.equal(result.before.appIdentifier, result.after.appIdentifier);
    assert.equal(result.before.vaultIdentity, result.after.vaultIdentity);
    assert.equal(result.before.vaultTreeSha256, result.after.vaultTreeSha256);
    assert.notEqual(result.before.packageSha256, result.after.packageSha256);
    assert.equal(result.filesVerified, 2);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("transition verification rejects same-version packages and any vault mutation", () => {
  const root = temporaryDirectory();
  try {
    const vault = path.join(root, "vault");
    writeVault(vault);
    const vaultEvidence = captureVaultEvidence(vault);
    const before = {
      platform: "linux",
      version: "1.2.2",
      appIdentifier: "dev.vaultbrain.desktop",
      packageSha256: crypto.createHash("sha256").update("old").digest("hex"),
      ...vaultEvidence,
    };
    const after = {
      ...before,
      version: "1.2.3",
      packageSha256: crypto.createHash("sha256").update("new").digest("hex"),
    };

    assert.throws(() => verifyNativeUpdateTransition(before, { ...after, version: before.version }), /newer/iu);
    assert.throws(
      () => verifyNativeUpdateTransition(before, { ...after, vaultTreeSha256: "0".repeat(64) }),
      /vault contents/iu,
    );
    assert.throws(
      () => verifyNativeUpdateTransition(before, { ...after, vaultIdentity: "f".repeat(64) }),
      /vault identity/iu,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("the harness rejects a package whose filename does not carry the requested native version", () => {
  const root = temporaryDirectory();
  try {
    const bundle = path.join(root, "bundle");
    const vault = path.join(root, "vault");
    writeLinuxBundle(bundle, "1.2.4");
    writeVault(vault);
    assert.throws(
      () =>
        runSyntheticNativeUpdateAcceptance({
          platform: "linux",
          bundleDirectory: bundle,
          vaultDirectory: vault,
          previousVersion: "1.2.2",
          nextVersion: "1.2.3",
          appIdentifier: "dev.vaultbrain.desktop",
        }),
      /package.*version/iu,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("the harness selects every native CI package target without cross-platform fallback", () => {
  const root = temporaryDirectory();
  try {
    const bundle = path.join(root, "bundle");
    const vault = path.join(root, "vault");
    writeVault(vault);
    for (const [directory, name] of [
      ["msi", "VaultBrain_1.2.3_x64_en-US.msi"],
      ["nsis", "VaultBrain_1.2.3_x64-setup.exe"],
      ["dmg", "Vault Brain_1.2.3_aarch64.dmg"],
    ]) {
      fs.mkdirSync(path.join(bundle, directory), { recursive: true });
      fs.writeFileSync(path.join(bundle, directory, name), name);
    }

    for (const [platform, target] of [
      ["windows", "windows-msi"],
      ["windows", "windows-nsis"],
      ["macos", "macos-dmg"],
    ]) {
      const result = runSyntheticNativeUpdateAcceptance({
        platform,
        target,
        bundleDirectory: bundle,
        vaultDirectory: vault,
        previousVersion: "1.2.2",
        nextVersion: "1.2.3",
        appIdentifier: "dev.vaultbrain.desktop",
      });
      assert.equal(result.after.platform, platform);
    }

    assert.throws(
      () =>
        runSyntheticNativeUpdateAcceptance({
          platform: "linux",
          target: "windows-msi",
          bundleDirectory: bundle,
          vaultDirectory: vault,
          previousVersion: "1.2.2",
          nextVersion: "1.2.3",
          appIdentifier: "dev.vaultbrain.desktop",
        }),
      /target.*platform/iu,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
