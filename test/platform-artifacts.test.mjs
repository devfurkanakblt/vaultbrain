import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const script = path.join(root, "scripts", "platform-artifacts.mjs");

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "vaultbrain-platform-artifacts-"));
}

function writeArm64MachO(file) {
  const header = Buffer.alloc(32);
  header.writeUInt32LE(0xfeedfacf, 0);
  header.writeUInt32LE(0x0100000c, 4);
  fs.writeFileSync(file, header);
}

function writeMacArtifacts(bundleDir, { architecture = "arm64" } = {}) {
  const app = path.join(bundleDir, "macos", "Vault Brain.app");
  const executable = path.join(app, "Contents", "MacOS", "Vault Brain");
  fs.mkdirSync(path.dirname(executable), { recursive: true });
  fs.writeFileSync(
    path.join(app, "Contents", "Info.plist"),
    `<?xml version="1.0"?><plist><dict><key>CFBundleIdentifier</key><string>dev.vaultbrain.desktop</string><key>CFBundleShortVersionString</key><string>0.2.0</string></dict></plist>`,
  );
  if (architecture === "arm64") writeArm64MachO(executable);
  else fs.writeFileSync(executable, Buffer.from([0xcf, 0xfa, 0xed, 0xfe, 0x07, 0, 0, 1]));
  fs.mkdirSync(path.join(bundleDir, "dmg"), { recursive: true });
  fs.writeFileSync(path.join(bundleDir, "dmg", "Vault Brain_0.2.0_aarch64.dmg"), "synthetic dmg");
}

function run(args, options = {}) {
  return execFileSync(process.execPath, [script, ...args], {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
  });
}

test("fails when the selected platform's required artifact is absent", () => {
  const bundleDir = tempDir();
  try {
    assert.throws(
      () => run(["--platform", "macos", "--bundle-dir", bundleDir]),
      /Missing required macOS artifact: .+\.app/u,
    );
  } finally {
    fs.rmSync(bundleDir, { recursive: true, force: true });
  }
});

test("rejects an app bundle whose executable is not ARM64", () => {
  const bundleDir = tempDir();
  try {
    writeMacArtifacts(bundleDir, { architecture: "x64" });
    assert.throws(() => run(["--platform", "macos", "--bundle-dir", bundleDir]), /expected arm64, found x64/u);
  } finally {
    fs.rmSync(bundleDir, { recursive: true, force: true });
  }
});

test("writes portable upload and checksum manifests for valid macOS artifacts", () => {
  const bundleDir = tempDir();
  try {
    writeMacArtifacts(bundleDir);
    const output = JSON.parse(run(["--platform", "macos", "--bundle-dir", bundleDir]));
    const checksums = fs.readFileSync(path.join(bundleDir, "checksums.sha256"), "utf8");
    const uploads = JSON.parse(fs.readFileSync(path.join(bundleDir, "upload-artifacts.json"), "utf8"));

    assert.equal(output.platform, "macos");
    assert.equal(output.identifier, "dev.vaultbrain.desktop");
    assert.deepEqual(
      uploads.artifacts.map((artifact) => artifact.path),
      ["dmg/Vault Brain_0.2.0_aarch64.dmg", "macos/Vault Brain.app.tar.gz"],
    );
    assert.match(checksums, /^[a-f0-9]{64} {2}dmg\/Vault Brain_0\.2\.0_aarch64\.dmg$/mu);
    assert.match(checksums, /^[a-f0-9]{64} {2}macos\/Vault Brain\.app\.tar\.gz$/mu);
    assert.doesNotMatch(checksums, /checksums\.sha256|upload-artifacts\.json/u);
  } finally {
    fs.rmSync(bundleDir, { recursive: true, force: true });
  }
});

test("repeated validation produces an identical checksum manifest", () => {
  const bundleDir = tempDir();
  try {
    writeMacArtifacts(bundleDir);
    run(["--platform", "macos", "--bundle-dir", bundleDir]);
    const first = fs.readFileSync(path.join(bundleDir, "checksums.sha256"));
    run(["--platform", "macos", "--bundle-dir", bundleDir]);
    const second = fs.readFileSync(path.join(bundleDir, "checksums.sha256"));
    assert.equal(
      crypto.createHash("sha256").update(first).digest("hex"),
      crypto.createHash("sha256").update(second).digest("hex"),
    );
  } finally {
    fs.rmSync(bundleDir, { recursive: true, force: true });
  }
});
