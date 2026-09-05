import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const DEVICE_A = "11111111-1111-4111-8111-111111111111";

/** Runs the built CLI and returns stdout. Throws on a non-zero exit. */
function runCli(args, env = {}) {
  return execFileSync(process.execPath, ["dist/cli.js", ...args], {
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
}

function tempVault(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `secondbrain-cli-${label}-`));
}

test("sync devices list reports the active epoch and per-device state", () => {
  const vaultDir = tempVault("epoch");
  const env = { VBRAIN_PASSPHRASE: "cli-epoch-test-passphrase" };
  const flags = ["--vault", vaultDir, "--experimental-trusted-sync"];

  runCli([...flags, "sync", "devices", "init", "Owner laptop", "--device-id", DEVICE_A], env);
  const listed = runCli([...flags, "sync", "devices", "list"], env);

  assert.match(listed, /epoch 1/u, "the header names the active epoch");
  assert.match(listed, new RegExp(`${DEVICE_A}.*epoch=1.*active`, "u"), "each row carries its epoch and state");
  fs.rmSync(vaultDir, { recursive: true, force: true });
});

test("vbrain format prints the frozen version matrix", () => {
  const output = JSON.parse(runCli(["format"]));
  assert.equal(output.formatVersion, "1.0");
  assert.deepEqual(output.artifacts.encryptedEnvelope, {
    path: "*.kv.enc",
    reads: [0, 1],
    writes: [1],
  });
  assert.deepEqual(output.artifacts.syncChangeEnvelope.reads, [1, 2, 3]);
});

/**
 * A second device that shares this vault's key material and enrollment
 * authority. Copying before any content is written is the CLI equivalent of
 * the whole-vault copy the sync library tests use: two independent directories
 * that can nonetheless open each other's envelopes.
 */
function cloneVault(sourceDir, label) {
  const targetDir = tempVault(label);
  fs.rmSync(targetDir, { recursive: true, force: true });
  fs.cpSync(sourceDir, targetDir, { recursive: true });
  return targetDir;
}

function tempFile(label, bytes) {
  const file = path.join(os.tmpdir(), `vbrain-cli-${label}-${crypto.randomUUID()}.bin`);
  const body = crypto.randomBytes(bytes);
  fs.writeFileSync(file, body);
  return { file, body };
}

/**
 * A relay in its own process. `runCli` is synchronous, so a relay hosted in
 * this process could never answer the request the CLI under test makes.
 */
function startRelayProcess(storageDir, env) {
  const child = spawn(
    process.execPath,
    ["dist/cli.js", "--experimental-trusted-sync", "sync", "relay", "serve", storageDir, "--port", "0"],
    { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "inherit"] },
  );
  const stop = () =>
    new Promise((done) => {
      child.once("exit", () => done());
      child.kill();
    });
  return new Promise((resolve, reject) => {
    let buffered = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (part) => {
      buffered += part;
      const match = /listening at (http:\/\/\S+?)\.\s/u.exec(buffered);
      if (match) resolve({ url: match[1], stop });
    });
    child.once("error", reject);
    child.once("exit", (code) => reject(new Error(`The relay process exited with ${code}.`)));
  });
}

/** `Stored name (id, size bytes, chunks chunks).` */
function attachmentIdOf(output) {
  const match = /\(([0-9a-f]{64}), /u.exec(output);
  assert.ok(match, `attach did not print an attachment id: ${output}`);
  return match[1];
}

test("sync export --bundle carries attachment blobs to another vault without a relay", () => {
  const env = { VBRAIN_PASSPHRASE: "cli-bundle-test-passphrase" };
  const sourceDir = tempVault("bundle-source");
  const source = ["--vault", sourceDir, "--experimental-trusted-sync"];
  runCli([...source, "sync", "devices", "init", "Owner laptop", "--device-id", DEVICE_A], env);

  const targetDir = cloneVault(sourceDir, "bundle-target");
  const target = ["--vault", targetDir, "--experimental-trusted-sync"];

  const { file, body } = tempFile("bundle", 3 * 1024 * 1024 + 3);
  const attachmentId = attachmentIdOf(
    runCli([...source, "--sync-device", DEVICE_A, "docs", "attach", file], env),
  );

  const bundle = path.join(os.tmpdir(), `vbrain-cli-bundle-${crypto.randomUUID()}`);
  const exported = runCli([...source, "sync", "export", "--bundle", bundle], env);
  assert.match(exported, /1 envelope\(s\) and 4 blob\(s\)/u);
  assert.ok(fs.existsSync(path.join(bundle, "changes.json")));
  assert.ok(fs.readdirSync(path.join(bundle, "blobs")).length >= 4);

  const imported = runCli([...target, "sync", "import", bundle], env);
  assert.match(imported, /Staged 4 attachment blob\(s\)\./u);
  assert.match(imported, /Imported 1; already present 0\./u);

  const status = runCli([...target, "sync", "blobs", "status"], env);
  assert.match(status, new RegExp(`${attachmentId} 4 present, 0 missing`, "u"));

  runCli([...target, "sync", "apply", "attachment", attachmentId], env);
  const restored = path.join(os.tmpdir(), `vbrain-cli-restored-${crypto.randomUUID()}.bin`);
  runCli([...target, "docs", "attachment-get", attachmentId, restored], env);
  assert.ok(fs.readFileSync(restored).equals(body), "the bundle carried every attachment byte");

  for (const scrap of [sourceDir, targetDir, bundle]) fs.rmSync(scrap, { recursive: true, force: true });
  for (const scrap of [file, restored]) fs.rmSync(scrap, { force: true });
});

test("relay push and pull move blobs, and blobs prune and fetch reclaim and restore them", async () => {
  const token = "cli-relay-blob-token-with-at-least-32-bytes";
  const env = { VBRAIN_PASSPHRASE: "cli-relay-blob-passphrase", VBRAIN_RELAY_TOKEN: token };
  const storageDir = tempVault("relay-storage");
  const relay = await startRelayProcess(storageDir, env);
  const scraps = [storageDir];
  try {
    const sourceDir = tempVault("relay-source");
    const source = ["--vault", sourceDir, "--experimental-trusted-sync"];
    runCli([...source, "sync", "devices", "init", "Owner laptop", "--device-id", DEVICE_A], env);
    const targetDir = cloneVault(sourceDir, "relay-target");
    const target = ["--vault", targetDir, "--experimental-trusted-sync"];
    const { file, body } = tempFile("relay", 1024 * 1024 + 7);
    const restored = path.join(os.tmpdir(), `vbrain-cli-relay-restored-${crypto.randomUUID()}.bin`);
    scraps.push(sourceDir, targetDir, file, restored);
    const attachmentId = attachmentIdOf(
      runCli([...source, "--sync-device", DEVICE_A, "docs", "attach", file], env),
    );

    runCli([...source, "sync", "relay", "push", relay.url], env);
    const pulled = JSON.parse(runCli([...target, "sync", "relay", "pull", relay.url], env));
    assert.deepEqual(pulled.blobs, { fetched: 2, skipped: 0 }, "pull stages the blobs its changes reference");
    assert.match(runCli([...target, "sync", "blobs", "status"], env), /2 present, 0 missing/u);
    runCli([...target, "sync", "apply", "attachment", attachmentId], env);
    runCli([...target, "docs", "attachment-get", attachmentId, restored], env);
    assert.ok(fs.readFileSync(restored).equals(body), "the relay carried every attachment byte");

    const pruned = runCli([...source, "sync", "blobs", "prune", relay.url], env);
    assert.match(pruned, /Pruned 2 staged blob\(s\); kept 0 the relay does not hold\./u);
    assert.match(runCli([...source, "sync", "blobs", "status"], env), /0 present, 2 missing/u);

    const fetched = runCli([...source, "sync", "blobs", "fetch", relay.url], env);
    assert.match(fetched, /Fetched 2 blob\(s\); 0 already present\./u);
    assert.match(runCli([...source, "sync", "blobs", "status"], env), /2 present, 0 missing/u);
  } finally {
    await relay.stop();
    for (const scrap of scraps) fs.rmSync(scrap, { recursive: true, force: true });
  }
});

test("the pre-rename SBRAIN_ environment names still work", () => {
  const vaultDir = tempVault("legacy-env");
  try {
    // getPassphrase and relayToken both keep the old names as read-only
    // aliases. If this ever fails, an existing deployment breaks silently on
    // upgrade, so the compatibility promise is pinned rather than assumed.
    const legacy = { SBRAIN_PASSPHRASE: "cli-legacy-env-passphrase" };
    const flags = ["--vault", vaultDir, "--experimental-trusted-sync"];
    runCli([...flags, "sync", "devices", "init", "Owner laptop", "--device-id", DEVICE_A], legacy);
    assert.match(runCli([...flags, "sync", "devices", "list"], legacy), /epoch 1/u);

    // A short token must be rejected on its length, not fall through as unset.
    assert.throws(
      () => runCli([...flags, "sync", "relay", "push", "http://127.0.0.1:1"], { ...legacy, SBRAIN_RELAY_TOKEN: "too-short" }),
      /VBRAIN_RELAY_TOKEN must contain at least 32 bytes/u,
    );
  } finally {
    fs.rmSync(vaultDir, { recursive: true, force: true });
  }
});

test("vbrain export writes a plaintext copy, records it, and says what it is", () => {
  const vaultDir = tempVault("export");
  const outside = tempVault("export-out");
  const destination = path.join(outside, "plain");
  const env = { VBRAIN_PASSPHRASE: "cli-export-test-passphrase" };
  const flags = ["--vault", vaultDir];

  const source = path.join(outside, "Ada.md");
  fs.writeFileSync(source, "---\ntitle: Ada\n---\n# Ada\n");
  runCli([...flags, "docs", "import", "People/Ada.md", source], env);

  const reportPath = path.join(outside, "export-report.json");
  const output = runCli([...flags, "export", destination, "--report", reportPath], env);

  assert.match(output, /Exported 1\/1 notes/u);
  assert.match(output, /This copy is not encrypted/u);
  assert.equal(fs.readFileSync(path.join(destination, "People", "Ada.md"), "utf8").includes("# Ada"), true);

  const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
  assert.equal(report.ok, true);
  assert.deepEqual(report.notes, { total: 1, written: 1 });

  // The chain records that a plaintext copy was made, and not where it went.
  const audit = fs.readFileSync(path.join(vaultDir, "audit.log"), "utf8");
  assert.match(audit, /export:1:0:0/u);
  assert.equal(audit.includes(destination), false);

  // A second export into the same directory is refused rather than merged.
  assert.throws(() => runCli([...flags, "export", destination], env), /not empty/u);

  fs.rmSync(vaultDir, { recursive: true, force: true });
  fs.rmSync(outside, { recursive: true, force: true });
});

test("vbrain backup and restore carry a vault to a new directory, and refuse a bad archive", () => {
  const vaultDir = tempVault("backup");
  const outside = tempVault("backup-out");
  const archive = path.join(outside, "vault.vbrainbackup");
  const env = { VBRAIN_PASSPHRASE: "cli-backup-test-passphrase" };
  const flags = ["--vault", vaultDir];

  const source = path.join(outside, "Ada.md");
  fs.writeFileSync(source, "---\ntitle: Ada\n---\n# Ada\n");
  runCli([...flags, "docs", "import", "People/Ada.md", source], env);

  const made = runCli([...flags, "backup", archive], env);
  assert.match(made, /Verified: the archive was read back/u);
  assert.match(made, /the passphrase is not in it/u);
  assert.match(fs.readFileSync(path.join(vaultDir, "audit.log"), "utf8"), /backup:\d+/u);

  const checked = runCli(["restore", archive, path.join(outside, "unused"), "--verify-only"], env);
  assert.match(checked, /Nothing was written/u);
  assert.equal(fs.existsSync(path.join(outside, "unused")), false);

  const destination = path.join(outside, "restored");
  assert.match(runCli(["restore", archive, destination], env), /Restored \d+ files/u);
  const listed = runCli(["--vault", destination, "docs", "list"], env);
  assert.match(listed, /People\/Ada\.md/u);

  // A restore that cannot open the archive leaves the destination alone.
  assert.throws(
    () => runCli(["restore", archive, path.join(outside, "wrong")], { VBRAIN_PASSPHRASE: "not-it" }),
    /Unable to unlock/u,
  );
  assert.equal(fs.existsSync(path.join(outside, "wrong")), false);

  fs.rmSync(vaultDir, { recursive: true, force: true });
  fs.rmSync(outside, { recursive: true, force: true });
});
