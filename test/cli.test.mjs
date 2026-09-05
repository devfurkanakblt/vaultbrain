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

// Important finding: the journal guard (src/cli.ts preAction hook) used to
// exempt any command whose bare leaf name is "init", which let a journaled
// vault be opened by `sync devices init` — a leaf command that happens to
// share a name with the exempt top-level `init`, but that (unlike top-level
// `init`) opens the vault with the passphrase and writes devices.enc and
// identity keys. The guard only checks that the journal file exists, so a
// hand-planted empty one is enough to exercise it without staging a real
// interrupted re-key.
test("the journal guard matches the full command path, not just a leaf named \"init\"", () => {
  const vaultDir = tempVault("journal-guard");
  const env = { VBRAIN_PASSPHRASE: "cli-journal-guard-passphrase" };
  const flags = ["--vault", vaultDir, "--experimental-trusted-sync"];

  // A real, already-initialized registry: before the fix, a wrongly-exempted
  // `sync devices init` would sail past the journal guard and reach
  // `initializeOwner`'s own "already initialized" refusal instead — a
  // different error that would prove the guard never ran at all.
  runCli([...flags, "sync", "devices", "init", "Owner laptop", "--device-id", DEVICE_A], env);

  const journalDir = path.join(vaultDir, ".rekey");
  fs.mkdirSync(journalDir, { recursive: true });
  fs.writeFileSync(path.join(journalDir, "journal.json"), "{}");

  assert.throws(
    () => runCli([...flags, "sync", "devices", "init", "Second device"], env),
    (error) => {
      const stderr = error.stderr ? error.stderr.toString("utf8") : "";
      return /interrupted re-key is still journaled/u.test(stderr);
    },
    "sync devices init must not be exempt from the journal guard just because its leaf name is \"init\"",
  );

  // The top-level `init` command is genuinely exempt (it only ensures the
  // vault directory exists) and must remain so: its own full path is "init",
  // not merely a leaf that happens to be named that.
  assert.doesNotThrow(() => runCli(["--vault", vaultDir, "init"]));

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

test("vbrain purge previews first, then removes the object and its history", () => {
  const vaultDir = tempVault("purge");
  const outside = tempVault("purge-out");
  const env = { VBRAIN_PASSPHRASE: "cli-purge-test-passphrase" };
  const flags = ["--vault", vaultDir];

  const source = path.join(outside, "Results.md");
  fs.writeFileSync(source, "---\ntitle: Results\n---\n# Results\n");
  runCli([...flags, "docs", "import", "Health/Results.md", source], env);
  fs.writeFileSync(source, "---\ntitle: Results\n---\n# Results\n\nEdited.\n");
  runCli([...flags, "docs", "import", "Health/Results.md", source], env);

  // Without --yes it is a preview that changes nothing and exits non-zero.
  let preview;
  try {
    runCli([...flags, "purge", "note", "Health/Results.md"], env);
    assert.fail("the preview must not exit zero");
  } catch (error) {
    preview = `${error.stdout ?? ""}`;
    assert.equal(error.status, 2);
  }
  assert.match(preview, /Would purge note/u);
  assert.match(preview, /Nothing was removed/u);
  assert.match(runCli([...flags, "docs", "list"], env), /Health\/Results\.md/u);

  const purged = runCli([...flags, "purge", "note", "Health/Results.md", "--yes"], env);
  assert.match(purged, /Purged note Health\/Results\.md/u);
  assert.match(purged, /not recoverable/u);
  assert.doesNotMatch(runCli([...flags, "docs", "list"], env), /Health\/Results\.md/u);
  assert.match(fs.readFileSync(path.join(vaultDir, "audit.log"), "utf8"), /purge:note:/u);

  // The history directory is gone with it.
  const history = path.join(vaultDir, "documents", "history");
  assert.equal(!fs.existsSync(history) || fs.readdirSync(history).length === 0, true);

  fs.rmSync(vaultDir, { recursive: true, force: true });
  fs.rmSync(outside, { recursive: true, force: true });
});

test("vbrain retention bounds history and reports what it removed", () => {
  const vaultDir = tempVault("retention");
  const outside = tempVault("retention-out");
  const env = { VBRAIN_PASSPHRASE: "cli-retention-test-passphrase" };
  const flags = ["--vault", vaultDir];
  const source = path.join(outside, "Journal.md");

  for (let revision = 1; revision <= 5; revision += 1) {
    fs.writeFileSync(source, `---\ntitle: Journal\n---\n# Journal\n\nrevision ${revision}\n`);
    runCli([...flags, "docs", "import", "Journal.md", source], env);
  }
  assert.match(runCli([...flags, "retention", "show"], env), /every revision, forever/u);
  assert.match(runCli([...flags, "docs", "history", "Journal.md"], env), /5/u);

  const set = runCli([...flags, "retention", "set", "--keep-revisions", "2"], env);
  assert.match(set, /newest 2 archived revision/u);
  assert.match(set, /2 revision\(s\) removed from 1 of 1 object/u);
  assert.match(set, /not recoverable/u);
  assert.match(runCli([...flags, "retention", "show"], env), /newest 2 archived revision/u);
  assert.match(fs.readFileSync(path.join(vaultDir, "audit.log"), "utf8"), /retention:2:all/u);

  // A further edit is bounded as it is written, not only when a sweep runs.
  fs.writeFileSync(source, "---\ntitle: Journal\n---\n# Journal\n\nrevision 6\n");
  runCli([...flags, "docs", "import", "Journal.md", source], env);
  const history = runCli([...flags, "docs", "history", "Journal.md"], env);
  assert.equal(history.trim().split("\n").length, 3, history);

  // A no-op sweep says so rather than claiming work.
  assert.match(runCli([...flags, "retention", "apply"], env), /0 revision\(s\) removed/u);

  // Asking for a bound without naming one is refused rather than guessed at.
  assert.throws(() => runCli([...flags, "retention", "set"], env), /Use --unlimited/u);

  fs.rmSync(vaultDir, { recursive: true, force: true });
  fs.rmSync(outside, { recursive: true, force: true });
});
