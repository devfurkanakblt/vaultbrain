// Regressions for the findings in docs/CLI-AUDIT-2026-09-19.md. Each test
// reproduces the scenario the review actually ran, so a fix that is quietly
// undone fails here rather than in the next review.
import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

import { approveRequest, consumeApproval, pendingRequests, requestConfirmation } from "../dist/grants.js";
import { decide } from "../dist/grants.js";
import { DocumentVault } from "../dist/documents.js";
import { exportVault } from "../dist/export.js";
import { importObsidianVault } from "../dist/obsidian-import.js";
import { planRekey } from "../dist/keyring-rekey.js";
import { buildSchema, readSchema } from "../dist/schema.js";
import { changeVaultPassphrase } from "../dist/keyring-passphrase.js";
import { upsertEntry } from "../dist/store.js";
import { removeTree } from "../scripts/fs-tree.mjs";

const run = promisify(execFile);
const CLI = path.resolve("dist/cli.js");
const PASSPHRASE = "cli-audit-regression-passphrase";

function tempVault(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), label));
}

function cli(vault, args, passphrase = PASSPHRASE, extra = {}) {
  return execFileSync(process.execPath, [CLI, "--vault", vault, ...args], {
    encoding: "utf8",
    env: { ...process.env, VBRAIN_PASSPHRASE: passphrase, ...extra },
  });
}

// Finding 1 -- eight processes each read, modified and rewrote the same file,
// all reported "Stored", and only the last write survived.
test("parallel CLI writes to one category all survive", async () => {
  const vault = tempVault("cli-audit-kv-");
  try {
    cli(vault, ["add", "test", "BASE=base", "--desc", "base"]);
    const writers = Array.from({ length: 8 }, (_, index) =>
      run(process.execPath, [CLI, "--vault", vault, "add", "test", `KEY${index}=value${index}`, "--desc", `k${index}`], {
        env: { ...process.env, VBRAIN_PASSPHRASE: PASSPHRASE },
      }),
    );
    const settled = await Promise.allSettled(writers);
    const rejected = settled.filter((result) => result.status === "rejected");
    assert.deepEqual(
      rejected.map((result) => String(result.reason?.stderr ?? result.reason)),
      [],
      "no writer should fail",
    );

    const listed = cli(vault, ["list"]);
    assert.match(listed, /\bBASE\b/u);
    for (let index = 0; index < 8; index += 1) {
      assert.match(listed, new RegExp(`\\bKEY${index}\\b`, "u"), `KEY${index} was lost`);
    }
    // The catalog has to agree with storage, not just storage with itself.
    const schema = readSchema(vault, PASSPHRASE);
    assert.equal(schema.files.test.length, 9);
  } finally {
    removeTree(vault);
  }
});

// Finding 2 -- one owner approval was consumable once per racing process.
test("a single-use approval is consumed exactly once across processes", async () => {
  const vault = tempVault("cli-audit-approval-");
  try {
    upsertEntry(vault, "test", "SECRET", "s3cret", "secret", PASSPHRASE);
    cli(vault, ["grant", "add", "racer", "--scope", "test:*:discover,resolve:none", "--confirm"]);
    requestConfirmation(vault, { agent: "racer", file: "test", key: "SECRET" }, PASSPHRASE);
    approveRequest(vault, pendingRequests(vault, PASSPHRASE)[0].id, PASSPHRASE);

    const grantsUrl = pathToFileURL(path.resolve("dist/grants.js")).href;
    const script = `
      const { consumeApproval } = await import(${JSON.stringify(grantsUrl)});
      process.stdout.write(String(consumeApproval(${JSON.stringify(vault)}, { agent: "racer", file: "test", key: "SECRET" }, ${JSON.stringify(PASSPHRASE)})));
    `;
    const settled = await Promise.allSettled(
      Array.from({ length: 8 }, () => run(process.execPath, ["--input-type=module", "-e", script])),
    );
    assert.deepEqual(
      settled.filter((result) => result.status === "rejected").map((r) => String(r.reason?.stderr ?? r.reason)),
      [],
    );
    const spent = settled.filter((result) => result.value.stdout.trim() === "true").length;
    assert.equal(spent, 1, "one yes must answer exactly one resolution");
    assert.equal(consumeApproval(vault, { agent: "racer", file: "test", key: "SECRET" }, PASSPHRASE), false);
  } finally {
    removeTree(vault);
  }
});

// Finding 3 -- store_note asked permission with no key, then generated one.
test("a store scope never covers an unnamed key", () => {
  const file = { version: 1, requests: [], grants: [] };
  file.grants.push({
    id: "11111111-1111-4111-8111-111111111111",
    agent: "agent",
    scopes: [{ file: "test", keys: ["ONLY_KEY"], actions: ["discover", "resolve", "store"], redact: "none" }],
    createdAt: "2026-09-19T00:00:00.000Z",
    expiresAt: null,
    confirm: "never",
    revokedAt: null,
  });

  assert.equal(decide(file, { agent: "agent", action: "store", file: "test", key: "ONLY_KEY" }).allowed, true);
  assert.equal(decide(file, { agent: "agent", action: "store", file: "test", key: "NOTE_20260919_0000_ab" }).allowed, false);
  // The hole itself: no key named at all must not authorize a write.
  assert.equal(decide(file, { agent: "agent", action: "store", file: "test" }).allowed, false);
  // Discovery still answers the broader "is anything here reachable" question.
  assert.equal(decide(file, { agent: "agent", action: "discover", file: "test" }).allowed, true);
});

// Findings 4 and 5 -- the catalog was sealed with a passphrase-derived key, so
// a passphrase change left `list` unreadable, and re-key refused the file.
test("the catalog survives a passphrase change and re-key classifies it", () => {
  const vault = tempVault("cli-audit-catalog-");
  const next = `${PASSPHRASE}-rotated`;
  try {
    cli(vault, ["add", "test", "KEY=synthetic", "--desc", "sample"]);
    assert.ok(fs.existsSync(path.join(vault, "schema.enc")));
    assert.ok(
      planRekey(vault).some((item) => item.path === "schema.enc"),
      "schema.enc must be in the re-key inventory",
    );

    changeVaultPassphrase(vault, PASSPHRASE, next);
    assert.equal(cli(vault, ["get", "test", "KEY"], next).trim(), "synthetic");
    // The failure this reproduces: `get` worked and `list` did not.
    assert.match(cli(vault, ["list"], next), /\bKEY\b/u);
    assert.equal(readSchema(vault, next).files.test[0].key, "KEY");
    assert.throws(() => readSchema(vault, PASSPHRASE), /unlock|authenticate/iu);

    cli(vault, ["rekey", "--keep-passphrase"], next);
    assert.match(cli(vault, ["list"], next), /\bKEY\b/u);
  } finally {
    removeTree(vault);
  }
});

test("a catalog left in the legacy envelope is rebuilt rather than re-keyed blindly", () => {
  const vault = tempVault("cli-audit-legacy-catalog-");
  try {
    cli(vault, ["add", "test", "KEY=value", "--desc", "sample"]);
    // Simulate what an older release wrote: version 1, passphrase-derived.
    const catalog = path.join(vault, "schema.enc");
    const payload = JSON.parse(fs.readFileSync(catalog, "utf8"));
    fs.writeFileSync(catalog, JSON.stringify({ ...payload, version: 1 }, null, 2));
    assert.throws(() => planRekey(vault), /vbrain index/u);

    buildSchema(vault, PASSPHRASE);
    assert.ok(planRekey(vault).some((item) => item.path === "schema.enc"));
  } finally {
    removeTree(vault);
  }
});

// Finding 6 -- containment was checked lexically, so a junction above the
// destination let a plaintext export land inside the vault.
test("an export destination reached through a link is refused", () => {
  const base = tempVault("cli-audit-export-");
  try {
    const vaultDir = path.join(base, "vault");
    const vault = new DocumentVault(vaultDir, PASSPHRASE);
    vault.put({ path: "Index.md", body: "secret body" });
    vault.lock();

    const link = path.join(base, "link");
    if (process.platform === "win32") {
      execFileSync("cmd", ["/c", "mklink", "/J", link, vaultDir], { stdio: "ignore" });
    } else {
      fs.symlinkSync(vaultDir, link, "dir");
    }

    assert.throws(
      () => exportVault(vaultDir, path.join(link, "plaintext"), PASSPHRASE),
      /must be written outside the vault/u,
    );
    assert.equal(fs.existsSync(path.join(vaultDir, "plaintext", "Index.md")), false);

    // A genuine destination outside the vault still works.
    const clean = path.join(base, "export");
    assert.equal(exportVault(vaultDir, clean, PASSPHRASE).ok, true);
    assert.ok(fs.existsSync(path.join(clean, "Index.md")));
  } finally {
    removeTree(base);
  }
});

// Finding 7 -- a note renamed for portability left every link to it dangling.
test("a portability rename carries note, canvas and text-node links with it", () => {
  const base = tempVault("cli-audit-roundtrip-");
  try {
    const vaultDir = path.join(base, "vault");
    const vault = new DocumentVault(vaultDir, PASSPHRASE);
    // A legal vault path and an illegal Windows filename.
    const results = vault.put({ path: "Q3: results.md", body: "The numbers." });
    vault.put({ path: "Index.md", body: "See [[Q3: results]] for detail." });
    vault.putCanvas({
      path: "Board.canvas",
      nodes: [
        { id: "n1", type: "file", file: "Q3: results.md", noteId: results.id, x: 0, y: 0, width: 300, height: 200 },
        { id: "n2", type: "text", text: "context: [[Q3: results]]", x: 0, y: 300, width: 300, height: 120 },
      ],
      edges: [],
    });
    vault.lock();

    const exported = path.join(base, "export");
    assert.equal(exportVault(vaultDir, exported, PASSPHRASE).ok, true);
    assert.ok(fs.existsSync(path.join(exported, "Q3- results.md")));
    assert.match(fs.readFileSync(path.join(exported, "Index.md"), "utf8"), /\[\[Q3- results\]\]/u);

    const board = JSON.parse(fs.readFileSync(path.join(exported, "Board.canvas"), "utf8"));
    assert.equal(board.nodes.find((node) => node.type === "file").file, "Q3- results.md");
    assert.match(board.nodes.find((node) => node.type === "text").text, /\[\[Q3- results\]\]/u);

    const reimportedDir = path.join(base, "reimported");
    importObsidianVault(exported, reimportedDir, PASSPHRASE);
    const reimported = new DocumentVault(reimportedDir, PASSPHRASE);
    try {
      assert.deepEqual(reimported.unresolvedLinks(), [], "the link web must survive the round trip");
      const node = reimported.getCanvas("Board.canvas").nodes.find((entry) => entry.type === "file");
      assert.ok(node.noteId, "the canvas node must resolve to a note again");
    } finally {
      reimported.lock();
    }
  } finally {
    removeTree(base);
  }
});

test("links inside code spans are left alone by an export rename", () => {
  const base = tempVault("cli-audit-code-");
  try {
    const vaultDir = path.join(base, "vault");
    const vault = new DocumentVault(vaultDir, PASSPHRASE);
    vault.put({ path: "Q3: results.md", body: "numbers" });
    vault.put({
      path: "Doc.md",
      body: ["Live [[Q3: results]].", "", "```", "[[Q3: results]]", "```", "", "Inline `[[Q3: results]]`."].join("\n"),
    });
    vault.lock();

    const exported = path.join(base, "export");
    exportVault(vaultDir, exported, PASSPHRASE);
    const text = fs.readFileSync(path.join(exported, "Doc.md"), "utf8");
    assert.match(text, /Live \[\[Q3- results\]\]\./u);
    assert.match(text, /```\n\[\[Q3: results\]\]\n```/u);
    assert.match(text, /Inline `\[\[Q3: results\]\]`\./u);
  } finally {
    removeTree(base);
  }
});

// Finding 8 -- a failed verification exited 0 in JSON mode and 2 in text mode.
test("audit reports the same exit code in both output formats", () => {
  const vault = tempVault("cli-audit-exit-");
  try {
    cli(vault, ["add", "test", "K=v", "--desc", "d"]);
    const logPath = path.join(vault, "audit.log");
    const lines = fs.readFileSync(logPath, "utf8").trimEnd().split("\n");
    const last = JSON.parse(lines[lines.length - 1]);
    last.hash = `${last.hash.slice(0, -4)}aaaa`;
    lines[lines.length - 1] = JSON.stringify(last);
    fs.writeFileSync(logPath, `${lines.join("\n")}\n`);

    for (const args of [["audit"], ["audit", "--json"]]) {
      let failure;
      try {
        cli(vault, args);
      } catch (error) {
        failure = error;
      }
      assert.ok(failure, `${args.join(" ")} must not exit 0 on a broken chain`);
      assert.equal(failure.status, 2, `${args.join(" ")} must exit 2`);
      if (args.includes("--json")) {
        assert.equal(JSON.parse(failure.stdout).verification.valid, false);
      }
    }
  } finally {
    removeTree(vault);
  }
});
