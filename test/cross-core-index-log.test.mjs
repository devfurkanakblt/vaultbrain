// Phase 17: the change log is a format both cores share.
//
// Both the TypeScript library and the Rust desktop core write `index.enc`. A
// log only one of them understood would leave the other reading a snapshot
// that omits the first one's recent saves, and then overwriting it from that
// stale state — a correctness bug, not a missed optimisation.
//
// This drives one vault from both cores and asserts each sees the other's
// work. It needs the Rust benchmark binary, which is built with
// `cargo build --release --features benchmark --bin vbrain-bench`; when that
// is not present the test reports why and skips rather than passing quietly.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { DocumentVault } from "../dist/documents.js";
import { INDEX_LOG_FILENAME } from "../dist/index-log.js";
import { removeTree } from "../scripts/fs-tree.mjs";

const PASSPHRASE = "cross-core-index-log-passphrase";
const BINARY = path.resolve(
  "src-tauri/target/release",
  process.platform === "win32" ? "vbrain-bench.exe" : "vbrain-bench",
);

/**
 * Drives the Rust core against an existing vault.
 *
 * `--inspect` opens the vault the way a desktop unlock does — snapshot plus
 * change log — and prints what it found, so the TypeScript side can compare.
 */
function rustInspect(vaultDir) {
  const output = execFileSync(BINARY, ["--inspect", vaultDir, "--passphrase", PASSPHRASE], {
    encoding: "utf8",
  });
  return JSON.parse(output);
}

function rustEdit(vaultDir, notePath, body) {
  execFileSync(
    BINARY,
    ["--edit", vaultDir, "--passphrase", PASSPHRASE, "--path", notePath, "--body", body],
    { encoding: "utf8" },
  );
}

test("each core reads the change log the other one wrote", { skip: skipReason() }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cross-core-log-"));
  try {
    // 1. TypeScript writes, and deliberately does not compact.
    const writer = new DocumentVault(dir, PASSPHRASE);
    writer.put({ path: "People/Ada.md", title: "Ada", body: "Works on [[Projects/Alpha]]." });
    writer.put({ path: "Projects/Alpha.md", title: "Alpha", body: "Owned by [[People/Ada]]." });
    const logFile = path.join(dir, "documents", INDEX_LOG_FILENAME);
    assert.ok(fs.existsSync(logFile), "the TypeScript saves should have left a log");

    // 2. Rust opens the same vault. Without understanding the log it would
    //    see an index that predates both notes.
    const seen = rustInspect(dir);
    assert.equal(seen.notes, 2, "the Rust core must replay the TypeScript log");
    assert.deepEqual(seen.paths.sort(), ["People/Ada.md", "Projects/Alpha.md"]);
    assert.equal(seen.unresolved, 0, "links written by TypeScript must resolve in Rust");

    // 3. Rust writes to the same vault, again without compacting.
    rustEdit(dir, "People/Ada.md", "Edited by the desktop core, still [[Projects/Alpha]].");

    // 4. TypeScript picks that up on its next open.
    const reader = new DocumentVault(dir, PASSPHRASE);
    try {
      assert.match(reader.get("People/Ada.md").body, /Edited by the desktop core/u);
      assert.equal(reader.unresolvedLinks().length, 0);
      assert.deepEqual(
        reader.backlinks("Projects/Alpha.md").map((note) => note.path),
        ["People/Ada.md"],
      );
    } finally {
      reader.lock();
    }
    writer.lock();
  } finally {
    removeTree(dir);
  }
});

function skipReason() {
  if (fs.existsSync(BINARY)) return false;
  return `the Rust core is not built; run: cargo build --release --manifest-path src-tauri/Cargo.toml --features benchmark --bin vbrain-bench`;
}
