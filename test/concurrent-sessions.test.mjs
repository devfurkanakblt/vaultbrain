// Two live sessions on one vault.
//
// A `DocumentVault` keeps the index in memory for the life of the session. It
// used to return that cache unconditionally, so a session's first read of the
// index was its only one: a note another process saved afterwards was invisible
// to it, and its next save committed on top of a state that no longer existed.
// The note object stayed on disk, unreferenced and unreachable.
//
// The vault lock was never the missing piece — it was always taken, and it
// serialises the writes correctly. What was missing is re-reading what the
// previous holder left behind after the lock is handed over.
//
// These drive a real second process, because that is the shape this takes in
// practice: a long-running session on one side, a `vbrain` invocation on the
// other. The Rust core compares the same snapshot stamp in
// `refresh_session_index`; a divergence here is the cross-implementation defect
// Phase 13 exists to prevent.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

import { DocumentVault } from "../dist/documents.js";
import { INDEX_LOG_FILENAME } from "../dist/index-log.js";
import { removeTree } from "../scripts/fs-tree.mjs";

const PASSPHRASE = "concurrent-sessions-test-passphrase";
const DIST = pathToFileURL(path.resolve("dist/documents.js")).href;

function tempVault() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "concurrent-sessions-"));
}

/**
 * Runs `body` against the same vault in a separate Node process.
 *
 * `body` is module source with `vault` already open. It decides for itself
 * whether to lock: locking compacts the log into a fresh snapshot, and not
 * locking leaves the log behind exactly as a killed process would.
 */
function inAnotherProcess(vaultDir, body) {
  const script = `
    const { DocumentVault } = await import(${JSON.stringify(DIST)});
    const vault = new DocumentVault(process.env.VB_DIR, process.env.VB_PASS);
    ${body}
  `;
  return execFileSync(process.execPath, ["--input-type=module", "-e", script], {
    env: { ...process.env, VB_DIR: vaultDir, VB_PASS: PASSPHRASE },
    encoding: "utf8",
  }).trim();
}

function logPath(vaultDir) {
  return path.join(vaultDir, "documents", INDEX_LOG_FILENAME);
}

function paths(vault) {
  return vault
    .list()
    .map((note) => note.path)
    .sort();
}

test("a note another process saved is not dropped by this session's next save", () => {
  const dir = tempVault();
  try {
    const session = new DocumentVault(dir, PASSPHRASE);
    session.put({ path: "Seed.md", body: "seed" });

    // Locking compacts, so this leaves a fresh snapshot and no log — the shape
    // an ordinary second session leaves when it closes cleanly.
    inAnotherProcess(dir, `vault.put({ path: "Other.md", body: "from another process" }); vault.lock();`);

    session.put({ path: "Later.md", body: "written after" });
    assert.deepEqual(paths(session), ["Later.md", "Other.md", "Seed.md"]);
    session.lock();

    const reopened = new DocumentVault(dir, PASSPHRASE);
    try {
      assert.deepEqual(paths(reopened), ["Later.md", "Other.md", "Seed.md"]);
      assert.equal(reopened.get("Other.md").body, "from another process");
    } finally {
      reopened.lock();
    }
  } finally {
    removeTree(dir);
  }
});

test("records another process appended without compacting are folded in", () => {
  const dir = tempVault();
  try {
    const session = new DocumentVault(dir, PASSPHRASE);
    session.put({ path: "Seed.md", body: "seed" });

    // No lock, so the snapshot is untouched and the save lives only in the log.
    // The stamp alone would report "unchanged"; the log has to be tailed too.
    inAnotherProcess(dir, `vault.put({ path: "Logged.md", body: "only in the log" });`);
    assert.ok(fs.existsSync(logPath(dir)), "the other process should have left a log");

    session.put({ path: "Later.md", body: "written after" });
    assert.deepEqual(paths(session), ["Later.md", "Logged.md", "Seed.md"]);
    session.lock();

    const reopened = new DocumentVault(dir, PASSPHRASE);
    try {
      assert.deepEqual(paths(reopened), ["Later.md", "Logged.md", "Seed.md"]);
      assert.equal(reopened.get("Logged.md").body, "only in the log");
    } finally {
      reopened.lock();
    }
  } finally {
    removeTree(dir);
  }
});

test("a removal by another process is not resurrected by this session", () => {
  const dir = tempVault();
  try {
    const session = new DocumentVault(dir, PASSPHRASE);
    session.put({ path: "Doomed.md", body: "here for now" });
    session.put({ path: "Points.md", body: "See [[Doomed]]." });
    assert.equal(session.unresolvedLinks().length, 0);

    inAnotherProcess(dir, `vault.remove("Doomed.md"); vault.lock();`);

    session.put({ path: "Later.md", body: "written after" });
    assert.deepEqual(paths(session), ["Later.md", "Points.md"]);
    // The removal has to reach the derived maps, not just the note list.
    assert.equal(session.unresolvedLinks().length, 1, "the link to the removed note should dangle");
    session.lock();

    const reopened = new DocumentVault(dir, PASSPHRASE);
    try {
      assert.deepEqual(paths(reopened), ["Later.md", "Points.md"]);
    } finally {
      reopened.lock();
    }
  } finally {
    removeTree(dir);
  }
});

test("a read in a live session reflects what another process wrote", () => {
  const dir = tempVault();
  try {
    const session = new DocumentVault(dir, PASSPHRASE);
    session.put({ path: "Seed.md", body: "seed" });
    assert.deepEqual(paths(session), ["Seed.md"]);

    inAnotherProcess(dir, `vault.put({ path: "Added.md", body: "added elsewhere" }); vault.lock();`);

    // No write on this side: a stale read is wrong on its own, and is what a
    // long-running reader would otherwise report for the rest of its life.
    assert.deepEqual(paths(session), ["Added.md", "Seed.md"]);
    assert.equal(session.get("Added.md").body, "added elsewhere");
    assert.equal(session.search("added elsewhere").length, 1, "search should see the new note too");
    session.lock();
  } finally {
    removeTree(dir);
  }
});
