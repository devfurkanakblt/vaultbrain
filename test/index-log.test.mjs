// Phase 17: the encrypted index change log.
//
// A save appends a sealed record instead of rewriting the whole index, so
// these cover the three things that can go wrong with that: the log must
// replay to exactly the index the writing session held, a crash must not cost
// an acknowledged save, and a damaged or stale log must not quietly hand back
// an index missing what it could not read.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { DocumentVault } from "../dist/documents.js";
import { INDEX_LOG_FILENAME, COMPACT_AFTER_RECORDS } from "../dist/index-log.js";
import { removeTree } from "../scripts/fs-tree.mjs";

const PASSPHRASE = "index-log-test-passphrase";

function tempVault() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "index-log-"));
}

function logPath(vaultDir) {
  return path.join(vaultDir, "documents", INDEX_LOG_FILENAME);
}

function logLines(vaultDir) {
  if (!fs.existsSync(logPath(vaultDir))) return 0;
  return fs.readFileSync(logPath(vaultDir), "utf8").split("\n").filter(Boolean).length;
}

/** The parts of an index a replay has to reproduce exactly. */
function shape(vault) {
  return {
    notes: vault
      .list()
      .map((note) => `${note.id}:${note.path}:${note.title}`)
      .sort(),
    unresolved: vault
      .unresolvedLinks()
      .map((entry) => `${entry.source.path}:${entry.links.map((link) => link.target).join(",")}`)
      .sort(),
    backlinks: vault
      .list()
      .map((note) => `${note.path}<-${vault.backlinks(note.id).map((source) => source.path).sort().join(",")}`)
      .sort(),
  };
}

test("a save appends to the log instead of rewriting the index", () => {
  const dir = tempVault();
  try {
    const vault = new DocumentVault(dir, PASSPHRASE);
    vault.put({ path: "One.md", body: "first" });
    const indexSize = fs.statSync(path.join(dir, "documents", "index.enc")).size;
    const linesBefore = logLines(dir);

    vault.put({ path: "Two.md", body: "second [[One]]" });
    assert.equal(logLines(dir), linesBefore + 1, "the save should have added one record");
    assert.equal(
      fs.statSync(path.join(dir, "documents", "index.enc")).size,
      indexSize,
      "the snapshot must not be rewritten by an ordinary save",
    );

    // Locking folds the log back in, so the vault is self-contained at rest.
    vault.lock();
    assert.equal(fs.existsSync(logPath(dir)), false, "locking should leave no log behind");
  } finally {
    removeTree(dir);
  }
});

test("replaying the log reproduces the index the writing session held", () => {
  const dir = tempVault();
  try {
    const writer = new DocumentVault(dir, PASSPHRASE);
    writer.put({ path: "People/Ada.md", title: "Ada", body: "Works on [[Projects/Alpha]]." });
    writer.put({ path: "Projects/Alpha.md", title: "Alpha", body: "Owned by [[People/Ada]]." });
    writer.put({ path: "Notes/Dangling.md", body: "Points at [[Nowhere]]." });
    writer.put({ path: "People/Ada.md", title: "Ada Lovelace", body: "Renamed, still [[Projects/Alpha]]." });
    const expected = shape(writer);
    assert.ok(logLines(dir) > 1, "the run should have left records to replay");

    // A second reader opens the same vault without the writer having locked,
    // which is the crash-shaped case: snapshot on disk, log not yet folded in.
    const reader = new DocumentVault(dir, PASSPHRASE);
    try {
      assert.deepEqual(shape(reader), expected);
    } finally {
      reader.lock();
    }
    writer.lock();
  } finally {
    removeTree(dir);
  }
});

test("an acknowledged save survives a crash before the snapshot is refreshed", () => {
  const dir = tempVault();
  try {
    const writer = new DocumentVault(dir, PASSPHRASE);
    writer.put({ path: "Kept.md", body: "durable" });
    // No lock(), no compaction: exactly what a killed process leaves behind.
    assert.ok(fs.existsSync(logPath(dir)));

    const reopened = new DocumentVault(dir, PASSPHRASE);
    try {
      assert.equal(reopened.get("Kept.md").body, "durable");
    } finally {
      reopened.lock();
    }
  } finally {
    removeTree(dir);
  }
});

test("a torn final append is discarded, and everything before it is kept", () => {
  const dir = tempVault();
  try {
    const writer = new DocumentVault(dir, PASSPHRASE);
    writer.put({ path: "First.md", body: "one" });
    writer.put({ path: "Second.md", body: "two" });
    const raw = fs.readFileSync(logPath(dir), "utf8");
    // A write that did not finish: the last line has no newline and is cut.
    fs.writeFileSync(logPath(dir), `${raw}{"version":1,"iv":"AAAA`);

    const reopened = new DocumentVault(dir, PASSPHRASE);
    try {
      assert.deepEqual(
        reopened.list().map((note) => note.path).sort(),
        ["First.md", "Second.md"],
      );
    } finally {
      reopened.lock();
    }
  } finally {
    removeTree(dir);
  }
});

test("a record damaged before the end is refused rather than skipped", () => {
  const dir = tempVault();
  try {
    const writer = new DocumentVault(dir, PASSPHRASE);
    writer.put({ path: "First.md", body: "one" });
    writer.put({ path: "Second.md", body: "two" });
    writer.put({ path: "Third.md", body: "three" });
    const lines = fs.readFileSync(logPath(dir), "utf8").split("\n").filter(Boolean);
    // Corrupt a middle record. Silently dropping it would hand back an index
    // that is missing a note the vault still holds.
    const damaged = JSON.parse(lines[1]);
    damaged.ciphertext = `${damaged.ciphertext.slice(0, -4)}AAAA`;
    lines[1] = JSON.stringify(damaged);
    fs.writeFileSync(logPath(dir), `${lines.join("\n")}\n`);

    assert.throws(() => new DocumentVault(dir, PASSPHRASE).list(), /damaged|rebuild/iu);
  } finally {
    removeTree(dir);
  }
});

test("a log left by a crash mid-compaction is stale and is not replayed twice", () => {
  const dir = tempVault();
  try {
    const writer = new DocumentVault(dir, PASSPHRASE);
    writer.put({ path: "One.md", body: "first" });
    const stale = fs.readFileSync(logPath(dir));
    writer.lock(); // compacts: the snapshot now contains the record
    assert.equal(fs.existsSync(logPath(dir)), false);

    // Put the old log back, as a crash between the two steps would.
    fs.writeFileSync(logPath(dir), stale);
    const reopened = new DocumentVault(dir, PASSPHRASE);
    try {
      assert.deepEqual(reopened.list().map((note) => note.path), ["One.md"]);
      assert.equal(reopened.get("One.md").body, "first");
    } finally {
      reopened.lock();
    }
  } finally {
    removeTree(dir);
  }
});

test("the log compacts on its own once it passes the threshold", () => {
  const dir = tempVault();
  try {
    const vault = new DocumentVault(dir, PASSPHRASE);
    const note = vault.put({ path: "Busy.md", body: "0" });
    for (let edit = 1; edit <= COMPACT_AFTER_RECORDS + 2; edit += 1) {
      vault.put({ id: note.id, path: note.path, body: String(edit) });
    }
    assert.ok(
      logLines(dir) <= COMPACT_AFTER_RECORDS,
      `the log should have compacted, found ${logLines(dir)} lines`,
    );
    assert.equal(vault.get(note.id).body, String(COMPACT_AFTER_RECORDS + 2));
    vault.lock();

    const reopened = new DocumentVault(dir, PASSPHRASE);
    try {
      assert.equal(reopened.get(note.id).body, String(COMPACT_AFTER_RECORDS + 2));
    } finally {
      reopened.lock();
    }
  } finally {
    removeTree(dir);
  }
});

test("a removal replays as a removal", () => {
  const dir = tempVault();
  try {
    const writer = new DocumentVault(dir, PASSPHRASE);
    writer.put({ path: "Gone.md", body: "bye" });
    writer.put({ path: "Points.md", body: "See [[Gone]]." });
    writer.remove("Gone.md");
    const expected = shape(writer);

    const reopened = new DocumentVault(dir, PASSPHRASE);
    try {
      assert.deepEqual(shape(reopened), expected);
      assert.deepEqual(reopened.list().map((note) => note.path), ["Points.md"]);
      assert.equal(reopened.unresolvedLinks().length, 1, "the link should now dangle");
    } finally {
      reopened.lock();
    }
  } finally {
    removeTree(dir);
  }
});
