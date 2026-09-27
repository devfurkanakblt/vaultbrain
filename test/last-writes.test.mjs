// When each key-value entry was last written, as the audit trail recorded it.
//
// The catalog stores no timestamps and the .kv format has none, so a fact
// that is overwritten in place looked as fresh as the day it was first
// written. The audit trail already records every CLI and MCP write, signed,
// so discovery reads the date from there instead of changing the encrypted
// format. Only a chain that verifies is trusted.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { appendAudit, lastWrites, readAudit } from "../dist/audit.js";

const PASSPHRASE = "correct horse battery staple";

function vault() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "vault-brain-last-writes-test-"));
}

test("the latest recorded write of each key wins, from the CLI and from an agent", () => {
  const dir = vault();
  appendAudit(dir, { actor: "cli-direct-write", file: "work", key: "PLAN" }, PASSPHRASE);
  appendAudit(dir, { actor: "mcp-agent-write", file: "work", key: "NOTE", agent: "claude", outcome: "allowed" }, PASSPHRASE);
  appendAudit(dir, { actor: "cli-direct-write", file: "work", key: "PLAN" }, PASSPHRASE);
  const log = readAudit(dir);

  const written = lastWrites(dir, PASSPHRASE);

  assert.equal(written.get("work\0PLAN"), log[2].timestamp);
  assert.equal(written.get("work\0NOTE"), log[1].timestamp);
});

test("reads, denials and refused writes are not writes", () => {
  const dir = vault();
  appendAudit(dir, { actor: "mcp-agent", file: "work", key: "READ", agent: "claude", outcome: "allowed" }, PASSPHRASE);
  appendAudit(dir, { actor: "cli-direct", file: "work", key: "READ" }, PASSPHRASE);
  appendAudit(dir, { actor: "mcp-agent-write", file: "work", key: "REFUSED", agent: "claude", outcome: "denied" }, PASSPHRASE);

  assert.equal(lastWrites(dir, PASSPHRASE).size, 0);
});

test("a chain that does not verify yields no dates at all", () => {
  const dir = vault();
  appendAudit(dir, { actor: "cli-direct-write", file: "work", key: "PLAN" }, PASSPHRASE);
  appendAudit(dir, { actor: "cli-direct-write", file: "work", key: "OTHER" }, PASSPHRASE);
  const logPath = path.join(dir, "audit.log");
  const [first, ...rest] = fs.readFileSync(logPath, "utf8").split("\n");
  const forged = { ...JSON.parse(first), timestamp: "2099-01-01T00:00:00.000Z" };
  fs.writeFileSync(logPath, [JSON.stringify(forged), ...rest].join("\n"));

  assert.equal(lastWrites(dir, PASSPHRASE).size, 0, "an edited log must not be able to plant a date");
});

test("a vault with no audit trail yet has no dates and no error", () => {
  assert.equal(lastWrites(vault(), PASSPHRASE).size, 0);
});
