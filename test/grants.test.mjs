import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { appendAudit, readAudit, verifyAudit } from "../dist/audit.js";
import {
  addGrant,
  approveRequest,
  consumeApproval,
  decide,
  denyRequest,
  filterDiscoverable,
  grantsExist,
  listGrants,
  loadGrants,
  matchesKey,
  normalizeScope,
  pendingRequests,
  requestConfirmation,
  revokeGrant,
} from "../dist/grants.js";
import { describeValue, redactValue } from "../dist/redaction.js";
import { resolveForAgent } from "../dist/mcp-server.js";
import { upsertEntry } from "../dist/store.js";

const PASSPHRASE = "correct horse battery staple";

function tempVault() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "vault-brain-grants-test-"));
}

function scope(overrides = {}) {
  return normalizeScope({
    file: "health",
    keys: ["*"],
    actions: ["discover", "resolve"],
    redact: "none",
    ...overrides,
  });
}

test("a vault with no grant file denies access by default", () => {
  const vault = tempVault();
  assert.equal(grantsExist(vault), false);
  const decision = decide(null, { agent: "claude", action: "resolve", file: "health", key: "IBAN" });
  assert.equal(decision.allowed, false);
  assert.equal(decision.ungoverned, true);
  assert.equal(decision.redact, "full");
});

test("the first grant closes the vault to every other agent", () => {
  const vault = tempVault();
  addGrant(vault, { agent: "claude", scopes: [scope()] }, PASSPHRASE);
  const policy = loadGrants(vault, PASSPHRASE);

  assert.equal(decide(policy, { agent: "claude", action: "resolve", file: "health", key: "IBAN" }).allowed, true);
  const stranger = decide(policy, { agent: "other-agent", action: "resolve", file: "health", key: "IBAN" });
  assert.equal(stranger.allowed, false);
  assert.equal(stranger.redact, "full");
  assert.match(stranger.reason, /has no grant in this vault/u);
});

test("a scope narrows by file, key pattern and action", () => {
  const vault = tempVault();
  addGrant(vault, { agent: "claude", scopes: [scope({ keys: ["NOTE_*", "IBAN"], actions: ["resolve"] })] }, PASSPHRASE);
  const policy = loadGrants(vault, PASSPHRASE);
  const ask = (over) =>
    decide(policy, { agent: "claude", action: "resolve", file: "health", key: "IBAN", ...over }).allowed;

  assert.equal(ask({}), true);
  assert.equal(ask({ key: "NOTE_20260830_120000_visit" }), true);
  assert.equal(ask({ key: "CARD_NUMBER" }), false, "a key outside the patterns stays out");
  assert.equal(ask({ file: "finance" }), false, "another category stays out");
  assert.equal(ask({ action: "store" }), false, "an action the scope omits stays out");
  assert.equal(ask({ action: "discover" }), false, "resolve alone does not imply discovery");
});

test("key patterns match exactly, by prefix, or wholesale", () => {
  assert.equal(matchesKey("*", "ANYTHING"), true);
  assert.equal(matchesKey("NOTE_*", "NOTE_2026"), true);
  assert.equal(matchesKey("NOTE_*", "NOTES"), false);
  assert.equal(matchesKey("IBAN", "IBAN"), true);
  assert.equal(matchesKey("IBAN", "IBAN2"), false);
});

test("an expired grant stops working without being revoked", () => {
  const vault = tempVault();
  addGrant(
    vault,
    { agent: "claude", scopes: [scope()], expiresAt: new Date(Date.now() + 60_000).toISOString() },
    PASSPHRASE,
  );
  const policy = loadGrants(vault, PASSPHRASE);
  const request = { agent: "claude", action: "resolve", file: "health", key: "IBAN" };

  assert.equal(decide(policy, request).allowed, true);
  assert.equal(
    decide(policy, { ...request, now: new Date(Date.now() + 120_000) }).allowed,
    false,
    "the grant lapses on its own clock",
  );
});

test("revoking takes effect immediately and drops that agent's approvals", () => {
  const vault = tempVault();
  const created = addGrant(vault, { agent: "claude", scopes: [scope()], confirm: "always" }, PASSPHRASE);
  const request = requestConfirmation(vault, { agent: "claude", file: "health", key: "IBAN" }, PASSPHRASE);
  approveRequest(vault, request.id, PASSPHRASE);

  revokeGrant(vault, created.id.slice(0, 8), PASSPHRASE);

  assert.equal(listGrants(vault, PASSPHRASE)[0].revokedAt !== null, true);
  assert.equal(
    decide(loadGrants(vault, PASSPHRASE), {
      agent: "claude",
      action: "resolve",
      file: "health",
      key: "IBAN",
    }).allowed,
    false,
  );
  assert.equal(
    consumeApproval(vault, { agent: "claude", file: "health", key: "IBAN" }, PASSPHRASE),
    false,
    "a revoked grant must not leave a usable approval behind",
  );
});

test("the strictest redaction among matching scopes is the one applied", () => {
  const vault = tempVault();
  addGrant(vault, { agent: "claude", scopes: [scope({ redact: "partial" })] }, PASSPHRASE);
  addGrant(vault, { agent: "claude", scopes: [scope({ file: "*", keys: ["*"], redact: "none" })] }, PASSPHRASE);
  const decision = decide(loadGrants(vault, PASSPHRASE), {
    agent: "claude",
    action: "resolve",
    file: "health",
    key: "IBAN",
  });

  assert.equal(decision.allowed, true);
  assert.equal(decision.redact, "partial", "a broad convenience grant cannot widen a masked key");
});

test("a confirmation approval is single-use", () => {
  const vault = tempVault();
  addGrant(vault, { agent: "claude", scopes: [scope()], confirm: "always" }, PASSPHRASE);
  const policy = loadGrants(vault, PASSPHRASE);
  const decision = decide(policy, {
    agent: "claude",
    action: "resolve",
    file: "health",
    key: "IBAN",
  });
  assert.equal(decision.requiresConfirmation, true);

  const target = { agent: "claude", file: "health", key: "IBAN" };
  assert.equal(consumeApproval(vault, target, PASSPHRASE), false, "nothing is approved yet");

  const request = requestConfirmation(vault, target, PASSPHRASE);
  assert.equal(pendingRequests(vault, PASSPHRASE).length, 1);
  assert.equal(
    requestConfirmation(vault, target, PASSPHRASE).id,
    request.id,
    "a repeated ask reuses the open request rather than flooding the owner",
  );

  approveRequest(vault, request.id, PASSPHRASE);
  assert.equal(pendingRequests(vault, PASSPHRASE).length, 0);
  assert.equal(consumeApproval(vault, target, PASSPHRASE), true);
  assert.equal(consumeApproval(vault, target, PASSPHRASE), false, "one yes is not a standing permission");
});

test("denying a request removes it without approving anything", () => {
  const vault = tempVault();
  addGrant(vault, { agent: "claude", scopes: [scope()], confirm: "always" }, PASSPHRASE);
  const target = { agent: "claude", file: "health", key: "IBAN" };
  const request = requestConfirmation(vault, target, PASSPHRASE);

  denyRequest(vault, request.id, PASSPHRASE);

  assert.equal(pendingRequests(vault, PASSPHRASE).length, 0);
  assert.equal(consumeApproval(vault, target, PASSPHRASE), false);
});

test("discovery is narrowed to the key names a grant covers", () => {
  const vault = tempVault();
  addGrant(vault, { agent: "claude", scopes: [scope({ keys: ["NOTE_*"], actions: ["discover"] })] }, PASSPHRASE);
  const entries = [
    { key: "NOTE_20260830_090000_visit", desc: "doctor" },
    { key: "IBAN", desc: "bank" },
  ];

  const visible = filterDiscoverable(loadGrants(vault, PASSPHRASE), "claude", "health", entries);

  assert.deepEqual(
    visible.map((entry) => entry.key),
    ["NOTE_20260830_090000_visit"],
  );
  assert.equal(filterDiscoverable(null, "claude", "health", entries).length, 0);
});

test("the grant file is encrypted at rest and refuses a wrong passphrase", () => {
  const vault = tempVault();
  addGrant(vault, { agent: "claude", scopes: [scope()] }, PASSPHRASE);
  const raw = fs.readFileSync(path.join(vault, "grants.enc"), "utf8");

  assert.equal(raw.includes("claude"), false, "an agent name is metadata, and stays encrypted too");
  assert.throws(() => loadGrants(vault, "wrong passphrase"));
});

test("an invalid scope is rejected before it can be stored", () => {
  const vault = tempVault();
  assert.throws(
    () => normalizeScope({ file: "../escape", keys: ["*"], actions: ["resolve"], redact: "none" }),
    /Invalid vault category/u,
  );
  assert.throws(
    () => normalizeScope({ file: "health", keys: ["a b"], actions: ["resolve"], redact: "none" }),
    /Invalid key pattern/u,
  );
  assert.throws(
    () => normalizeScope({ file: "health", keys: ["*"], actions: [], redact: "none" }),
    /at least one action/u,
  );
  assert.throws(
    () => normalizeScope({ file: "health", keys: ["*"], actions: ["resolve"], redact: "loud" }),
    /Unknown redaction level/u,
  );
  assert.throws(() => addGrant(vault, { agent: "bad/name", scopes: [scope()] }, PASSPHRASE), /Invalid agent name/u);
  assert.throws(() => addGrant(vault, { agent: "claude", scopes: [] }, PASSPHRASE), /between 1 and/u);
});

test("partial redaction keeps a tail and full redaction keeps nothing", () => {
  const iban = "TR330006100519786457841326";

  assert.equal(redactValue(iban, "none"), iban);
  const partial = redactValue(iban, "partial");
  assert.equal(partial.endsWith("1326"), true, "enough to confirm a match");
  assert.equal(partial.includes("TR3300061005"), false, "not enough to use");

  const full = redactValue(iban, "full");
  assert.match(full, /^\[redacted: an IBAN, 26 characters\]$/u);
  assert.equal(full.includes("1326"), false);
});

test("redaction masks identifiers embedded in a sentence", () => {
  const masked = redactValue("Reach me at ada@example.com about card 4111 1111 1111 1111.", "partial");

  assert.equal(masked.includes("ada@example.com"), false);
  assert.equal(masked.includes("4111 1111 1111 1111"), false);
  assert.equal(masked.startsWith("Reach me at "), true, "the surrounding sentence still reads");
});

test("a short value with no recognizable identifier is still masked", () => {
  const masked = redactValue("yes", "partial");
  assert.equal(masked.includes("yes"), false);
  assert.match(describeValue("yes"), /^\[redacted: a stored value, 3 characters\]$/u);
});

test("audit entries carrying grant fields sign and verify, next to legacy ones", () => {
  const vault = tempVault();
  appendAudit(vault, { actor: "cli-direct", file: "health", key: "IBAN" }, PASSPHRASE);
  appendAudit(
    vault,
    {
      actor: "mcp-agent",
      file: "health",
      key: "IBAN",
      agent: "claude",
      grant: "1f2e3d4c",
      redaction: "partial",
      outcome: "allowed",
    },
    PASSPHRASE,
  );
  appendAudit(
    vault,
    { actor: "mcp-agent", file: "finance", key: "CARD", agent: "claude", outcome: "denied" },
    PASSPHRASE,
  );

  const verification = verifyAudit(vault, PASSPHRASE);
  assert.equal(verification.valid, true);
  assert.equal(verification.signedEntries, 3);

  const entries = readAudit(vault);
  assert.equal(entries[1].redaction, "partial");
  assert.equal(entries[2].outcome, "denied");
  assert.equal(
    entries.some((entry) => entry.value !== undefined),
    false,
    "no value ever enters the log",
  );
});

test("tampering with a recorded redaction level breaks the audit chain", () => {
  const vault = tempVault();
  appendAudit(
    vault,
    { actor: "mcp-agent", file: "health", key: "IBAN", agent: "claude", redaction: "full", outcome: "allowed" },
    PASSPHRASE,
  );
  const logPath = path.join(vault, "audit.log");
  fs.writeFileSync(logPath, fs.readFileSync(logPath, "utf8").replace('"full"', '"none"'));

  assert.equal(verifyAudit(vault, PASSPHRASE).valid, false);
});

test("deleting or truncating an initialized audit log is detected", () => {
  const vault = tempVault();
  appendAudit(vault, { actor: "cli-direct", file: "health", key: "IBAN" }, PASSPHRASE);
  fs.writeFileSync(path.join(vault, "audit.log"), "");

  const verification = verifyAudit(vault, PASSPHRASE);
  assert.equal(verification.valid, false);
  assert.match(verification.error, /missing or truncated/u);
});

test("removing the authenticated audit head cannot hide a truncated tail", () => {
  const vault = tempVault();
  appendAudit(vault, { actor: "cli-direct", file: "health", key: "IBAN" }, PASSPHRASE);
  appendAudit(vault, { actor: "cli-direct", file: "health", key: "BLOOD" }, PASSPHRASE);
  const logPath = path.join(vault, "audit.log");
  const [firstEntry] = fs.readFileSync(logPath, "utf8").trim().split("\n");
  fs.writeFileSync(logPath, `${firstEntry}\n`);
  fs.rmSync(path.join(vault, "audit.head.json"));

  const verification = verifyAudit(vault, PASSPHRASE);
  assert.equal(verification.valid, false);
  assert.match(verification.error, /head is missing/u);
});

function seededVault() {
  const vault = tempVault();
  upsertEntry(vault, "health", "IBAN", "TR330006100519786457841326", "bank", PASSPHRASE);
  upsertEntry(vault, "health", "BLOOD", "A Rh+", "blood type", PASSPHRASE);
  return vault;
}

test("an MCP resolution is denied outright when no grant covers it", () => {
  const vault = seededVault();
  addGrant(vault, { agent: "claude", scopes: [scope({ keys: ["BLOOD"] })] }, PASSPHRASE);

  const outcome = resolveForAgent(vault, "claude", "health", "IBAN", PASSPHRASE);

  assert.equal(outcome.kind, "denied");
  assert.equal(outcome.message.includes("786457841326"), false, "a denial never leaks the value");
  const denial = readAudit(vault).at(-1);
  assert.equal(denial.outcome, "denied");
  assert.equal(denial.agent, "claude");
});

test("an MCP resolution comes back masked at the granted level", () => {
  const vault = seededVault();
  addGrant(vault, { agent: "claude", scopes: [scope({ keys: ["IBAN"], redact: "partial" })] }, PASSPHRASE);

  const outcome = resolveForAgent(vault, "claude", "health", "IBAN", PASSPHRASE);

  assert.equal(outcome.kind, "value");
  assert.equal(outcome.redaction, "partial");
  assert.equal(outcome.message.includes("TR330006100519"), false);
  assert.equal(outcome.message.includes("1326"), true, "the tail survives so the agent can confirm the field");
  assert.match(outcome.message, /masked by the vault's grant policy/u);
  assert.equal(readAudit(vault).at(-1).redaction, "partial");
});

test("an ungoverned vault refuses MCP resolution", () => {
  const vault = seededVault();

  const outcome = resolveForAgent(vault, "anyone", "health", "IBAN", PASSPHRASE);

  assert.equal(outcome.kind, "denied");
  assert.equal(outcome.message.includes("TR330006100519786457841326"), false);
});

test("a confirming grant holds the first call and answers the second", () => {
  const vault = seededVault();
  addGrant(vault, { agent: "claude", scopes: [scope()], confirm: "always" }, PASSPHRASE);

  const held = resolveForAgent(vault, "claude", "health", "BLOOD", PASSPHRASE);
  assert.equal(held.kind, "pending");
  assert.equal(held.message.includes("A Rh+"), false, "nothing leaks while the owner decides");
  assert.equal(readAudit(vault).at(-1).outcome, "pending");

  approveRequest(vault, held.requestId, PASSPHRASE);
  const answered = resolveForAgent(vault, "claude", "health", "BLOOD", PASSPHRASE);
  assert.equal(answered.kind, "value");
  assert.equal(answered.message, "A Rh+");

  const replay = resolveForAgent(vault, "claude", "health", "BLOOD", PASSPHRASE);
  assert.equal(replay.kind, "pending", "the spent approval does not answer a second call");
});

test("a revoked grant stops the very next resolution", () => {
  const vault = seededVault();
  const created = addGrant(vault, { agent: "claude", scopes: [scope()] }, PASSPHRASE);
  assert.equal(resolveForAgent(vault, "claude", "health", "BLOOD", PASSPHRASE).kind, "value");

  revokeGrant(vault, created.id, PASSPHRASE);

  assert.equal(resolveForAgent(vault, "claude", "health", "BLOOD", PASSPHRASE).kind, "denied");
});
