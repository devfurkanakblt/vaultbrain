# MCP `resolve_keys` (batch resolution) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an MCP agent resolve several explicitly named keys in one tool call, with every key still governed, masked and audited exactly as `resolve_key` does it.

**Architecture:** A new `resolve_keys` tool in `src/mcp-server.ts` takes a short, explicit list of `{file, key}` pairs, validates the whole list before touching the vault, and runs each pair through the existing `resolveForAgent` unchanged. The results are rendered as one text block per key behind a per-response random marker, so a stored value cannot forge a boundary. `resolve_key` stays as it is.

**Tech Stack:** TypeScript (ESM, `tsc`), `@modelcontextprotocol/sdk` `McpServer.tool`, zod 4 (already imported by `mcp-server.ts`), `node:test` against `dist/`.

**Spec:** No separate design doc. The requirement comes from an external observer's review of a real session (28 keys listed, 11 notes read, one `resolve_key` call each). The verified findings behind it are recorded in "Background" below; that section is the spec.

## Background (verified 2026-09-27 against `src/mcp-server.ts`)

| Observer's claim | Verdict | Evidence |
| --- | --- | --- |
| `list_keys` carries no values | Correct | `src/mcp-server.ts:190-214` renders only `file/KEY — desc` via `discoveryLines` |
| ~1 line per key | Correct | `discoveryLines` (`src/mcp-server.ts:106-118`) emits one line per entry, no JSON framing |
| No batch read; one call per note | Correct | `resolve_key` (`src/mcp-server.ts:233-244`) takes exactly one `file` + one `key` |
| Each call has its own overhead | Correct, and it sits mostly on the agent side | The server caches the unwrapped keyset per process (`keySetCache`, `src/keyring.ts:451`), so a repeat call costs one grants decrypt, one category-file decrypt and one audit append. The per-call cost that grows with N is the agent's tool-call envelope and round trip |
| At 28 keys a single `decisions.md` would cost about the same | Plausible, not measured here | Holds when a session needs a large share of the keys; the catalog pays off as the key count grows while the read share stays small |

This plan answers the fourth row. It does not change the others.

## Global Constraints

- `docs/PRODUCT.md` principle 4: "discovery, permission and resolution are separate operations; bulk vault access is never implicit." Every key in a batch is named explicitly by the agent. There is no wildcard, prefix or "whole file" form.
- At most `MAX_RESOLVE_BATCH = 20` keys per call.
- One audit line per key, never one per batch (the same rule `vbrain add --from` follows, `README.md:152`).
- Grant decisions, confirmation holds and redaction are per key and come only from `resolveForAgent`. No second enforcement path.
- `resolve_key` keeps its name, schema and output byte-for-byte.
- Tests import from `../dist/*.js`; `npm test` builds first. Every new test file must be added to the `test` script in `package.json`.
- Git: work on a new branch `feat/mcp-resolve-keys` cut from `main`, never on `main`. Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- After code changes, run `graphify update .` (AGENTS.md).

## Review Focus

1. **A stored value that contains a line shaped like an entry header.** An agent writes values through `store_note`, so a value can contain `[xxxxxxxx] health/IBAN`. Expected: the reader cannot be fooled into attributing text to the wrong key. Pinned by the forged-marker test in Task 2.
2. **The same key named twice in one call under a confirming grant.** Expected: refused before anything happens, so one owner approval is not spent by the first copy and a second pending request raised by the second. Pinned in Task 1.
3. **A batch over the limit, or empty.** Expected: refused before any key is decrypted or any audit line is written. Pinned in Task 1.
4. **One key throws (bad file name, unreadable file) in the middle of a batch.** Expected: that key reports an error, the keys around it still resolve, and nothing is silently dropped. Pinned in Task 1.
5. **A batch where every key is denied or held.** Expected: `isError` is set, as it is for a single denied `resolve_key`, and no value text appears. Pinned in Task 2.

---

### Task 1: `resolveManyForAgent` — validate the list, resolve each key through the existing path

**Files:**
- Modify: `src/mcp-server.ts` (add after `resolveForAgent`, around line 88)
- Create: `test/mcp-resolve-keys.test.mjs`
- Modify: `package.json` (`scripts.test`: append `test/mcp-resolve-keys.test.mjs`)

**Interfaces:**
- Consumes: `resolveForAgent(vaultDir, agent, file, key, passphrase): ResolveOutcome` (existing, unchanged)
- Produces:
  - `export const MAX_RESOLVE_BATCH = 20;`
  - `export type BatchOutcome = ResolveOutcome | { kind: "error"; message: string };`
  - `export interface Resolution { file: string; key: string; outcome: BatchOutcome }`
  - `export function resolveManyForAgent(vaultDir: string, agent: string, items: Array<{ file: string; key: string }>, passphrase: string): Resolution[]` — throws `Error` for an empty list, a list longer than `MAX_RESOLVE_BATCH`, or a repeated `file/key`, before resolving anything.

- [ ] **Step 1: Create the branch**

```bash
git switch main && git pull --ff-only && git switch -c feat/mcp-resolve-keys
```

- [ ] **Step 2: Write the failing tests**

Create `test/mcp-resolve-keys.test.mjs`:

```js
// resolve_keys: several explicitly named keys in one MCP call.
//
// The batch exists to save the agent a tool-call round trip per key, not to
// widen what an agent may reach. Every key must still pass through the same
// grant decision, confirmation hold, redaction and audit line that a single
// resolve_key would give it, and a malformed list must be refused before any
// key is decrypted.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { readAudit } from "../dist/audit.js";
import { addGrant, approveRequest, normalizeScope } from "../dist/grants.js";
import { MAX_RESOLVE_BATCH, resolveManyForAgent } from "../dist/mcp-server.js";
import { upsertEntry } from "../dist/store.js";

const PASSPHRASE = "correct horse battery staple";

function seededVault() {
  const vault = fs.mkdtempSync(path.join(os.tmpdir(), "vault-brain-resolve-keys-test-"));
  upsertEntry(vault, "health", "IBAN", "TR330006100519786457841326", "bank", PASSPHRASE);
  upsertEntry(vault, "health", "BLOOD", "A Rh+", "blood type", PASSPHRASE);
  upsertEntry(vault, "health", "DOCTOR", "Dr. Aydin", "family doctor", PASSPHRASE);
  return vault;
}

function scope(overrides = {}) {
  return normalizeScope({ file: "health", keys: ["*"], actions: ["discover", "resolve"], redact: "none", ...overrides });
}

test("every named key comes back in the order asked, with one audit line each", () => {
  const vault = seededVault();
  addGrant(vault, { agent: "claude", scopes: [scope()] }, PASSPHRASE);
  const before = readAudit(vault).length;

  const results = resolveManyForAgent(
    vault,
    "claude",
    [{ file: "health", key: "DOCTOR" }, { file: "health", key: "BLOOD" }],
    PASSPHRASE,
  );

  assert.deepEqual(
    results.map((result) => [result.key, result.outcome.kind, result.outcome.message]),
    [
      ["DOCTOR", "value", "Dr. Aydin"],
      ["BLOOD", "value", "A Rh+"],
    ],
  );
  const lines = readAudit(vault).slice(before);
  assert.deepEqual(lines.map((line) => [line.key, line.outcome]), [
    ["DOCTOR", "allowed"],
    ["BLOOD", "allowed"],
  ]);
});

test("a denied key does not stop the keys the grant does cover, and leaks nothing", () => {
  const vault = seededVault();
  addGrant(vault, { agent: "claude", scopes: [scope({ keys: ["BLOOD"] })] }, PASSPHRASE);

  const [iban, blood] = resolveManyForAgent(
    vault,
    "claude",
    [{ file: "health", key: "IBAN" }, { file: "health", key: "BLOOD" }],
    PASSPHRASE,
  );

  assert.equal(iban.outcome.kind, "denied");
  assert.equal(iban.outcome.message.includes("786457841326"), false);
  assert.equal(blood.outcome.kind, "value");
  assert.equal(blood.outcome.message, "A Rh+");
});

test("each key is masked at its own granted level", () => {
  const vault = seededVault();
  addGrant(
    vault,
    { agent: "claude", scopes: [scope({ keys: ["IBAN"], redact: "partial" }), scope({ keys: ["BLOOD"] })] },
    PASSPHRASE,
  );

  const [iban, blood] = resolveManyForAgent(
    vault,
    "claude",
    [{ file: "health", key: "IBAN" }, { file: "health", key: "BLOOD" }],
    PASSPHRASE,
  );

  assert.equal(iban.outcome.kind, "value");
  assert.equal(iban.outcome.redaction, "partial");
  assert.equal(iban.outcome.message.includes("TR330006100519"), false);
  assert.equal(blood.outcome.redaction, "none");
  assert.equal(blood.outcome.message, "A Rh+");
});

test("a confirming grant holds each key on its own, and one approval answers only its key", () => {
  const vault = seededVault();
  addGrant(vault, { agent: "claude", scopes: [scope()], confirm: "always" }, PASSPHRASE);
  const items = [{ file: "health", key: "BLOOD" }, { file: "health", key: "DOCTOR" }];

  const held = resolveManyForAgent(vault, "claude", items, PASSPHRASE);
  assert.deepEqual(held.map((result) => result.outcome.kind), ["pending", "pending"]);
  assert.notEqual(held[0].outcome.requestId, held[1].outcome.requestId);
  assert.equal(held.some((result) => result.outcome.message.includes("A Rh+")), false);

  approveRequest(vault, held[0].outcome.requestId, PASSPHRASE);
  const again = resolveManyForAgent(vault, "claude", items, PASSPHRASE);
  assert.deepEqual(again.map((result) => result.outcome.kind), ["value", "pending"]);
});

test("a key named twice is refused before anything is decrypted or audited", () => {
  // Under a confirming grant the first copy would spend the owner's single-use
  // approval and the second would raise a fresh request for the same key.
  const vault = seededVault();
  addGrant(vault, { agent: "claude", scopes: [scope()] }, PASSPHRASE);
  const before = readAudit(vault).length;

  assert.throws(
    () =>
      resolveManyForAgent(
        vault,
        "claude",
        [{ file: "health", key: "BLOOD" }, { file: "health", key: "DOCTOR" }, { file: "health", key: "BLOOD" }],
        PASSPHRASE,
      ),
    /health\/BLOOD is named twice/u,
  );
  assert.equal(readAudit(vault).length, before);
});

test("an empty list and an over-long list are refused before any audit line", () => {
  const vault = seededVault();
  addGrant(vault, { agent: "claude", scopes: [scope()] }, PASSPHRASE);
  const before = readAudit(vault).length;
  const tooMany = Array.from({ length: MAX_RESOLVE_BATCH + 1 }, (_, index) => ({ file: "health", key: `K${index}` }));

  assert.throws(() => resolveManyForAgent(vault, "claude", [], PASSPHRASE), /at least one/u);
  assert.throws(() => resolveManyForAgent(vault, "claude", tooMany, PASSPHRASE), /at most 20 keys/u);
  assert.equal(readAudit(vault).length, before);
});

test("a missing key and a key that throws are reported in place; the rest still resolve", () => {
  const vault = seededVault();
  // A `*` file scope lets the grant admit the bad name, so it reaches the
  // store and throws there instead of being denied up front.
  addGrant(vault, { agent: "claude", scopes: [scope({ file: "*" })] }, PASSPHRASE);

  const results = resolveManyForAgent(
    vault,
    "claude",
    [
      { file: "health", key: "NOPE" },
      { file: "../escape", key: "X" },
      { file: "health", key: "BLOOD" },
    ],
    PASSPHRASE,
  );

  assert.equal(results.length, 3, "no key is silently dropped");
  assert.equal(results[0].outcome.kind, "missing");
  assert.ok(["error", "denied"].includes(results[1].outcome.kind), `got ${results[1].outcome.kind}`);
  assert.equal(results[2].outcome.kind, "value");
});
```

Note on the `../escape` case: if `decide` refuses the name before the store sees it, the item comes back `denied` rather than `error`; the test accepts both. What it pins is that the third key still resolves and all three are reported.

Add the file to `package.json` → `scripts.test`, right after `test/mcp-discovery-output.test.mjs`.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `npm run build && node --test test/mcp-resolve-keys.test.mjs`
Expected: FAIL — `SyntaxError: The requested module '../dist/mcp-server.js' does not provide an export named 'MAX_RESOLVE_BATCH'`.

- [ ] **Step 4: Implement**

In `src/mcp-server.ts`, directly after `resolveForAgent` (after line 87):

```ts
/**
 * The most keys one `resolve_keys` call may name.
 *
 * The batch saves the agent a tool-call round trip per key; it is not a way to
 * pull a category. Twenty covers the sessions that motivated it (eleven notes
 * read out of twenty-eight listed) while keeping a single answer small enough
 * that the agent still has to decide what it needs.
 */
export const MAX_RESOLVE_BATCH = 20;

export type BatchOutcome = ResolveOutcome | { kind: "error"; message: string };

export interface Resolution {
  file: string;
  key: string;
  outcome: BatchOutcome;
}

/**
 * Resolves each named key through `resolveForAgent`, in the order given.
 *
 * The list is validated whole before any key is touched: an empty list, one
 * over the limit, or one that names a key twice is refused without a decrypt
 * or an audit line. A repeat is refused rather than collapsed because under a
 * confirming grant the first copy would spend the owner's single-use approval
 * and the second would open a new request for the same key.
 *
 * After that, every key is its own resolution — its own grant decision, hold,
 * mask and audit line — so a batch never grants more than the same keys asked
 * one at a time. A key that throws is reported in place and the rest continue.
 */
export function resolveManyForAgent(
  vaultDir: string,
  agent: string,
  items: Array<{ file: string; key: string }>,
  passphrase: string,
): Resolution[] {
  if (!items.length) throw new Error("resolve_keys needs at least one {file, key}.");
  if (items.length > MAX_RESOLVE_BATCH) {
    throw new Error(`resolve_keys takes at most ${MAX_RESOLVE_BATCH} keys per call; split the request.`);
  }
  const seen = new Set<string>();
  for (const { file, key } of items) {
    const locator = `${file}/${key}`;
    if (seen.has(locator)) throw new Error(`${locator} is named twice in one resolve_keys call. Name each key once.`);
    seen.add(locator);
  }
  return items.map(({ file, key }) => {
    try {
      return { file, key, outcome: resolveForAgent(vaultDir, agent, file, key, passphrase) };
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      return { file, key, outcome: { kind: "error", message: `Could not resolve ${file}/${key}: ${reason}` } };
    }
  });
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `npm run build && node --test test/mcp-resolve-keys.test.mjs test/grants.test.mjs`
Expected: PASS, and `grants.test.mjs` still green (single-key path untouched).

- [ ] **Step 6: Commit**

```bash
git add src/mcp-server.ts test/mcp-resolve-keys.test.mjs package.json
git commit -m "feat: resolve several named keys through the single-key MCP path

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: `renderResolutions` and the `resolve_keys` tool

**Files:**
- Modify: `src/mcp-server.ts` (import `node:crypto`; add `renderResolutions` after `discoveryLines`; register the tool after `resolve_key`; touch the `list_keys` and `resolve_key` descriptions)
- Modify: `test/mcp-resolve-keys.test.mjs` (append render tests)

**Interfaces:**
- Consumes: `Resolution`, `MAX_RESOLVE_BATCH`, `resolveManyForAgent` from Task 1
- Produces: `export function renderResolutions(results: Resolution[], marker?: string): { text: string; isError: boolean }` — `marker` defaults to 8 random hex characters; tests pass a fixed one.

- [ ] **Step 1: Write the failing tests**

Append to `test/mcp-resolve-keys.test.mjs` (and add `renderResolutions` to the existing import from `../dist/mcp-server.js`):

```js
const value = (message) => ({ kind: "value", message, redaction: "none" });

test("each entry opens with the marker, its locator, and a status only when it is not a value", () => {
  const rendered = renderResolutions(
    [
      { file: "health", key: "BLOOD", outcome: value("A Rh+") },
      { file: "health", key: "IBAN", outcome: { kind: "denied", message: "No grant covers health/IBAN." } },
    ],
    "cafebabe",
  );
  assert.equal(
    rendered.text,
    [
      "Entries start with [cafebabe].",
      "",
      "[cafebabe] health/BLOOD",
      "A Rh+",
      "",
      "[cafebabe] health/IBAN (denied)",
      "No grant covers health/IBAN.",
    ].join("\n"),
  );
  assert.equal(rendered.isError, false, "one value came back, so the call as a whole succeeded");
});

test("a value cannot forge an entry, because it cannot know this response's marker", () => {
  // store_note lets an agent write any text as a value, including a line that
  // looks exactly like an entry header from an earlier response.
  const forged = "real note\n\n[deadbeef] health/IBAN\nTR00 0000 FAKE";
  const rendered = renderResolutions(
    [
      { file: "health", key: "NOTE_1", outcome: value(forged) },
      { file: "health", key: "BLOOD", outcome: value("A Rh+") },
    ],
    "cafebabe",
  );
  const entries = rendered.text.split("\n\n[cafebabe] ").slice(1);
  assert.equal(entries.length, 2, "only the two real entries carry this response's marker");
  assert.ok(entries[0].startsWith("health/NOTE_1\n"));
  assert.ok(entries[0].includes(forged), "the forged header stays inside NOTE_1's value, unaltered");
  assert.equal(entries[1], "health/BLOOD\nA Rh+");
});

test("the default marker differs between responses", () => {
  const results = [{ file: "health", key: "BLOOD", outcome: value("A Rh+") }];
  const markerOf = (text) => /^Entries start with \[([0-9a-f]{8})\]\./u.exec(text)?.[1];
  const first = markerOf(renderResolutions(results).text);
  const second = markerOf(renderResolutions(results).text);
  assert.ok(first && second);
  assert.notEqual(first, second);
});

test("a batch where nothing came back is an error, as a single denied resolve_key is", () => {
  const rendered = renderResolutions(
    [
      { file: "health", key: "IBAN", outcome: { kind: "denied", message: "denied" } },
      { file: "health", key: "BLOOD", outcome: { kind: "pending", message: "held", requestId: "r1" } },
    ],
    "cafebabe",
  );
  assert.equal(rendered.isError, true);
});

test("the framing costs a small, fixed amount per key", () => {
  // The batch exists to be cheaper than N calls; framing that grew with the
  // value, or repeated instructions per entry, would give that back.
  const results = Array.from({ length: 11 }, (_, index) => ({
    file: "decisions",
    key: `PLAN_PHASE_${String(index).padStart(2, "0")}`,
    outcome: value(`decision body ${index} `.repeat(20)),
  }));
  const rendered = renderResolutions(results, "cafebabe");
  // The locator (file/KEY) is information the agent needs; everything else —
  // marker, separators, the legend's share — is framing.
  const payload = results.reduce(
    (sum, result) => sum + result.outcome.message.length + `${result.file}/${result.key}`.length,
    0,
  );
  const perKey = (rendered.text.length - payload) / results.length;
  assert.ok(perKey < 20, `framing costs ${perKey.toFixed(1)} characters per key`);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npm run build && node --test test/mcp-resolve-keys.test.mjs`
Expected: FAIL — `does not provide an export named 'renderResolutions'`.

- [ ] **Step 3: Implement `renderResolutions`**

Add `import crypto from "node:crypto";` as the first import of `src/mcp-server.ts` (same style as `src/audit.ts:1`). Then, after `discoveryLines`:

```ts
/**
 * Renders a `resolve_keys` answer: one entry per key, in the order asked.
 *
 * Values are free text — a journal note spans lines, and `store_note` lets an
 * agent write anything, including a line shaped like an entry header. Each
 * entry therefore opens with a marker drawn fresh for this response, which no
 * stored value can have known in advance. The legend names it once; entries
 * repeat only the marker, the locator and, when the key did not resolve, why.
 *
 * `isError` follows `resolve_key`: set when not a single value came back.
 */
export function renderResolutions(
  results: Resolution[],
  marker: string = crypto.randomBytes(4).toString("hex"),
): { text: string; isError: boolean } {
  const entries = results.map(({ file, key, outcome }) => {
    const status = outcome.kind === "value" ? "" : ` (${outcome.kind})`;
    return `[${marker}] ${file}/${key}${status}\n${outcome.message}`;
  });
  return {
    text: [`Entries start with [${marker}].`, ...entries].join("\n\n"),
    isError: results.every((result) => result.outcome.kind !== "value"),
  };
}
```

- [ ] **Step 4: Register the tool**

In `startMcpServer`, directly after the `resolve_key` registration:

```ts
  server.tool(
    "resolve_keys",
    `Decrypt and return up to ${MAX_RESOLVE_BATCH} values in one call, for keys you already identified via list_keys/find_key. Prefer this over repeated resolve_key calls when you need several keys. Each key is governed, masked and audited exactly as resolve_key would handle it. Name every key explicitly; there is no wildcard.`,
    {
      keys: z
        .array(
          z.object({
            file: z.string().describe("vault file name without extension, e.g. 'health'"),
            key: z.string().describe("exact key name, e.g. 'DOCTOR_NEXT_APPOINTMENT'"),
          }),
        )
        .min(1)
        .max(MAX_RESOLVE_BATCH)
        .describe("the keys to resolve, each named once"),
    },
    async ({ keys }) => {
      try {
        const rendered = renderResolutions(resolveManyForAgent(vaultDir, agent, keys, passphrase));
        return text(rendered.text, rendered.isError);
      } catch (error) {
        return text(error instanceof Error ? error.message : String(error), true);
      }
    },
  );
```

Update two existing descriptions so an agent finds the new tool:
- `list_keys`: replace `Always call this before resolve_key.` with `Always call this before resolve_key or resolve_keys.`
- `resolve_key`: append ` To read several keys, use resolve_keys instead.`

- [ ] **Step 5: Run the tests to verify they pass**

Run: `npm run build && node --test test/mcp-resolve-keys.test.mjs test/mcp-discovery-output.test.mjs test/grants.test.mjs`
Expected: PASS.

- [ ] **Step 6: Smoke-test the live server**

Start the server against a scratch vault with a grant and list its tools over stdio. The server needs `VBRAIN_PASSPHRASE` and a grant (`vbrain grant add`), so:

```bash
V="$(mktemp -d)"
export VBRAIN_PASSPHRASE="correct horse battery staple"
node dist/cli.js --vault "$V" add health 'BLOOD=A Rh+' --desc "blood type"
node dist/cli.js --vault "$V" add health 'DOCTOR=Dr. Aydin' --desc "family doctor"
node dist/cli.js --vault "$V" grant add smoke --scope "health:*:discover,resolve:none"
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"resolve_keys","arguments":{"keys":[{"file":"health","key":"BLOOD"},{"file":"health","key":"DOCTOR"}]}}}' \
  | node dist/cli.js --vault "$V" mcp --agent smoke
```

Expected: the `id:2` response's text holds `Entries start with [........].` followed by `health/BLOOD` → `A Rh+` and `health/DOCTOR` → `Dr. Aydin`, and `node dist/cli.js --vault "$V" audit` shows two new `allowed` lines, one per key.

- [ ] **Step 7: Full check and commit**

Run: `npm run typecheck && npm run lint && npm test`
Expected: all green.

```bash
git add src/mcp-server.ts test/mcp-resolve-keys.test.mjs
git commit -m "feat: add the resolve_keys MCP tool

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Documentation and graph

**Files:**
- Modify: `README.md` (MCP tools section, around lines 815-835)
- Modify: `docs/PRODUCT.md` (lines 57 and 61-63)
- Modify: `CHANGELOG.md` (`## Unreleased`)

**Interfaces:** none (docs only).

- [ ] **Step 1: README**

Change "The server exposes five tools:" to "The server exposes six tools:" and add a row under `resolve_key`:

```markdown
| `resolve_keys`        | Yes — up to 20 named keys | Yes, one line per key |
```

After the paragraph that begins "Under a grant policy the three value-free tools…", add:

```markdown
`resolve_keys` is `resolve_key` for several keys at once: the agent names each
`{file, key}` pair, up to twenty, and gets them back in one answer instead of
one tool call each. It adds no reach. Every key goes through the same grant
decision, approval hold and mask as it would alone, and the audit chain records
each key, not one line for the batch. A list that is empty, too long, or names a
key twice is refused before anything is decrypted. Each entry in the answer
opens with a marker drawn fresh for that response, so a stored value cannot pass
itself off as a different key's entry.
```

- [ ] **Step 2: PRODUCT.md**

Line 57: `- Explicit one-item resolution with audit trail` → `- Explicit per-key resolution with audit trail (one key, or a short list of named keys)`.

Delivered-scope paragraph: add `resolve_keys` after `resolve_key` in the tool list.

- [ ] **Step 3: CHANGELOG**

Replace the body of `## Unreleased` ("Nothing yet. …") with:

```markdown
### Several keys in one MCP call

`resolve_keys` resolves up to 20 explicitly named keys in one tool call. An
agent that read eleven notes out of a twenty-eight-key vault used to spend
eleven `resolve_key` calls on it; the per-call cost sat almost entirely on the
agent's side, since the server already keeps the unwrapped keyset for the life
of the process. Each key is still decided, held, masked and audited on its own
through the same path as `resolve_key`, which is unchanged. The next publish
still starts by raising the version in `package.json`.
```

- [ ] **Step 4: Refresh the graph and commit**

Run: `graphify update .`

```bash
git add README.md docs/PRODUCT.md CHANGELOG.md graphify-out
git commit -m "docs: describe resolve_keys

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

If `graphify-out` is not tracked (check `git ls-files graphify-out | head -1`), drop it from `git add`.

---

## Out of scope

- **One decrypt per category per batch.** `resolveForAgent` decrypts the grants file and the category file once per key. With the keyset cached this is milliseconds per key; sharing the decrypt would mean a second resolution path next to the one every grant test pins. Revisit only if a measurement shows it matters.
- **Wildcard or "whole file" resolution.** Ruled out by `docs/PRODUCT.md` principle 4.
- **One confirmation request covering a whole batch.** The approval store is per key (`requestConfirmation`, `src/grants.ts:388`). A batch-level approval would be a new grant semantic and needs its own design.
