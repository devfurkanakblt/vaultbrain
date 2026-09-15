# Phase 16.6 follow-up — non-ASCII removal and copy in tests

The scripts follow-up
([`2026-09-15-phase-16-6-non-ascii-scripts.md`](2026-09-15-phase-16-6-non-ascii-scripts.md))
recorded, and did not fix, that files under `test/` still use Node's rm/cp
family. This plan closes that.

**The defect.** Measured on Windows 11 with Node v24.11.1: when any path
component is non-ASCII, every `fs.rmSync` call removes nothing and returns
normally, and `fs.cpSync({ recursive: true })` aborts the process with
0xC0000409. Test roots come from `os.tmpdir()`, which is ASCII on this host,
so the suite passes here; on a host whose temp directory has a non-ASCII
component (a Windows user name with `ğ`, say) cleanup would silently leak and
every recursive copy would kill the test process.

**Measured scope at `8fe108d`.** Outside `test/fs-removal.test.mjs` (whose
probe strings name the banned calls on purpose): about 300 `rmSync` call sites
(229 of them `{ recursive: true, force: true }`), 32 recursive `cpSync` calls,
and one `node:fs/promises` import (`test/package.test.mjs`), across 34 files.

## Global Constraints

- Code, comments, commits and docs in English.
- Tests take the helpers from `scripts/fs-tree.mjs` (`removeTree`,
  `removeFile`, `copyTree`). A test file that already imports `removeTree`
  from `../dist/fs-tree.js` keeps that import; if it also needs `copyTree`, it
  imports `copyTree` from `../scripts/fs-tree.mjs`.
- Conversion rules, applied per call site:
  - `rmSync(x, { recursive: true, force: true })` → `removeTree(x)`.
  - `rmSync(x, { force: true })` on a file → `removeFile(x)`.
  - `rmSync(x)` with no options (a file the test expects to exist) →
    `fs.unlinkSync(x)`, so a missing file still throws.
  - `rmSync(x, { recursive: true })` without `force` → `removeTree(x)` only if
    the test does not depend on a throw for a missing target; otherwise keep
    the throw (e.g. `fs.lstatSync(x)` first). Flag any such site in the report.
  - `cpSync(a, b, { recursive: true })` → `copyTree(a, b)`.
  - `node:fs/promises` imports → `fs.promises.<name>` through the existing
    default `fs` import (none of those names is rm/cp).
- Change no test's intent, assertion, name or ordering. No retries, no
  swallowed errors.
- Comments in converted files must not spell the banned names either; reword
  to "Node's recursive removal helper" style, as `src/fs-tree.ts` does.
- A single exemption from the scan is allowed: `test/fs-removal.test.mjs`,
  whose `MUST_MATCH` probes must spell the banned calls. No other file is
  exempt.
- Every touched test file is run with `node --test` after `npm run build` and
  must pass; report the per-file counts. A file that cannot run on this host is
  recorded as NOT RUN with the reason.
- Do not commit the unrelated `package-lock.json` diff.

## Task 1: Keyring and re-key tests

**Files:** `test/rekey-vault.test.mjs`, `test/keyring-passphrase.test.mjs`,
`test/keyring-create.test.mjs`, `test/keyring.test.mjs`,
`test/keyring-recovery.test.mjs`, `test/rekey-transitions.test.mjs`.

- Convert every banned call per the rules above, including comments (e.g. the
  comment near `test/rekey-vault.test.mjs:60`).
- Verify: `npm run build`, then `node --test` on the six files; eslint on the
  six files; a grep of the six files for `rmSync|cpSync|fs.rm(|fs.cp(|fs/promises`
  returns nothing.

## Task 2: Sync and portable-sync tests

**Files:** `test/sync.test.mjs`, `test/sync-relay.test.mjs`,
`test/sync-apply.test.mjs`, `test/sync-blob-transport.test.mjs`,
`test/sync-transaction.test.mjs`, `test/sync-epoch.test.mjs`,
`test/sync-protocol.test.mjs`, `test/sync-blobs.test.mjs`,
`test/portable-sync.test.mjs`.

- Convert every banned call per the rules above, including comments.
- Verify: `npm run build`, then `node --test` on the nine files; eslint; the
  same grep returns nothing. `test/portable-sync.test.mjs` has a known flake
  under load (Phase 16.4, not in scope): if it fails, re-run it alone and
  record both runs; do not change it beyond the conversion.

## Task 3: Remaining tests

**Files:** `test/cli.test.mjs`, `test/release.test.mjs`,
`test/platform-artifacts.test.mjs`, `test/canvas.test.mjs`,
`test/vault-lock.test.mjs`, `test/durability.test.mjs`,
`test/native-update-acceptance.test.mjs`, `test/format-conformance.test.mjs`,
`test/search-cache.test.mjs`, `test/purge.test.mjs`, `test/package.test.mjs`,
`test/native-keychain.test.mjs`, `test/memory-ledger.test.mjs`,
`test/memory.test.mjs`, `test/grants.test.mjs`,
`test/format-inventory.test.mjs`, `test/clean-dist.test.mjs`,
`test/backup.test.mjs`, `test/fs-tree.test.mjs`.

- Convert every banned call per the rules above, including comments (the
  `test/fs-tree.test.mjs` header comment names the Node helpers; reword it).
- Before converting, re-run the file grep over all of `test/` (except
  `test/fs-removal.test.mjs`) and convert anything Tasks 1-2 and this list
  missed; name such files in the report.
- Verify: `npm run build`, then `node --test` on every touched file; eslint;
  the grep over `test/` (except `test/fs-removal.test.mjs`) returns nothing.

## Task 4: Extend the source scan to `test/`

**Files:** `test/fs-removal.test.mjs`.

- Add `test/` (`.mjs`, `.cjs`, `.js`) to the trees the scan walks, exempting
  exactly `test/fs-removal.test.mjs` by its repo-relative path, with a comment
  stating why (its probes must spell the banned calls).
- Update the comment above `findBannedCalls` to name the three trees and the
  one exemption.
- Non-vacuity: temporarily reintroduce one banned call in another test file
  (uncommitted), record the failure naming file and line, revert, confirm the
  test passes.
- Verify: `npm run build && node --test test/fs-removal.test.mjs`; eslint.

## Task 5: Documentation and evidence

**Files:** this plan,
`docs/superpowers/plans/2026-09-15-phase-16-6-non-ascii-scripts.md`,
`docs/ROADMAP.md`.

- In the scripts plan's "Found beyond this plan", keep the text and add a
  sentence that the `test/` exposure was fixed by this plan, linking it. Leave
  the `finally`-cleanup note as is.
- ROADMAP 16.6: extend the sentence added for the scripts follow-up to say
  tests were moved too and the scan covers `test/`, linking this plan. No
  checkbox change.
- Fill in Evidence below from the Task 1-4 reports: commands and per-file
  results, flagged sites, NOT RUN items with reasons. No `.superpowers/` paths.
- Verify: `npx prettier --check` on the edited Markdown (CRLF-only warnings
  are a known host artifact: report, do not rewrite line endings).

## Evidence

_To be filled by Task 5._
