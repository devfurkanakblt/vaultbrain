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

### Task 1 (commit `c0bf516`): keyring and re-key tests

Six files converted: `test/rekey-vault.test.mjs`,
`test/keyring-passphrase.test.mjs`, `test/keyring-create.test.mjs`,
`test/keyring.test.mjs`, `test/keyring-recovery.test.mjs`,
`test/rekey-transitions.test.mjs`.

- `rekey-vault.test.mjs`: 68 `removeTree` conversions, 4 bare `rmSync` →
  `fs.unlinkSync` (each on a file the test requires to already exist), 3
  comments reworded (checked against `src/keyring-rekey.ts` so the reworded
  text stays accurate).
- `keyring-passphrase.test.mjs`: 21 `removeTree` conversions.
- `keyring-create.test.mjs`: 7 `removeTree` conversions; also dropped the
  file's own hand-rolled `copyTree` (a workaround for `fs.cpSync` crashing on
  this host) in favor of the shared `copyTree` from `scripts/fs-tree.mjs`.
- `keyring.test.mjs`: 4 bare `rmSync` → `fs.unlinkSync` (deleting a
  just-written `keyring.json`).
- `keyring-recovery.test.mjs`: 1 `removeTree` conversion (a `finally` block).
- `rekey-transitions.test.mjs`: 2 `removeTree` conversions.

No sites were flagged under the `rmSync(x, { recursive: true })` without
`force` rule — every recursive removal in these six files already carried
`force: true`.

- `npm run build` — exit 0.
- `node --test` per file: 79 + 24 + 7 + 34 + 14 + 5 = 163 pass, 0 fail.
- `npx eslint` on the six files — clean, no output.
- `grep -rn "rmSync\|cpSync\|fs\.rm(\|fs\.cp(\|fs/promises"` over the six
  files — no matches.

### Task 2 (commit `fe693ac`): sync and portable-sync tests

Nine files converted: `test/sync.test.mjs`, `test/sync-relay.test.mjs`,
`test/sync-apply.test.mjs`, `test/sync-blob-transport.test.mjs`,
`test/sync-transaction.test.mjs`, `test/sync-epoch.test.mjs`,
`test/sync-protocol.test.mjs`, `test/sync-blobs.test.mjs`,
`test/portable-sync.test.mjs`. None of the nine previously imported an
`fs-tree` helper, so each gained an
`import { removeTree } from "../scripts/fs-tree.mjs";` (plus `copyTree` where
the file also called `cpSync`).

Recounted directly against the commit range
(`git diff c0bf516 fe693ac | grep -c '^+.*removeTree('`): 64 `removeTree`
conversions in total, 43 of them in `test/sync.test.mjs` alone (the file's
own report undercounted these two figures as 54 and 33; the counts above are
the corrected ones). Also converted: 19 `cpSync` → `copyTree`, 20 bare
`rmSync` → `fs.unlinkSync` (all in `sync.test.mjs`, on identity key files the
tests require to exist), and 1 comment reworded in
`test/sync-blobs.test.mjs` (a comment-only site — the file has no removal or
copy call sites of its own).

One non-standard shape: a two-line `fs.rmSync(\n  path.join(...),\n)` in
`sync.test.mjs` converted to the equivalent multi-line `fs.unlinkSync` call,
same rule as the file's other bare single-file removals.

Flagged (semantic-parity notes, not required changes): in
`sync-apply.test.mjs`'s `stageBlobs()`, `copyTree` copies attachment blobs
onto a `toDir` that a prior `copyVault()` may already have created (typically
empty at that point) — `copyTree`'s merge-into-existing-directory behavior
matches what the old recursive `cpSync` default already did there, since no
`filter`/`errorOnExist`/`dereference` was used at the original call site.
Every other `copyTree` call site in this batch either targets a directory
`removeTree` just cleared or a path that does not yet exist.

- `npm run build` — exit 0.
- `node --test` per file: 28 + 4 + 9 + 4 + 14 + 9 + 7 + 4 + 5 = 84 pass, 0
  fail. `test/portable-sync.test.mjs` passed cleanly on this run (5/5); the
  known Phase 16.4 flake did not reproduce here, so only one run is recorded.
  A reviewer of this task separately observed that same Phase 16.4
  portable-sync flake once on an independent run, passing cleanly on
  re-run — consistent with it being a pre-existing, out-of-scope flake rather
  than something introduced by this conversion.
- `npx eslint` on all nine files — clean, no output.
- The same banned-call grep, run over all nine files — no matches.

### Task 3 (commit `44574a9`): remaining tests

Nineteen files converted: `test/canvas.test.mjs`, `test/cli.test.mjs`,
`test/durability.test.mjs`, `test/format-conformance.test.mjs`,
`test/format-inventory.test.mjs`, `test/grants.test.mjs`,
`test/memory-ledger.test.mjs`, `test/memory.test.mjs`,
`test/native-keychain.test.mjs`, `test/native-update-acceptance.test.mjs`,
`test/package.test.mjs`, `test/platform-artifacts.test.mjs`,
`test/release.test.mjs`, `test/search-cache.test.mjs`,
`test/vault-lock.test.mjs`, `test/backup.test.mjs`,
`test/clean-dist.test.mjs`, `test/fs-tree.test.mjs`, `test/purge.test.mjs`.

- Re-running the scan (a standalone copy of `findBannedCalls` from
  `test/fs-removal.test.mjs`) over all of `test/` except
  `test/fs-removal.test.mjs` before converting anything matched exactly this
  nineteen-file list — no leftovers in the Task 1/2 files. After conversion
  the same scan returns zero offenses across all of `test/` except
  `test/fs-removal.test.mjs`.
- `test/package.test.mjs` had no removal/copy calls: its `node:fs/promises`
  import (`readFile`, `access`) was replaced with `fs.promises.<name>`
  through the default `node:fs` import.
- Two test-local helper functions were named `copyTree`, colliding with the
  imported `scripts/fs-tree.mjs` export: `durability.test.mjs`'s was renamed
  to `copyFixtureTree` (body unchanged); `format-conformance.test.mjs`'s
  needed no rename since that file never calls `cpSync` and so never imports
  `copyTree`.
- Four comment-only files reworded prose naming the banned calls:
  `backup.test.mjs`, `clean-dist.test.mjs`, `fs-tree.test.mjs` (the header
  comment named in the brief), `purge.test.mjs`.
- No site was flagged under the `rmSync(x, { recursive: true })` without
  `force` rule — every recursive removal in this batch already carried
  `force: true`, or was a no-option single-file `rmSync` converted to
  `fs.unlinkSync` (preserving the throw-on-missing behavior).

- `npm run build` — exit 0.
- `node --test`, run in five groups plus three `npm run test:*` scripts
  (native-keychain, release, update-acceptance, platform-artifacts) and a
  standalone run of `test/fs-removal.test.mjs` itself: 30 + 36 + 44 + 13 + 1
  - 12 + 4 + 9 + 9 = 158 pass, 0 fail, 0 skipped.
- `npm run lint` (`eslint src desktop/src scripts test desktop/vite.config.ts`)
  — clean, no warnings or errors.
- `test/native-keychain.test.mjs` ran on this host (native credential store
  available) — no NOT RUN needed for any file in this task.

### Task 4 (commit `89ca47f`): extend the source scan to `test/`

**File:** `test/fs-removal.test.mjs`.

- Added a third tree to the scan (`test/`, extensions `.mjs`/`.cjs`/`.js`),
  alongside the existing `src/` (`.ts`) and `scripts/` (`.mjs`/`.cjs`/`.js`)
  trees. The single exemption, `test/fs-removal.test.mjs`, is matched by
  repo-relative path (not basename), with a comment stating why (its own
  `MUST_MATCH` probes must spell the banned calls verbatim). The test title
  and the comment above `findBannedCalls` were updated to name all three
  trees and the one exemption.
- Non-vacuity (RED): an uncommitted `import { rmSync } from "node:fs";` line
  appended to `test/backup.test.mjs` made `node --test
test/fs-removal.test.mjs` fail, naming the exact file and line
  (`test/backup.test.mjs:242`, reported twice because two of the scan's
  regexes both match the same import line — pre-existing, correct behavior
  of `findBannedCalls`, unchanged by this task). The line was reverted with
  `git checkout -- test/backup.test.mjs`.
- GREEN on HEAD: `npm run build` — clean; `node --test
test/fs-removal.test.mjs` — `tests 9`, `pass 9`, `fail 0`, including the
  renamed scan test ("no source file under src/, scripts/, or test/ calls
  Node's non-ASCII-unsafe recursive removal helpers"). The extended scan
  reports zero offenses across all of `test/` on HEAD, consistent with Tasks
  1-3 having already moved every call site onto the `fs-tree` helpers.
- `npx eslint test/fs-removal.test.mjs` — clean, no output.

At the time this evidence was recorded, the Task 4 change was reviewed but
that review may still have been in progress; the results above are what its
own report records, and the merge-time verification set (see below) covers
the file again regardless.

### NOT RUN

None. Every verification step called for by Tasks 1-4 ran on this host
(Windows 11, Node v24.11.1); no test file or command was skipped.

### Not part of this documentation task

The full local verification set and the PR's CI run are executed at merge
time, not as part of Task 5.
