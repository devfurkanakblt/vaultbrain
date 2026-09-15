# Phase 16.6 — Removals that do not remove, inside the product

**Goal:** No removal under `src/` may report success while the file or tree it
names survives. 16.2 and 16.3 fixed this for the build scripts; this phase fixes
it for vault data, where the consequences are security consequences.

**Origin:** "What this found beyond 16.3" in
[the Phase 16 plan](2026-09-14-phase-16-verification-findings.md). On Windows 11
with Node v24.11.1, every `fs.rmSync` call — file or directory, recursive or not,
forced or not — removes nothing and returns normally when any path component is
non-ASCII, and `fs.cpSync({ recursive: true })` aborts the process. `unlink`,
`rmdir`, `readdir`, `rename`, `mkdir`, `lstat` and `copyFile` are unaffected. A
vault under `C:\Users\<user>\Masaüstü` is exactly where a Turkish-speaking user
keeps one, and a Windows user name is itself allowed to be non-ASCII, which
reaches `%APPDATA%` and `%TEMP%`.

Observed through the real exported APIs, ASCII vault against a `ü` vault:

- `purgeAttachment` reports `liveRemoved: true`, removes nothing, and the
  attachment is still returned by `listAttachments()`.
- After one successful re-key, `journal.json` survives the commit; every later
  re-key is refused, `recoverRekey` cannot clear it, and recovery reports
  `rolled-back` for a re-key that committed.
- Identity rotation fails with `Attachment integrity check failed` and leaves
  `.rekey/new/keyring.json` — a second wrapped keyset — plus fresh sync authority
  and device private keys on disk permanently.

**Not in this phase.** The Rust analogue at `src-tauri/src/lib.rs:5410`
(`remove_dir_all` in `remove_attachment`) stays UNVERIFIED: Rust's standard
library calls the wide-character Win32 APIs directly and is not expected to share
Node's defect, but it cannot be built on the host that found this, and an
expectation is not evidence. The build scripts' `scripts/fs-tree.mjs` is not
merged with the new module: the scripts run before `tsc` and cannot import
`dist/`.

## Global constraints

- Read `AGENTS.md` and the surrounding code before changing it.
- Preserve older vault readability and every committed compatibility fixture. No
  on-disk format, AAD, journal shape or file name changes.
- Work test-first. Behavior tests create their vault under a directory whose name
  is deliberately non-ASCII (the `fs-tree-ü-é-` pattern in
  `test/fs-tree.test.mjs`), so they fail before the fix on the Windows host that
  found the defect. Because a Linux runner cannot reproduce the Node defect, a
  source scan must also fail on any host if `fs.rmSync`, `rmSync` or `fs.cpSync`
  reappears under `src/`.
- A removal that does not remove must throw or be reported, never retried into
  silence. No retry loops.
- Never follow a symbolic link during a recursive removal: a link inside a tree is
  unlinked, its target untouched.
- Keep every existing error-handling decision at each call site. Where the code
  deliberately ignores a cleanup failure so the original error is reported (the
  staging `catch` in `stageRekey`), it keeps ignoring it; where a missing target
  was tolerated (`force: true`), it stays tolerated; where it was an error
  (`force: false`), it stays an error.
- Do not weaken any security guard to make a test pass.

## File structure

- Create `src/fs-tree.ts` — `removeTree(target)` and `removeFile(target)`, built on
  `lstatSync`, `readdirSync`, `unlinkSync` and `rmdirSync`.
- Create `test/fs-removal.test.mjs` — the module's tests and the `src/` source scan.
- Modify, in later tasks: `src/documents.ts`, `src/keyring-rekey.ts`,
  `src/backup.ts`, `src/keychain.ts`, `src/schema.ts`, `src/sync-blobs.ts`,
  `src/sync.ts`, `src/memory/runner.ts`, and the tests named per task.
- Register every new test file in the `test` script in `package.json`.

## Task 1: A removal module the product can trust

- [x] Write `test/fs-removal.test.mjs` first, importing from `../dist/fs-tree.js`,
      with every fixture under `fs.mkdtempSync(path.join(os.tmpdir(), "fs-removal-ü-é-"))`:
  - `removeTree` removes a nested tree (a file at the root, two levels of
    subdirectories) and the root is gone afterwards.
  - `removeTree` on a missing path returns without throwing.
  - `removeTree` on a directory junction/symlink removes the link and leaves the
    target's contents intact (use `fs.symlinkSync(real, link, "junction")`, as
    `test/fs-tree.test.mjs` does).
  - `removeFile` removes a single file; on a missing path it returns without
    throwing; handed a directory it throws rather than removing it.
- [x] Run `npm run build` then `node --test test/fs-removal.test.mjs`; record the
      failure (the module does not exist).
- [x] Implement `src/fs-tree.ts`. Mirror `scripts/fs-tree.mjs`'s `removeTree` and
      its explanatory comment (state why the two copies exist: scripts run before
      `tsc`). `removeFile` uses `lstatSync`: absent → return; a directory that is
      not a link → throw `Error` naming the path; otherwise `unlinkSync`. Every
      other error propagates. Explicit TypeScript types; no default export.
- [x] Register `test/fs-removal.test.mjs` in the `test` script next to
      `test/fs-tree.test.mjs`.
- [x] `npm run build`, `node --test test/fs-removal.test.mjs`, `npm run lint`,
      `npm run typecheck` pass. Commit.

## Task 2: Purging an attachment removes it

- [x] In `test/purge.test.mjs`, add a test that creates a `DocumentVault` under a
      non-ASCII temporary directory, adds an attachment, calls `purgeAttachment`,
      and asserts: the report says `liveRemoved: true`, `listAttachments()` no
      longer returns it, and the attachment's directory
      (`documents/attachments/<id>`) does not exist on disk. Add the same
      on-disk assertion for `removeAttachment` under the same kind of path. Follow
      the file's existing helpers and how attachments are added elsewhere in the
      test suite.
- [x] Run it and record the failure on this host.
- [x] In `src/documents.ts`, replace both `fs.rmSync(this.attachmentDir(id), { recursive: true, force: false })`
      calls with `removeTree` from `./fs-tree.js`. `readAttachmentManifest(id)` is
      already called first, so a missing attachment still throws before removal.
- [x] `npm run build`, `node --test test/purge.test.mjs`, lint and typecheck pass.
      Commit.

## Task 3: A committed re-key clears itself, and identity rotation completes

- [x] In `test/rekey-vault.test.mjs`, add tests that use a vault under a
      non-ASCII temporary directory, following the file's existing vault setup and
      `rekeyVault` usage:
  - After a successful `rekeyVault`, the staging root (and therefore its
    `journal.json`) does not exist, and a second `rekeyVault` on the same vault
    succeeds. `recoverRekey` then returns `"none"`.
  - An identity rotation (the mode that renames attachments and resets sync
    state; see how the existing tests or `test/cli.test.mjs` invoke it) on a vault
    that holds at least one attachment completes, leaves no staging root, no
    `keyring.json` under it, and no old attachment directory; the attachment is
    readable under its new id.
  - A re-key that fails before commit leaves no staging root.
- [x] Run them and record the failures on this host.
- [x] Replace every `fs.rmSync` in `src/keyring-rekey.ts` (currently eleven): the
      recursive ones with `removeTree`, the single-file `force: true` ones with
      `removeFile`. Keep the empty `catch` around the cleanup inside `stageRekey`'s
      failure path exactly as it is, with its comment.
- [x] `npm run build`, `node --test test/rekey-vault.test.mjs test/rekey-transitions.test.mjs test/keyring-rekey.test.mjs`,
      lint and typecheck pass. Commit.

## Task 4: No Node recursive helper left under src/

- [x] Add a test to `test/fs-removal.test.mjs` that reads every `.ts` file under
      `src/` (recursively) and fails, naming each file and line, if any call site
      matches the removal scan's `findBannedCalls` matcher. The matcher is wider
      than a single regex: it flags `rmSync`/`cpSync` anywhere, `fs.rm(`/`fs.cp(`
      with or without whitespace before the parenthesis, `promises.rm`/
      `promises.cp` (including `fs.promises.*`), any import or `require` of
      `node:fs/promises` or `fs/promises`, a named `{ rm | rmSync | cp | cpSync }`
      import from `fs`/`node:fs`, and `rmdirSync`/`rmdir` called with a
      `recursive` option (measured on this host: that also emits `DEP0147`,
      returns normally, and leaves the directory). It does not flag
      `mkdirSync(..., { recursive: true })`, a non-recursive `rmdirSync`, or any
      identifier that merely contains "rm" or "cp". A probe test in the same
      file pins the matcher against a list of strings that must match and a
      list that must not, so the two scan tests both run the same function.
      `src/fs-tree.ts` gets no exemption; it must not use them either.
- [x] Run it and record the failure naming the remaining call sites.
- [x] Replace the remaining sites: `src/backup.ts` (restore staging cleanup,
      recursive → `removeTree`), `src/keychain.ts` (`forget`, single file →
      `removeFile`), `src/schema.ts` (legacy catalog → `removeFile`),
      `src/sync-blobs.ts` (`remove` → `removeFile`), `src/sync.ts` (device
      identity key rollback → `removeFile`), `src/memory/runner.ts` (worker home,
      recursive → `removeTree`). Keep each site's surrounding control flow.
- [x] Where an existing test already exercises the site, add a non-ASCII-path
      assertion that the file is gone: the restore-failure staging cleanup in
      `test/backup.test.mjs` and `remove` in `test/sync-blobs.test.mjs`. The source
      scan covers the rest.
- [x] `npm run build`, `node --test test/fs-removal.test.mjs test/backup.test.mjs test/sync-blobs.test.mjs`,
      then the full `npm test`, `npm run lint`, `npm run typecheck`. Record exact
      counts; name every failure that is not 16.1 or 16.4. Commit.

## Acceptance gate

- [x] `purgeAttachment` and `removeAttachment` remove the attachment from disk
      under a non-ASCII vault path.
- [x] A committed re-key under a non-ASCII vault path leaves no journal, and a
      second re-key succeeds.
- [x] Identity rotation under a non-ASCII vault path completes and leaves no
      second wrapped keyset or sync private keys under the staging root.
- [x] No `rmSync` or `cpSync` remains under `src/`, and a test fails on any host if
      one returns.
- [x] The Rust analogue is recorded as UNVERIFIED, not as passing.

## Evidence

Host for every run below: Windows 11, Node v24.11.1, checkout under
`Masaüstü` (non-ASCII path component), so the defect this phase fixes
reproduces without a contrived fixture directory.

**Task 1 — `src/fs-tree.ts`.**
RED: `node --test test/fs-removal.test.mjs` before the module existed —
`ERR_MODULE_NOT_FOUND` for `dist/fs-tree.js`, 1 test, 0 pass, 1 fail.
GREEN: after implementing `src/fs-tree.ts` — 6 tests, 6 pass, 0 fail.
Files: `src/fs-tree.ts` (new), `test/fs-removal.test.mjs` (new), `package.json`
(registered the new test file).

**Task 2 — `purgeAttachment`/`removeAttachment`.**
RED: `node --test test/purge.test.mjs` with the two new non-ASCII-path tests
added but `src/documents.ts` unchanged — 8 tests, 6 pass, 2 fail (both new
tests failed: `existsSync(attachmentDir)` was `true` after the call reported
success).
GREEN: after routing both `fs.rmSync` sites in `src/documents.ts` through
`removeTree` — 8 tests, 8 pass, 0 fail.
Files: `src/documents.ts`, `test/purge.test.mjs`.

**Task 3 — re-key and identity rotation.**
RED: `node --test --test-name-pattern="non-ASCII" test/rekey-vault.test.mjs`
with the four new tests added but `src/keyring-rekey.ts` unchanged — 4 tests,
0 pass, 4 fail (staging root and journal survived a commit; identity rotation
threw "Attachment integrity check failed").
GREEN: `node --test test/rekey-vault.test.mjs test/rekey-transitions.test.mjs
test/keyring-rekey.test.mjs` after all eleven `fs.rmSync` call sites in
`src/keyring-rekey.ts` were routed through `removeTree`/`removeFile` — 101
tests, 101 pass, 0 fail.
Files: `src/keyring-rekey.ts`, `test/rekey-vault.test.mjs`.

**Task 4 — every remaining call site under `src/`.**
RED: `node --test test/fs-removal.test.mjs` with the source scan added but
`src/` unchanged — 7 tests, 6 pass, 1 fail, naming exactly the seven remaining
call sites plus the one comment mention that had not yet been reworded.
GREEN: `node --test test/fs-removal.test.mjs test/backup.test.mjs
test/sync-blobs.test.mjs` after the seven sites were converted
(`src/backup.ts`, `src/keychain.ts`, `src/schema.ts`, `src/sync-blobs.ts`,
`src/sync.ts`, `src/memory/runner.ts`) and the comment reworded — 19 tests, 19
pass, 0 fail.
Files: `src/backup.ts`, `src/keychain.ts`, `src/schema.ts`,
`src/sync-blobs.ts`, `src/sync.ts`, `src/memory/runner.ts`,
`test/backup.test.mjs`, `test/sync-blobs.test.mjs`.

**Final review findings (this pass).**

- _Finding 1, the scan's coverage._ RED: a probe script ran the plan's original
  regex (`/\brmSync\b|\bcpSync\b|\bfs\.rm\(|\bfs\.cp\(|promises\.rm\b|promises\.cp\b/`)
  against 22 probe strings that a wider scan should catch; it missed 11 of
  them — whitespace before the parenthesis (`fs.rm (x, cb)`), every
  `fs/promises` import and `require`, every named `{ rm | cp }` import from
  `fs`/`node:fs`, and `rmdirSync`/`rmdir` called with `recursive: true`
  (including one written across three lines). GREEN: the widened
  `findBannedCalls` matcher in `test/fs-removal.test.mjs`, exercised by
  `"findBannedCalls matches every probe that names a banned removal, and none
of the others"`, matches all 22 must-match probes and none of the 12
  must-not-match probes (which include `mkdirSync(..., { recursive: true })`,
  a non-recursive `rmdirSync`, and identifiers that merely contain "rm" or
  "cp"). `grep` over `src/` before widening the scan confirmed no `src/` file
  currently uses recursive `rmdirSync`/`rmdir` or imports `fs/promises`, so
  the wider scan changes no other file's behavior. Full run after widening:
  `node --test test/fs-removal.test.mjs` — 9 tests, 9 pass, 0 fail. File:
  `test/fs-removal.test.mjs`.
- _Finding 2, nested junction._ Added
  `"removeTree on a tree containing a nested junction removes the tree and
leaves the junction's target intact"` to `test/fs-removal.test.mjs`, which
  passes with the existing `removeTree` implementation (no source change was
  needed; the case was already covered by the recursion's unlink-not-follow
  behavior, it just was not asserted). File: `test/fs-removal.test.mjs`.
- _Finding 5, isolating `stageRekey`'s own cleanup._ Added
  `"stageRekey's own failure cleanup removes the staging root under a
non-ASCII path"` to `test/rekey-vault.test.mjs`, which calls the exported
  `stageRekey` directly (not through `rekeyVault`) so `rekeyVault`'s
  pre-commit catch cannot mask the site under test. GREEN (as committed):
  `node --test --test-name-pattern="stageRekey's own failure cleanup"
test/rekey-vault.test.mjs` — 1 test, 1 pass, 0 fail. RED (temporary,
  reverted, never committed): the one `removeTree(stagingRoot(vaultDir))`
  call inside `stageRekey`'s own `catch` block (`src/keyring-rekey.ts`,
  the loop's guarded cleanup) was replaced with a no-op comment; the same
  test then failed — `AssertionError: stageRekey's own catch must clear the
staging root it built, true !== false` — 1 test, 0 pass, 1 fail. The call
  was restored immediately after and `npm run build` plus the same test run
  were repeated to confirm the GREEN result above. File:
  `test/rekey-vault.test.mjs`.

**Full suite, lint, and typecheck (this pass).** `npm run build`: clean.
`node --test test/rekey-vault.test.mjs test/fs-removal.test.mjs`: 88 tests, 88
pass, 0 fail. `npm test`: 481 tests, 479 pass, 2 fail, `duration_ms 215948`.
Both failures are `test/memory-client.test.mjs` ("setup preserves unrelated
TOML and refuses to overwrite an existing integration" and "disconnect
refuses to remove user-modified managed config"), each throwing "Refusing
symbolic-link path component: nodejs" from `assertNoSymlinkComponents` — the
pre-existing Phase 16.1 symlinked-interpreter-path guard, unrelated to this
phase's changes. No `test/portable-sync.test.mjs` failure occurred in this
run. `npm run lint`: exit 0, no errors or warnings. `npm run typecheck`
(`tsc -p . --noEmit && tsc -p desktop/tsconfig.json`): exit 0, no errors.

**Rust.** `remove_dir_all` at `src-tauri/src/lib.rs:5410` (in
`remove_attachment`) is NOT RUN / UNVERIFIED in this phase: it cannot be built
on this host (no MSVC linker). Rust's standard library calls the
wide-character Win32 APIs directly and is not expected to share Node's
defect, but that is an expectation, not evidence.

**Accepted TOCTOU.** Between the `lstat` and the `readdir` it precedes inside
`removeTree`, a same-user process with write access inside the tree being
removed could swap a directory entry for a junction, redirecting the
recursion outside the tree. Accepted because it requires write access inside
the vault while a removal is already running, and Node's own removal helper
carried the same gap.

### Found beyond 16.6

The same defect — recursive removal or copy that can silently fail or abort
on a non-ASCII path — remains outside the product build, in scripts that are
not part of `npm run build`/`npm test`. Verified by `grep` in this pass, not
fixed here:

- `scripts/make-fixtures.mjs`: recursive `fs.rmSync` at multiple call sites
  and recursive `fs.cpSync` at two (~109, ~180).
- `scripts/benchmark.mjs`: one recursive `fs.rmSync`.
- `scripts/sync-recovery-drill.mjs`: one recursive `fs.rmSync`.
- `scripts/portable-recovery-drill.mjs`: one recursive `fs.rmSync`.
- `scripts/release/release.mjs`: one recursive `fs.rmSync`.
- `scripts/release/native-update-acceptance.mjs`: one recursive `fs.rmSync`.

This was fixed by the follow-up in
[`2026-09-15-phase-16-6-non-ascii-scripts.md`](2026-09-15-phase-16-6-non-ascii-scripts.md).
