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

- [ ] Write `test/fs-removal.test.mjs` first, importing from `../dist/fs-tree.js`,
      with every fixture under `fs.mkdtempSync(path.join(os.tmpdir(), "fs-removal-ü-é-"))`:
  - `removeTree` removes a nested tree (a file at the root, two levels of
    subdirectories) and the root is gone afterwards.
  - `removeTree` on a missing path returns without throwing.
  - `removeTree` on a directory junction/symlink removes the link and leaves the
    target's contents intact (use `fs.symlinkSync(real, link, "junction")`, as
    `test/fs-tree.test.mjs` does).
  - `removeFile` removes a single file; on a missing path it returns without
    throwing; handed a directory it throws rather than removing it.
- [ ] Run `npm run build` then `node --test test/fs-removal.test.mjs`; record the
      failure (the module does not exist).
- [ ] Implement `src/fs-tree.ts`. Mirror `scripts/fs-tree.mjs`'s `removeTree` and
      its explanatory comment (state why the two copies exist: scripts run before
      `tsc`). `removeFile` uses `lstatSync`: absent → return; a directory that is
      not a link → throw `Error` naming the path; otherwise `unlinkSync`. Every
      other error propagates. Explicit TypeScript types; no default export.
- [ ] Register `test/fs-removal.test.mjs` in the `test` script next to
      `test/fs-tree.test.mjs`.
- [ ] `npm run build`, `node --test test/fs-removal.test.mjs`, `npm run lint`,
      `npm run typecheck` pass. Commit.

## Task 2: Purging an attachment removes it

- [ ] In `test/purge.test.mjs`, add a test that creates a `DocumentVault` under a
      non-ASCII temporary directory, adds an attachment, calls `purgeAttachment`,
      and asserts: the report says `liveRemoved: true`, `listAttachments()` no
      longer returns it, and the attachment's directory
      (`documents/attachments/<id>`) does not exist on disk. Add the same
      on-disk assertion for `removeAttachment` under the same kind of path. Follow
      the file's existing helpers and how attachments are added elsewhere in the
      test suite.
- [ ] Run it and record the failure on this host.
- [ ] In `src/documents.ts`, replace both `fs.rmSync(this.attachmentDir(id), { recursive: true, force: false })`
      calls with `removeTree` from `./fs-tree.js`. `readAttachmentManifest(id)` is
      already called first, so a missing attachment still throws before removal.
- [ ] `npm run build`, `node --test test/purge.test.mjs`, lint and typecheck pass.
      Commit.

## Task 3: A committed re-key clears itself, and identity rotation completes

- [ ] In `test/rekey-vault.test.mjs`, add tests that use a vault under a
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
- [ ] Run them and record the failures on this host.
- [ ] Replace every `fs.rmSync` in `src/keyring-rekey.ts` (currently eleven): the
      recursive ones with `removeTree`, the single-file `force: true` ones with
      `removeFile`. Keep the empty `catch` around the cleanup inside `stageRekey`'s
      failure path exactly as it is, with its comment.
- [ ] `npm run build`, `node --test test/rekey-vault.test.mjs test/rekey-transitions.test.mjs test/keyring-rekey.test.mjs`,
      lint and typecheck pass. Commit.

## Task 4: No Node recursive helper left under src/

- [ ] Add a test to `test/fs-removal.test.mjs` that reads every `.ts` file under
      `src/` (recursively) and fails, naming each file and line, if any matches
      `/\brmSync\b|\bcpSync\b|\bfs\.rm\(|\bfs\.cp\(|promises\.rm\b|promises\.cp\b/`.
      `src/fs-tree.ts` gets no exemption; it must not use them either.
- [ ] Run it and record the failure naming the remaining call sites.
- [ ] Replace the remaining sites: `src/backup.ts` (restore staging cleanup,
      recursive → `removeTree`), `src/keychain.ts` (`forget`, single file →
      `removeFile`), `src/schema.ts` (legacy catalog → `removeFile`),
      `src/sync-blobs.ts` (`remove` → `removeFile`), `src/sync.ts` (device
      identity key rollback → `removeFile`), `src/memory/runner.ts` (worker home,
      recursive → `removeTree`). Keep each site's surrounding control flow.
- [ ] Where an existing test already exercises the site, add a non-ASCII-path
      assertion that the file is gone: the restore-failure staging cleanup in
      `test/backup.test.mjs` and `remove` in `test/sync-blobs.test.mjs`. The source
      scan covers the rest.
- [ ] `npm run build`, `node --test test/fs-removal.test.mjs test/backup.test.mjs test/sync-blobs.test.mjs`,
      then the full `npm test`, `npm run lint`, `npm run typecheck`. Record exact
      counts; name every failure that is not 16.1 or 16.4. Commit.

## Acceptance gate

- [ ] `purgeAttachment` and `removeAttachment` remove the attachment from disk
      under a non-ASCII vault path.
- [ ] A committed re-key under a non-ASCII vault path leaves no journal, and a
      second re-key succeeds.
- [ ] Identity rotation under a non-ASCII vault path completes and leaves no
      second wrapped keyset or sync private keys under the staging root.
- [ ] No `rmSync` or `cpSync` remains under `src/`, and a test fails on any host if
      one returns.
- [ ] The Rust analogue is recorded as UNVERIFIED, not as passing.
