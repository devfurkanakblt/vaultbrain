# Phase 16.6 follow-up — non-ASCII removal and copy in non-build scripts

Phase 16.6 routed every removal under `src/` through `src/fs-tree.ts` and
recorded, not fixed, the same defect in scripts outside the product build
(see "Found beyond 16.6" in
[`2026-09-14-phase-16-6-non-ascii-vault-removal.md`](2026-09-14-phase-16-6-non-ascii-vault-removal.md)).
This plan closes that list.

**The defect.** Measured on Windows 11 with Node v24.11.1: when any path
component is non-ASCII, every `fs.rmSync` call removes nothing and returns
normally (with or without `recursive`/`force`, never even ENOENT), and
`fs.cpSync({ recursive: true })` aborts the process with 0xC0000409. This
checkout lives under `Masaüstü`, so every script below is exposed on this host.

## Global Constraints

- Code, comments, commits and docs in English.
- Scripts must not import compiled product code for this helper; they use
  `scripts/fs-tree.mjs`. `scripts/fs-tree.mjs` and `src/fs-tree.ts` are two
  copies of the same fix and must stay in sync: `removeFile` in the script
  copy has the same behavior and the same error message as `src/fs-tree.ts`
  (`Refusing to remove a directory as a file: ${target}`).
- A removal that does not remove must surface an error. No retries, no
  swallowed errors, no fallback to the Node helpers.
- A call that threw on a missing file before (`fs.rmSync(file)` without
  `force`) must still throw on a missing file after the change. A call with
  `force: true` must still tolerate a missing target.
- After this plan, no file under `src/` (`.ts`) or `scripts/` (`.mjs`) contains
  anything `findBannedCalls` in `test/fs-removal.test.mjs` reports —
  `scripts/fs-tree.mjs` included, even in comments.
- Never run `scripts/make-fixtures.mjs` in the main checkout: it overwrites the
  checked-in fixtures under `test/fixtures/`.
- Do not commit the unrelated `package-lock.json` diff in the worktree.

## Task 1: `removeFile` in `scripts/fs-tree.mjs`

**Files:** `scripts/fs-tree.mjs`, `test/fs-tree.test.mjs`.

- Add and export `removeFile(target)` with the same semantics as
  `src/fs-tree.ts`: missing target returns; a real directory (not a link)
  throws `Refusing to remove a directory as a file: ${target}` and is left in
  place; anything else is `fs.unlinkSync`ed.
- Reword the header comment of `scripts/fs-tree.mjs` so it no longer spells
  the banned names (follow the wording of `src/fs-tree.ts`'s header, which
  already avoids them), and add the same "two copies, keep them in sync"
  note pointing at `src/fs-tree.ts`.
- Tests in `test/fs-tree.test.mjs`, under the existing non-ASCII `AWKWARD`
  root: removes a file under a non-ASCII path; returns without error on a
  missing target; refuses a directory and leaves it (and its contents) in
  place.
- Verify: `node --test test/fs-tree.test.mjs` (write the tests first, see them
  fail on the missing export, then implement), `npx eslint scripts/fs-tree.mjs
  test/fs-tree.test.mjs`.

## Task 2: Replace the call sites in the six scripts

**Files:** `scripts/make-fixtures.mjs`, `scripts/benchmark.mjs`,
`scripts/sync-recovery-drill.mjs`, `scripts/portable-recovery-drill.mjs`,
`scripts/release/release.mjs`, `scripts/release/native-update-acceptance.mjs`.

- Recursive removals (`fs.rmSync(x, { recursive: true, force: true })`) →
  `removeTree(x)`.
- Single-file removals with `force: true` → `removeFile(x)`.
- Single-file removals without `force` (make-fixtures ~110-112 and ~218) →
  `fs.unlinkSync(x)`, so a missing file still throws.
- `fs.cpSync(a, b, { recursive: true })` (make-fixtures ~109 and ~180) →
  `copyTree(a, b)`. At ~107-109 the `mkdtempSync` directory is removed and
  then recreated by the copy; keep that order (`removeTree` then `copyTree`).
- Import from `./fs-tree.mjs` / `../fs-tree.mjs` as appropriate. Change no
  other behavior.
- Verify, and record the exact commands and results in the report:
  - `npx eslint` on the six files.
  - `npm run build`, then
    `node --test test/fs-tree.test.mjs test/portable-sync.test.mjs test/release.test.mjs test/native-update-acceptance.test.mjs`.
  - `node scripts/sync-recovery-drill.mjs` (after build) exits 0.
  - `node scripts/benchmark.mjs` at the smallest tier its options allow
    exits 0 and leaves no benchmark root behind under the OS temp directory.
  - `make-fixtures`, in a throwaway worktree — never the main checkout:
    `git worktree add "<scratch>/fixtures-ü-check" HEAD`, junction/symlink
    `node_modules` from the main checkout, `npm run build`, `node
    scripts/make-fixtures.mjs`; it must exit 0, and `npm test`'s
    format-conformance file (`node --test test/format-conformance.test.mjs`)
    must pass inside that worktree. If feasible, first run the same command on
    the base commit to record the pre-fix failure. Remove the worktree with
    `git worktree remove --force` afterwards. If any step cannot run on this
    host, record it as NOT RUN with the reason; do not mark it passed.

## Task 3: Extend the source scan to `scripts/`

**Files:** `test/fs-removal.test.mjs`.

- Generalize the file lister so the scan covers `src/**/*.ts` and
  `scripts/**/*.mjs`, reporting offences relative to the repository root.
  Either one test covering both trees or a second test for `scripts/`; no
  exemptions for any file.
- Update the comment above `findBannedCalls` (currently says the scan covers
  `src/`) to name both trees and state that `scripts/fs-tree.mjs` gets no
  exemption either.
- Show the scan is not vacuous: temporarily reintroduce one banned call in a
  file under `scripts/` (uncommitted), record that the test fails naming that
  file and line, revert it, then confirm the test passes on HEAD.
- Verify: `npm run build && node --test test/fs-removal.test.mjs`,
  `npx eslint test/fs-removal.test.mjs`.

## Task 4: Documentation and evidence

**Files:** `docs/superpowers/plans/2026-09-14-phase-16-6-non-ascii-vault-removal.md`,
`docs/superpowers/plans/2026-09-15-phase-16-6-non-ascii-scripts.md`,
`docs/ROADMAP.md`.

- In the 16.6 plan's "Found beyond 16.6", keep the list and replace "This is
  recorded, not fixed, in this phase." with a sentence saying it was fixed by
  this follow-up, linking this plan.
- ROADMAP 16.6: append one sentence stating that the non-build scripts were
  moved onto `scripts/fs-tree.mjs` and the source scan now covers `scripts/`,
  linking this plan. Do not change any checkbox.
- Fill in the Evidence section of this plan from the Task 1-3 reports:
  commands and results, including any NOT RUN with its reason. Cite commands
  and outcomes, not git-ignored `.superpowers/` report paths.
- Verify: `npx prettier --check` on the edited Markdown files (CRLF-only
  differences on this host are a known `format:check` artifact; report them,
  do not rewrite line endings).

## Evidence

_To be filled by Task 4._
