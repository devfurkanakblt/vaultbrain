# Phase 16 — What the verification run found

**Goal:** Close the defects and verification gaps a full local check of `c0236d3`
exposed. None of them were caught by CI, and two of them are the kind of thing CI
structurally cannot catch: they only appear on a real Windows developer machine.

**Baseline:** `c0236d3` on `main` (merge of PR #49), worktree clean, local and
`origin/main` identical. Every result below comes from that commit.

**Not in this phase.** Phase 15's unfinished work stays in
[the Phase 15 plan](2026-09-11-phase-15-personal-memory.md): the worker adapter,
the first real capture-to-review round, Windows adversarial acceptance, the
restore/re-key compatibility round, the platform decision and the memory-specific
security review. The external gates stay with their existing owners too —
production signing and the real updater transitions with Phase 12, the acceptance
runbooks and documentation reconciliation with Phase 14.0–14.5, the independent
audit with 14.5. This phase owns only what the verification run itself produced.

## Global constraints

- Read `AGENTS.md` and the surrounding code before changing it.
- Preserve older vault readability and every committed compatibility fixture.
- Work test-first. A fix without a test that fails before it is not a fix here,
  because every item below is something the existing suite already failed to catch.
- Do not weaken a security guard to make a test pass. Two of these findings are
  guards behaving exactly as written; the question is whether the guard is asking
  the right question, not whether it should be removed.
- A check that cannot run on a host is a verification gap, never a pass. Do not
  convert a failing environment-dependent test into a silent skip.

## The verification run, for the record

| Check | Result |
| --- | --- |
| `npm run typecheck` | Pass, after `npm install` (see F0) |
| `npm run lint` | Pass |
| `npm test` | 448 tests, 443 pass, 5 fail — see F1, F2, F3, F4 |
| `npm run desktop:test` | Pass, 13 files, 145 tests |
| `npm run desktop:build` | Pass |
| `npm run test:release` | Pass, 12 tests |
| `npm run test:update-acceptance` | Pass, 4 tests |
| `npm run test:platform-artifacts` | Pass, 8 tests, from PowerShell — fails from Git Bash, see F3 |
| `npm run format:check` | Fails on 5 files; carriage returns only, see F3 |
| `npm run quality:rust` | Could not run — no MSVC linker on this host, see F3 |

## Phase 16.1 — The symlink guard asks the wrong question

`vbrain memory setup` cannot be run by anyone whose Node is installed through
nvm-windows, which is a large share of Windows developers and therefore a large
share of the people who would try personal memory first.

`src/memory/setup.ts:13` runs every executable path through
`assertNoSymlinkComponents`. On this host `process.execPath` is
`C:\nvm4w\nodejs\node.exe`, and `C:\nvm4w\nodejs` is a symbolic link to
`C:\Users\<user>\AppData\Local\nvm\v24.11.1` — that redirection is how nvm-windows
switches versions. The guard refuses with `Refusing symbolic-link path component:
nodejs`, so both `test/memory-client.test.mjs:37` and `:55` fail, and so does the
real command.

The guard is not wrong to care. A symlinked component in a path that ends up
inside an MCP `command` field means the executable that actually runs can be
changed later without touching the configuration. The question is what to do about
it, and refusing is only one of two defensible answers.

### Task 1: Decide what a symlinked interpreter path means

- [x] Write the decision down before writing code. Two candidates: resolve the path
      with `fs.realpathSync` and record the resolved target in the managed config,
      so the configuration names the binary that will actually run; or keep refusing
      and tell the user the exact resolved path to pass instead.
- [x] State which threat the choice addresses and which it accepts. Resolving pins
      the binary but freezes the nvm version, so a later `nvm use` silently leaves
      the configuration pointing at an older interpreter. Refusing keeps the user in
      control but makes the command unusable for a common, legitimate setup.
- [x] Record whether the same reasoning applies to `nativeExecutable` and `cliPath`,
      which go through the identical check.

**Decided, 2026-09-14: resolve, then record and show.** The three executable paths
are resolved with `fs.realpathSync`, checked in resolved form by the unchanged
guard, and written resolved into the managed TOML; setup prints every path it
resolved and says to run setup again after switching Node versions, so the `nvm use`
cost is stated rather than silent. `nativeExecutable` and `cliPath` follow the same
rule. `configPath` does not: a link there redirects where setup writes, and it keeps
being refused. The reasoning, the rejected alternative and the tasks are in
[the Phase 16.1 plan](2026-09-14-phase-16-1-symlinked-interpreter.md).

### Task 2: Implement the decision

- [x] Add a failing test that constructs a symlinked interpreter path itself rather
      than depending on how the host's Node happens to be installed — the current
      tests pass on CI purely because a Linux runner's Node is not symlinked, which
      is why this was never caught.
- [x] Implement the decided behavior and assert on what lands in the managed TOML,
      not just on the absence of a throw.
- [x] Cover the negative case that the guard exists for: a path component that is a
      symlink pointing somewhere unexpected must still be refused or resolved
      visibly, never silently accepted.

### Acceptance gate

- [ ] `vbrain memory setup` completes on a host whose Node is managed by
      nvm-windows, or refuses with a message naming the exact path to use instead.
      The library (`installMemoryConfig` resolves an executable path reached
      through a directory junction — the same redirection nvm-windows uses —
      and writes the resolved binary into the managed TOML, or refuses and
      names the unresolvable path for a dangling junction), the formatter, and
      the CLI wiring are all covered by tests. What remains is a live
      `vbrain memory setup` run against a real nvm-windows install with a
      paired desktop native executable — no paired desktop has been available
      on any host used for this phase. See the Evidence section below.
- [x] The managed MCP entry names a path whose meaning is stable and documented.
      The decision paragraph above states the meaning (the binary that ran at
      setup time; a later `nvm use` requires re-running setup) and the CLI prints
      the resolution and that note; see Evidence.
- [x] A test fails if the decided behavior regresses, on any host. The junction
      tests in `test/memory-client.test.mjs` build their own link rather than
      depending on the host's Node installation.

### Evidence

Fail-before / pass-after on this host, `test/memory-client.test.mjs`:

- Before Task 1 (Phase 16 baseline): 2 failures (the two setup tests using
  `process.execPath`, which resolves through the `C:\nvm4w\nodejs` junction on
  this host). RED for Task 1, after adding its new junction-based tests but
  before implementing resolution: 6 of 11 fail —
  ```
  ✖ setup preserves unrelated TOML and refuses to overwrite an existing integration
  ✖ setup resolves a node executable reached through a junction
  ✖ setup resolves a native executable and cli entry reached through junctions
  ✖ setup reports no resolutions when no executable path is linked
  ✖ setup resolves a linked executable under a non-ASCII temporary directory
  ✖ disconnect refuses to remove user-modified managed config
  ```
  (the two pre-existing tests fail with `Refusing symbolic-link path component`,
  as expected; the four new junction tests fail because no resolution step
  exists yet; the two tests already correct before the fix — dangling junction,
  `configPath` through a junction — pass at RED as regression guards, not new
  bugs). GREEN after Task 1: 11/11 pass.
- Task 2 added two tests: a normalization test (forward slashes and a `..`
  segment through a regular file must not be reported as a resolution — a
  review finding: comparing the resolved path against the raw `given` string,
  rather than `path.resolve(given)`, produced a false "resolved" entry even
  without any link), and a `formatResolvedPaths` unit test (entries to lines;
  empty to no lines). It also tightened the dangling-junction test's assertion
  to also match `/Could not resolve installation path/u`, and fixed a
  checkout-dependent test (`setup reports no resolutions when no executable
  path is linked`) that used `path.resolve("dist/cli.js")` to instead use a
  regular file created in its own temp root — both changes to existing tests,
  not new ones. RED for the normalization test (confirmed by reverting the
  `path.resolve(given)` comparison back to a raw-string comparison): 12/13
  pass, 1 fail. GREEN after restoring the fix: 13/13 pass.
- A later review of Task 2 found the normalization test's `..` case was
  vacuous: it built the given path with `path.join(root, "sub", "..", "sub",
  "node.exe")`, which collapses the `..` before `installMemoryConfig` ever
  sees it, so the assertion could not have caught a regression in that case.
  The fix builds the string directly
  (`` `${root}${path.sep}sub${path.sep}..${path.sep}sub${path.sep}node.exe` ``)
  and asserts it still contains `..` before calling setup. The same review
  found `src/memory/cli.ts` duplicated `installMemoryConfig`'s "record only
  when the resolved path differs from `path.resolve(given)`" rule and its
  fixed name order, to merge in a `nativeExecutable` entry computed from the
  CLI's own pre-resolution, untested. The fix adds an optional `givenPaths`
  input to `installMemoryConfig` (the owner-typed path to report as `given`
  for a name whose option value the caller already resolved); the CLI now
  passes the pre-resolved native path as `nativeExecutable` and the
  owner-typed path via `givenPaths.nativeExecutable`, and prints
  `formatResolvedPaths(result.resolvedPaths)` directly, with no merge logic of
  its own. Two tests were added: passing an already-resolved native path with
  `givenPaths.nativeExecutable` set to the junction path yields one entry
  whose `given` is the junction path and whose `resolved` is the real path;
  `givenPaths` equal to the path already passed yields no entry. RED for the
  first (confirmed before `givenPaths` existed): 14/15 pass, 1 fail —
  `resolvedPaths` came back `[]` instead of naming the native entry. GREEN
  after adding `givenPaths`: 15/15 pass. This review-findings fix brought
  `test/memory-client.test.mjs` from 13 to 15 tests.

Full suite: `npm test` — 491 tests, 490 pass, 1 fail. The one failure,
`epoch keys persist under the master key and refuse epoch 1` in
`test/sync-epoch.test.mjs`, is unrelated to Phase 16.1: `SyntaxError: Invalid
regular expression: /+1ofthQZH+GvDV6r/u: Nothing to repeat` — the test builds
a regular expression directly from randomly generated key material, which
occasionally contains a leading regex metacharacter. Re-running
`test/sync-epoch.test.mjs` alone passed 9/9, confirming the flake. No failure
occurred in `test/memory-client.test.mjs` or `test/portable-sync.test.mjs` in
this run. The most recent prior full run recorded in this repository (before
this review-findings fix, i.e. Task 2's own closing evidence) was 489 tests,
489 pass, 0 fail; the two extra tests here are the `givenPaths` tests this fix
added. `npm run lint` and `npm run typecheck` both pass with no output.
`node --test test/fs-removal.test.mjs` — 9/9 pass, confirming
`src/memory/setup.ts` and `src/memory/cli.ts` introduce no
`fs.rmSync`/`fs.cpSync` usage.

`vbrain memory setup` itself was NOT RUN end-to-end: it requires a paired
desktop native executable, and no paired desktop is available on this host.
The behavior it depends on (resolution, the guard, the TOML write, the printed
lines) is covered by the library and formatter tests above and by the CLI
wiring in `src/memory/cli.ts`, which resolves the native executable once and
passes the same resolved path to both the pairing check and
`installMemoryConfig`. What remains: an actual run against a real nvm-windows
Node and a paired desktop, and the acceptance runbook that would exercise it.

## Phase 16.2 — A build that cannot prove it cleaned itself — CLOSED

Phase 14.3 retired `src/sync/change-log.ts`, and `test/package.test.mjs:10` asserts
that neither the source nor `dist/sync/change-log.js` survives. On this host the
test failed: `dist/sync/change-log.js` was still present, dated five days before
the run, because `fs.rmSync(output, { recursive: true, force: true })` in
`scripts/clean-dist.mjs` had failed to remove it and reported nothing. Deleting
`dist` by hand and rebuilding made the test pass.

The stale file is the small consequence. The real one is that a build claimed
success while the output directory still held a retired implementation — the exact
failure mode Phase 13 exists to prevent, and the reason `package.test.mjs` was
written in the first place.

### What the fix found

The suspected cause — a sync client, a scanner or an open handle holding one file
— was wrong, and the real one is worse. `fs.rmSync` with `recursive: true` removes
nothing and returns normally under a path containing a non-ASCII component; this
checkout lives under `Masaüstü`. Probed three bases on Node v24.11.1: a tree under
`os.tmpdir()` is removed, a tree under `C:\Users\<user>\OneDrive` is removed, a
tree under the repository root survives untouched. `fs.unlinkSync` on the same
entries succeeds, so nothing holds the files. It is the same family as the
`fs.cpSync` crash in 16.3 item 1: Node's internal recursive filesystem helpers are
not dependable in this checkout.

So no handle was ever stuck, and this was never intermittent. Every build on this
machine has compiled on top of its predecessor's output, and the only reason
anyone noticed is that Phase 14.3 deleted a file whose absence a test asserts.

### Task 1: Make the clean verifiable

- [x] Add a failing test: with a file in `dist` that cannot be removed, the build
      must fail loudly rather than continue.
- [x] After the removal, assert the directory is actually gone before `tsc` runs;
      report the paths that survived.
- [x] Keep the existing refusal to clean a linked `dist`. Do not add retry loops
      that hide the condition instead of reporting it.

### Acceptance gate

- [x] A build cannot report success while a previous build's output survives.
- [x] The failure message names the files that could not be removed.

### Evidence

`scripts/clean-dist.mjs` now exports `cleanDist(output, { remove })`, walks the
tree itself rather than calling `fs.rmSync`, and verifies the result: anything
still under `dist` after the removal aborts the build with the surviving paths
named, up to twenty, and a count beyond that. The linked-`dist` refusal is
unchanged and is now taken from `lstat` directly, so a broken link is refused too.
No retry loop was added.

`test/clean-dist.test.mjs` adds six tests, registered in the `npm test` list. The
silent-survivor case injects a `remove` that does nothing, so it reproduces the
observed defect on any host rather than depending on this one's path encoding.
Before the fix the file did not import; after it, 6/6 pass.

Full suite on this host: 454 tests, 451 pass, 3 fail — from 448/443/5. The
`package.test.mjs` failure is gone and `npm run build` now removes `dist`. The
three remaining failures belong to 16.1 (`memory-client`, two) and 16.3 item 1
(`desktop-sync-helper`). The 16.4 relay flake did not recur in this run and stays
open under the standing rule that it is not closed on a single green run.

Carried into 16.3: its Task 1 must name the non-ASCII path hazard alongside the
cloud-sync one, and its Task 2 decision about `fs.cpSync` in the build scripts now
has a second instance behind it.

## Phase 16.3 — Checks that cannot run, and checks that lie — CLOSED

Four of the repository's own commands behaved differently on a real Windows
developer machine than in CI. Three of the four original diagnoses were
incomplete, and one of them was hiding a product defect; the corrected findings
are recorded under each item.

1. **`fs.cpSync` crashes Node.** Recorded as an OneDrive problem. It is not.
   `fs.cpSync(src, dst, { recursive: true })` exits `3221226505` (`0xC0000409`,
   `STATUS_STACK_BUFFER_OVERRUN`) whenever any component of the source path is
   non-ASCII, and copies normally from an all-ASCII sibling in the same temp
   directory. Isolated against `ascii`, `ü` and `é` directories outside OneDrive.
   It is the same defect as 16.2: every `fs.rmSync` call is a silent no-op under
   the same paths. The same removal from PowerShell succeeds, so the defect is in
   Node, not the filesystem.
2. **`tar` resolves to the wrong program** under Git Bash — and, on this host,
   under PowerShell too, because Git for Windows' `usr\bin` is on the system PATH.
   GNU tar reads `C:\Users\...` as a remote host. `C:\Windows\System32\tar.exe`
   is bsdtar 3.8.8 and reads it correctly.
3. **`format:check` reports five files** that are byte-identical to Prettier's
   output once carriage returns are stripped. Confirmed for `package.json`,
   `src-tauri/tauri.conf.json` and `.github/workflows/ci.yml`. Unchanged: this is
   the one item that is documentation only.
4. **`quality:rust` cannot run.** Recorded as a missing MSVC linker. That is true
   — no Visual Studio installation exists — but it is not why cargo's error was
   unreadable. Git for Windows ships GNU coreutils `link` as `usr\bin\link.exe`;
   cargo finds it, runs it, and reports `link: extra operand '...'`. The error
   names neither the missing toolchain nor the wrong program.

### Task 1: Say all of this once, where a contributor will read it

- [x] Add a Windows section to `CONTRIBUTING.md`: which `tar` a shell gets; do not
      run `npm run format` on a CRLF checkout; do not put a checkout under a
      non-ASCII path. The last one replaces "a cloud-synced folder", which was
      wrong.
- [x] Name the Build Tools prerequisite and state plainly that without it the Rust
      half of the project is unverified locally.

### Task 2: Make the environment failures self-describing

- [x] `test/platform-artifacts.test.mjs` no longer trusts PATH for `tar`. It
      prefers the system bsdtar, accepts a reader only if its banner shows it reads
      a drive letter as a path (`readsWindowsPaths` in
      `scripts/platform-artifacts.mjs`), and otherwise fails naming every
      candidate it rejected and why. This goes further than the task asked: the
      check now runs on this host instead of explaining why it cannot.
- [x] `npm run quality:rust` now starts with `scripts/rust-toolchain.mjs`, which
      on Windows looks for a real MSVC linker through `vswhere` and refuses before
      cargo starts if there is none, naming Build Tools and, when present, the
      shadowing coreutils `link`. It does nothing on other platforms.
- [x] No check was converted into a skip.
- [x] Decided: the build scripts stop using `fs.cpSync` and `fs.rmSync`.
      `scripts/fs-tree.mjs` provides `removeTree`, `copyTree` and `surviving`,
      built on `unlink`, `rmdir`, `readdir` and `copyFile`, which are unaffected.
      `scripts/clean-dist.mjs`, `scripts/build-desktop-sync-helper.mjs` and
      `test/desktop-sync-helper.test.mjs` use it.

### Acceptance gate

- [x] A contributor on Windows can tell, from the failure message alone, which
      failures are theirs and which are their environment's.
- [x] No environment-dependent check reports success without running.

### Evidence

New tests: `test/fs-tree.test.mjs` (5, run under a deliberately non-ASCII temp
directory so a return to Node's helpers fails there), `test/rust-toolchain.test.mjs`
(4), and one in `test/platform-artifacts.test.mjs`. The first two are registered
in the `npm test` list. Each new test file failed to import before its module
existed.

- `test/desktop-sync-helper.test.mjs`: crashed the process before; 2/2 now.
- `npm run test:platform-artifacts` from Git Bash: 6/8 before; 9/9 now.
- `node scripts/rust-toolchain.mjs` on this host: exit 1 with both causes named.
- `npm run lint`: exit 0.
- `npm test`: 463 tests, 459 pass, 4 fail. Two are 16.1 (`memory-client`). Two
  are in `test/portable-sync.test.mjs` and belong to 16.4 — see the second
  instance recorded there. This branch changes nothing under `src/`.

`quality:rust` was not run: no MSVC linker on this host. Recorded as NOT RUN.

### What this found beyond 16.3

The Node defect is not confined to build scripts. `fs.rmSync` is used throughout
`src/` on paths derived from the user's vault directory, and a vault under
`Masaüstü` is exactly where a Turkish-speaking user keeps one. Probed against
the real exported APIs, comparing an ASCII vault with a `ü` vault:

- `purgeAttachment` reports `liveRemoved: true`, removes nothing, and the
  attachment is still returned by `listAttachments()`.
- After one successful re-key, `journal.json` survives the commit; every later
  re-key is refused, `recoverRekey` cannot clear it, and recovery reports
  `rolled-back` for a re-key that committed.
- Identity rotation fails with `Attachment integrity check failed` and leaves
  `.rekey/new/keyring.json` — a second wrapped keyset — plus fresh sync authority
  and device private keys on disk permanently.

Note and canvas purge, retention, backup create and successful restore, and
`fs-safe.ts` were probed and are unaffected. The Rust analogue at
`src-tauri/src/lib.rs:5410` (`remove_dir_all` in `remove_attachment`) is
UNVERIFIED: it could not be built on this host. This is a product defect with
security consequences and is not closed by 16.3. It is owned by 16.6:
[the Phase 16.6 plan](2026-09-14-phase-16-6-non-ascii-vault-removal.md). 16.6
has since closed it for `src/`: `purgeAttachment`/`removeAttachment`, re-key
and identity rotation, and every other removal under `src/` now go through
`src/fs-tree.ts`, and a source scan fails on any host if a banned removal
call returns. The Rust analogue stays UNVERIFIED, unchanged.

## Phase 16.4 — One flaky test

`test/portable-sync.test.mjs:13`, "encrypted backup plus relay catch-up restores
every portable live object", failed once inside the full suite with
`TypeError: fetch failed` / `ECONNRESET` from `SyncRelayClient.downloadChanges`,
and passed when the file was run alone. The suite runs several files concurrently,
each with its own loopback relay.

- [ ] Determine whether the reset comes from the relay closing a connection under
      concurrent load, from port reuse between test files, or from a real
      client-side gap in handling a dropped connection mid-download.
- [ ] Fix the cause. A retry is only acceptable if the investigation shows the reset
      is legitimate and the client should survive it — in which case the retry
      belongs in the client with a test, not in the test.
- [ ] Do not mark this closed on a single green run. Run the full suite repeatedly.

**Second instance, 2026-09-14.** A later full run failed a different test in the
same file: "portable state remains readable after an ordinary content re-key",
with `EPERM: operation not permitted, rename` while installing
`.rekey/new/documents/sync/changes/<id>.change.enc` into the live vault under
`%TEMP%` — an all-ASCII path, so not the 16.2/16.3 Node defect. Run alone it
passed 3/3. The branch it ran on changed nothing under `src/`. Both instances
appear only inside the concurrent full suite, so the investigation should cover
the re-key install's `renameSync` under load as well as the relay download; a
Windows rename that fails with `EPERM` while another process briefly holds the
file is a durability question for re-key, not only a test-harness one.

## Phase 16.5 — The dependency backlog nobody has triaged

Twelve Dependabot pull requests are open, the oldest from 2026-08-31. Five of them
are major-version bumps of crates in the audited cryptographic surface:
`aes-gcm` 0.10 → 0.11 (#5), `rand` 0.8 → 0.10 (#7), `sha2` 0.10 → 0.11 (#9),
`ed25519-dalek` 2.2 → 3.0 (#10), `hmac` 0.12 → 0.13 (#11). The rest are Actions and
npm development dependencies, including a `commander` major (#3).

A crypto crate major is not a routine bump here. The cross-core vectors exist
precisely to detect a changed byte on the wire, and these crates sit under the
keyring, the audit chain and the sync envelope.

### Task 1: Triage, in two piles

- [ ] Take the Actions and npm development updates as ordinary maintenance, in one
      batch, on CI evidence.
- [ ] Take each crypto crate separately, with its own review: what changed in the
      release, whether any committed vector or fixture changes by a single byte, and
      whether the cross-core tests still agree.
- [ ] Record any bump deliberately declined and why, so the PR is not reopened
      monthly without an answer.

### Acceptance gate

- [ ] Every open Dependabot PR is merged, closed with a recorded reason, or has a
      named blocker.
- [ ] No committed fixture or cross-core vector changed silently as a result.

## Required verification commands

Run from PowerShell on Windows. Record exit codes, not the absence of visible
errors.

```powershell
npm.cmd install
npm.cmd run lint
npm.cmd run typecheck
npm.cmd test
npm.cmd run test:platform-artifacts
npm.cmd run test:release
npm.cmd run test:update-acceptance
npm.cmd run desktop:test
npm.cmd run desktop:build
npm.cmd run quality:rust
npm.cmd run package:check
```

`npm run format:check` is expected to report carriage-return differences on a
Windows checkout; confirm that is all it reports rather than running
`npm run format`. `quality:rust` requires Visual Studio Build Tools with the C++
option; without them, record it as not run.

## Handoff format for every subphase

Report completed items and their evidence; changed files and user-visible behavior;
tests added and exact command results; security and compatibility risks reviewed;
platform evidence still pending; and the next smallest safe step.
