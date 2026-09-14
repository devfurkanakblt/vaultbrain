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

- [ ] Write the decision down before writing code. Two candidates: resolve the path
      with `fs.realpathSync` and record the resolved target in the managed config,
      so the configuration names the binary that will actually run; or keep refusing
      and tell the user the exact resolved path to pass instead.
- [ ] State which threat the choice addresses and which it accepts. Resolving pins
      the binary but freezes the nvm version, so a later `nvm use` silently leaves
      the configuration pointing at an older interpreter. Refusing keeps the user in
      control but makes the command unusable for a common, legitimate setup.
- [ ] Record whether the same reasoning applies to `nativeExecutable` and `cliPath`,
      which go through the identical check.

### Task 2: Implement the decision

- [ ] Add a failing test that constructs a symlinked interpreter path itself rather
      than depending on how the host's Node happens to be installed — the current
      tests pass on CI purely because a Linux runner's Node is not symlinked, which
      is why this was never caught.
- [ ] Implement the decided behavior and assert on what lands in the managed TOML,
      not just on the absence of a throw.
- [ ] Cover the negative case that the guard exists for: a path component that is a
      symlink pointing somewhere unexpected must still be refused or resolved
      visibly, never silently accepted.

### Acceptance gate

- [ ] `vbrain memory setup` completes on a host whose Node is managed by
      nvm-windows, or refuses with a message naming the exact path to use instead.
- [ ] The managed MCP entry names a path whose meaning is stable and documented.
- [ ] A test fails if the decided behavior regresses, on any host.

## Phase 16.2 — A build that cannot prove it cleaned itself

Phase 14.3 retired `src/sync/change-log.ts`, and `test/package.test.mjs:10` asserts
that neither the source nor `dist/sync/change-log.js` survives. On this host the
test failed: `dist/sync/change-log.js` was still present, dated five days before
the run, because `fs.rmSync(output, { recursive: true, force: true })` in
`scripts/clean-dist.mjs` had failed to remove it and reported nothing. Deleting
`dist` by hand and rebuilding made the test pass.

The stale file is the small consequence. The real one is that a build claimed
success while the output directory still held a retired implementation — the exact
failure mode Phase 13 exists to prevent, and the reason `package.test.mjs` was
written in the first place. On a host where a sync client, an antivirus scanner or
an open handle holds one file, `clean-dist` is a no-op that nobody is told about.

### Task 1: Make the clean verifiable

- [ ] Add a failing test: with a file in `dist` that cannot be removed, the build
      must fail loudly rather than continue.
- [ ] After the removal, assert the directory is actually gone before `tsc` runs;
      report the paths that survived.
- [ ] Keep the existing refusal to clean a linked `dist`. Do not add retry loops
      that hide the condition instead of reporting it.

### Acceptance gate

- [ ] A build cannot report success while a previous build's output survives.
- [ ] The failure message names the files that could not be removed.

## Phase 16.3 — Checks that cannot run, and checks that lie

Four of the repository's own commands behave differently on a real Windows
developer machine than in CI. None of these is a product defect; all four cost a
reviewer time and can be mistaken for one, which is itself the problem.

1. **`fs.cpSync` crashes Node** under this OneDrive-synced checkout. Reproduced
   directly outside the suite: `fs.cpSync('dist/sync', <temp>, {recursive:true})`
   exits `-1073740791` (`0xC0000409`, stack buffer overrun) on Node v24.11.1. It
   takes down `test/desktop-sync-helper.test.mjs`, which builds the helper through
   `scripts/build-desktop-sync-helper.mjs:18`. The project ledger recorded this in
   Phase 7.1 and it is still live.
2. **`tar` resolves to the wrong program** under Git Bash. GNU tar reads
   `C:\Users\...` as a remote host and fails with `Cannot connect to C: resolve
   failed`; `test/platform-artifacts.test.mjs` fails two tests. The same command
   passes 8/8 from PowerShell, where `tar` is `C:\windows\system32\tar.exe`.
3. **`format:check` reports five files that are byte-identical to Prettier's own
   output** once carriage returns are stripped. `.gitattributes` sets `* text=auto`,
   so Windows checks out CRLF while Prettier defaults to `endOfLine: "lf"`. Running
   `npm run format` locally to "fix" it rewrites the files to LF and produces a diff
   that is pure noise.
4. **`quality:rust` cannot run at all.** `cargo 1.98.1` is installed but no Visual
   Studio Build Tools are (`vswhere.exe` is absent), so `link.exe` is missing and
   every build script fails to link. Every Rust guarantee on this machine currently
   rests on CI alone — including, today, the entire Phase 15 broker.

### Task 1: Say all of this once, where a contributor will read it

- [ ] Add a Windows section to `CONTRIBUTING.md`: run the suite from PowerShell,
      not Git Bash; do not run `npm run format` on a CRLF checkout; a checkout
      inside a cloud-synced folder will crash the helper build.
- [ ] Name the Build Tools prerequisite and state plainly that without it the Rust
      half of the project is unverified locally.

### Task 2: Make the environment failures self-describing

- [ ] Where a test depends on a host-provided program, check the precondition and
      fail with a message that names the cause — "GNU tar cannot read a Windows
      path; run this from PowerShell" is a diagnosis, `status 128` is not.
- [ ] Do not convert any of these into a skip. A check that did not run is recorded
      as a gap, per the Phase 14 rule.
- [ ] Decide whether `scripts/build-desktop-sync-helper.mjs` should stop using
      `fs.cpSync`. A recursive copy helper avoids a crash the project has now hit
      twice in different phases; the earlier decision to avoid `cpSync` in tests was
      taken for exactly this reason and never reached the build scripts.

### Acceptance gate

- [ ] A contributor on Windows can tell, from the failure message alone, which
      failures are theirs and which are their environment's.
- [ ] No environment-dependent check reports success without running.

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
