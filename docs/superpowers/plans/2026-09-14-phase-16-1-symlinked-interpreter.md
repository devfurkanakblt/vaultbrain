# Phase 16.1 — Resolve a symlinked executable path, and say so

**Goal:** `vbrain memory setup` works for a vault owner whose Node is managed by
nvm-windows, without accepting a symbolic-link path silently. The managed MCP entry
names the binary that will actually run, and the owner is told exactly what was
resolved.

**Origin:** Phase 16.1 in
[the Phase 16 plan](2026-09-14-phase-16-verification-findings.md). On the host that
found it, `process.execPath` is `C:\nvm4w\nodejs\node.exe`; `C:\nvm4w\nodejs` is a
directory link to `C:\Users\<user>\AppData\Local\nvm\v24.11.1`. `installMemoryConfig`
in `src/memory/setup.ts` runs every path through `assertNoSymlinkComponents` and
refuses with `Refusing symbolic-link path component: nodejs`, so both setup tests in
`test/memory-client.test.mjs` fail there, and so does the real command.

## Decision

Resolve, then record and show the resolved path.

- `nodeExecutable`, `nativeExecutable` and `cliPath` are each resolved with
  `fs.realpathSync` before they are checked. The resolved path, not the path the
  caller gave, goes through the existing absolute-path, control-character,
  no-symlink-component and regular-file checks, and is what lands in the managed
  TOML (`command`, and both paths in `args`).
- `configPath` is not resolved. It keeps refusing a symbolic-link component: a link
  there redirects where setup writes, which is the threat the guard exists for, and
  no common installation puts the client configuration behind one.
- Setup reports every executable path whose resolved form differs from what was
  given, and the CLI prints each as `given -> resolved`, followed by a note that
  setup must be run again after switching Node versions.

Threat addressed: a symbolic link in the configured `command` would let whoever can
retarget the link change the executable that runs, without touching the
configuration. Pinning the resolved binary closes that. Accepted: after `nvm use`,
the configuration still names the previous interpreter until setup is run again;
the printed note says so, and the older binary stays a real, unchanged file.
Rejected alternative: refusing and naming the resolved path. It keeps the owner in
control, but every nvm-windows user would hit a refusal on first use for a setup
that is legitimate, and the path they would be told to pass is the same one this
decision records automatically — with the owner still told what it is.

A link that resolves to nothing (dangling) makes `fs.realpathSync` throw `ENOENT`;
setup refuses and names the path it could not resolve. Measured on the finding
host: `fs.realpathSync` and `fs.realpathSync.native` both resolve a directory
junction correctly under an all-ASCII and under a non-ASCII temporary path, and both
throw `ENOENT` for a dangling junction.

## Global constraints

- Read `AGENTS.md` and the surrounding code before changing it.
- Work test-first. Tests construct the symbolic link themselves (a directory
  junction, `fs.symlinkSync(realDir, linkDir, "junction")`, which needs no elevated
  rights on Windows) rather than depending on how the host's Node is installed.
  A test that passes only because a Linux runner's Node is not symlinked is the
  reason this was never caught.
- Assert on what lands in the managed TOML, not only on the absence of a throw.
- Do not weaken the guard: every path that ends up in the configuration must still
  have no symbolic-link component at the moment it is checked, and `configPath`
  keeps refusing one.
- Do not use `fs.rmSync` or `fs.cpSync` anywhere; `src/` is scanned for them by
  `test/fs-removal.test.mjs`, and tests clean non-ASCII fixtures with `removeTree`
  from `../dist/fs-tree.js`.
- No change to the managed block's markers, digest line or TOML shape.

## Task 1: Resolve executable paths in installMemoryConfig

- [ ] In `test/memory-client.test.mjs`, add failing tests. Each builds, under a
      temporary root, a real directory holding a regular file and a junction to that
      directory, and passes the file's path *through the junction*:
  - Node executable through a junction: setup succeeds; the managed TOML's
    `mcp_servers.vaultbrain_memory.command` equals `fs.realpathSync` of the given
    path and differs from the given path; the returned report lists it with its
    given and resolved forms.
  - Native executable and CLI entry through a junction: both resolved paths appear
    in `args` in their existing positions, and the report lists both.
  - No links anywhere: the report is empty and the TOML names the given paths.
  - A dangling junction: setup throws an error naming the path it could not resolve,
    and the configuration file is unchanged (no managed block, no backup written).
  - `configPath` whose directory is reached through a junction: setup still refuses
    with the symbolic-link refusal, and nothing is written.
  - One case built under a non-ASCII temporary directory (for example
    `memory-link-ü-é-`), so the resolution is exercised on the path class that
    broke Phase 16.6.
- [ ] Update the two existing setup tests, which pass `process.execPath`: expect the
      resolved path in the TOML (`fs.realpathSync(process.execPath)`), so they pass
      on any host and still fail if the resolution regresses.
- [ ] Run `npm run build` and `node --test test/memory-client.test.mjs`; record the
      failures.
- [ ] Implement in `src/memory/setup.ts`: resolve the three executable paths first
      (keeping the absolute-path and control-character check on the given path
      before resolution), check the resolved paths with the existing guard and
      regular-file check, write the resolved paths into the table, and return
      `{ backupPath, resolvedPaths }` where `resolvedPaths` is an array of
      `{ name: "nodeExecutable" | "nativeExecutable" | "cliPath", given, resolved }`
      entries for paths that changed. Keep `checkedPath` for `configPath` unchanged.
      Wrap the `ENOENT` from resolution in an error that names the given path.
- [ ] `npm run build`, `node --test test/memory-client.test.mjs`, `npm run lint`,
      `npm run typecheck` pass. Commit.

## Task 2: Show the resolution, and record the evidence

- [ ] In `src/memory/cli.ts`, after `installMemoryConfig` returns in the `setup`
      action, print one line per `resolvedPaths` entry,
      `Resolved symbolic link for <name>: <given> -> <resolved>`, and when there is
      at least one, a line saying the configuration names the resolved binaries and
      setup must be run again after switching Node versions. Keep the existing
      success line. Cover the formatting with a test if it can be exercised without
      the native executable (extract a small exported formatting function from
      `src/memory/setup.ts` or `src/memory/cli.ts` and test that); otherwise record
      why it is untested.
- [ ] Run the full `npm test`, `npm run lint`, `npm run typecheck`. Record exact
      totals; the two `test/memory-client.test.mjs` failures that Phase 16 recorded
      must be gone. Name every remaining failure (a `test/portable-sync.test.mjs`
      failure under concurrent load belongs to 16.4).
- [ ] In `docs/superpowers/plans/2026-09-14-phase-16-verification-findings.md`,
      tick the 16.1 Task 2 and Acceptance gate items that are satisfied and add a
      `### Evidence` section in the style of 16.2's: fail-before and pass-after
      counts from this host, the new tests, full-suite totals. In
      `docs/ROADMAP.md`, tick 16.1. Tick this plan's boxes and add a short
      `## Evidence` pointer to that section.
- [ ] Commit.

## Acceptance gate

- [ ] `vbrain memory setup` completes on a host whose Node is managed by
      nvm-windows, and prints the resolved interpreter path.
- [ ] The managed MCP entry names resolved, link-free paths, and this plan documents
      what that means after a Node version switch.
- [ ] A test fails on any host if resolution regresses, if a dangling link is
      accepted, or if a linked `configPath` stops being refused.
