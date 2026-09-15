# Phase 16.5 — npm updates

Phase 16.5 triages the open Dependabot updates (see "Phase 16.5" in
[`2026-09-14-phase-16-verification-findings.md`](2026-09-14-phase-16-verification-findings.md)).
This plan takes the npm side: `commander` 15 (#3) and the `npm-development`
group (#50). Rebased onto main, #3 is green. #50 fails before any test runs:
`npm ci` stops with `ERESOLVE` because `typescript-eslint` 8.70.0 declares
`peer typescript@">=4.8.4 <6.1.0"` and the group raises `typescript` to 7.0.2.

Decisions (2026-09-15):

- `commander` 15 is taken. It requires Node.js 22.12 or later, so
  `package.json` `engines.node` becomes `">=22.12"`. CI already runs Node 22.
  Node 20 reached end of life in April 2026.
- From #50, every update is taken except two: `typescript` stays on 5.x until
  `typescript-eslint` supports 7, and `@types/node` stays on 22.x to match the
  Node line CI runs. Both majors get a Dependabot `ignore` entry with the reason
  in a comment, so the group stops proposing them.

## Global Constraints

- Code, comments, commits and docs in English.
- Versions, exactly as in #50 and #3 (caret ranges, as the repo already uses):
  `@codemirror/state` ^6.7.4, `@codemirror/view` ^6.43.11, `eslint` ^10.10.0,
  `globals` ^17.12.0, `jsdom` ^30.0.1, `lucide-react` ^1.44.0, `react` ^19.3.0,
  `@types/react` ^19.3.0, `react-dom` ^19.3.0, `@types/react-dom` ^19.3.0,
  `typescript-eslint` ^8.70.0, `vite` ^8.3.0, `vitest` ^5.0.0, and
  `commander` ^15.0.0. `typescript` and `@types/node` ranges unchanged.
- `package-lock.json` changes only through `npm install`; it must not contain
  unrelated churn beyond what these updates require (the npm `"peer": true` flag
  churn seen in the main checkout is acceptable only if `npm install` itself
  produces it here; note it in the report).
- `.github/dependabot.yml`: under the npm entry add `ignore` rules for
  `typescript` and `@types/node` with `update-types: ["version-update:semver-major"]`,
  each with a one-line comment giving the reason above. Nothing else changes in
  that file.
- No source or test change unless an update requires it; any such change is
  named and justified in the report. No test is weakened or skipped.
- Local verification, all from this worktree, exit codes recorded: `npm run lint`,
  `npm run typecheck`, `npm test`, `npm run test:platform-artifacts`,
  `npm run test:release`, `npm run test:update-acceptance`, `npm run desktop:test`,
  `npm run desktop:build`, `npm run package:check`. `format:check` and
  `quality:rust` are recorded with their known host limits (CRLF-only warnings;
  no MSVC) rather than as passes.

## Task 1: Apply the updates

- Edit `package.json` per the constraints, run `npm install`, add the Dependabot
  ignores, fix anything the updates break (commander 15 is ESM-only and changes
  `--no-*` option defaults: check every `.option("--no-...")` in `src/cli.ts`
  and the CLI tests), run the local verification set.
- Record the evidence below, then commit.

## Evidence

Worktree: `chore/phase-16-5-npm-updates`, branched from main `8fe108d`. Host
Node v24.11.1, npm 11.6.2.

### Baseline

- `npm ci` on the unchanged lockfile: clean, `added 413 packages ... found 0
  vulnerabilities`, exit 0.

### Changes

- `package.json`: `engines.node` `">=20"` -> `">=22.12"`; `commander`
  `^12.1.0` -> `^15.0.0`; every devDependency in the Global Constraints list
  bumped to the exact version given there. `typescript` (`^5.7.2`) and
  `@types/node` (`^22.10.0`) left unchanged, as decided.
- `.github/dependabot.yml`: added an `ignore` block under the npm entry for
  `typescript` and `@types/node` majors, each with a one-line reason comment.
  Nothing else in the file changed.
- `npm install`: `added 12 packages, removed 12 packages, changed 42
  packages`, 0 vulnerabilities, exit 0. One `EBADENGINE` warning: `jsdom@30.0.1`
  wants Node `^22.22.2 || ^24.15.0 || >=26.0.0`; the host's v24.11.1 falls
  just short of that range. This is a warning, not an install failure, and
  CI's `node-version: 22` (floating to the latest 22.x) is expected to satisfy
  it; flagged as a concern below since it isn't satisfied by this exact host
  build.
- No source or test change was needed. `commander` 15's `--no-*` default
  change does not apply: `src/cli.ts` defines no `--no-...` options (grepped;
  only positive flags and one bare `--experimental-trusted-sync` boolean with
  no negated counterpart), so the behavior change described in the plan has no
  surface here.
- `desktop/vite.config.ts` and `desktop/src/test-setup.ts` needed no changes
  for `vitest` 5 / `jsdom` 30 / `react` 19.3 (see desktop:test below).

### Lockfile

- `package-lock.json`: 397 insertions / 389 deletions, touching only the
  version/resolved/integrity fields of the updated packages and their
  transitive dependents — no package name was added or removed (diffed by
  `node_modules/<name>` keys, added-set == removed-set).
- Peer-flag churn: yes, it appeared. 30 lines changed `"peer": true` entries
  (4 removed, 6 removed-with-comma, 20 added) purely as a side effect of
  `npm install` re-resolving the peer graph for the updated packages — no
  manual edits were made to any `"peer"` field. Per the Global Constraint,
  this is acceptable since `npm install` produced it unprompted.

### Verification (all run from this worktree; exit codes as reported)

- `npm run lint` — exit 0, no findings.
- `npm run typecheck` — exit 0 (`tsc -p . --noEmit && tsc -p
  desktop/tsconfig.json`).
- `npm test` — exit 0. `tests 495, pass 495, fail 0, cancelled 0, skipped 0,
  todo 0` (includes `test/portable-sync.test.mjs`; no flake was observed in
  this run, so no isolated re-run was needed).
- `npm run test:platform-artifacts` — exit 0, `tests 9, pass 9`.
- `npm run test:release` — exit 0, `tests 12, pass 12`.
- `npm run test:update-acceptance` — exit 0, `tests 4, pass 4`.
- `npm run desktop:test` — exit 0, `Test Files 13 passed (13)`, `Tests 145
  passed (145)`. First attempt inside this session's default Bash sandbox
  failed with `[vitest-pool]: Failed to start forks worker ... Timeout
  waiting for worker to respond` for every file (13 errors, 0 tests run) —
  this is the sandbox blocking the subprocess spawns vitest's default
  `forks` pool needs, not a `vitest` 5/`jsdom` 30 regression: the same exact
  `npm run desktop:test` command (unchanged `forks` pool, unchanged config)
  passed cleanly once run with the sandbox disabled, and `--pool=threads`
  also passed cleanly inside the sandbox. No config or code change was made;
  recorded here so a future run knows to disable the sandbox (or use
  `--pool=threads`) for this script in this harness.
- `npm run desktop:build` — exit 0 (`tsc -p desktop/tsconfig.json && vite
  build --config desktop/vite.config.ts`, `built in 45.57s`).
- `npm run package:check` — exit 0 (`npm pack --dry-run --json`, 63 entries).
- `npm run format:check` — exit 1, as expected from the known host limit.
  13 files flagged as CRLF-only on this host (the original 5 —
  `package.json`, `src-tauri/tauri.conf.json`,
  `src-tauri/capabilities/main.json`, `.github/workflows/ci.yml`,
  `.github/workflows/release.yml` — plus `eslint.config.js`,
  `tsconfig.json`, `desktop/tsconfig.json`, `desktop/vite.config.ts`,
  `src-tauri/tauri.linux.conf.json`, `src-tauri/tauri.macos.conf.json`,
  `src-tauri/tauri.windows.conf.json`, and the newly-touched
  `.github/dependabot.yml`; this worktree's checkout evidently normalizes
  more files to CRLF than the main checkout does, which is a pre-existing
  environment difference and out of scope). Checked specifically:
  `package.json` and `.github/dependabot.yml` — the two files this task
  edited — were diffed against their own `prettier --write` output with line
  endings stripped from both sides, and the diff was empty; the only
  difference Prettier objects to is CRLF, so no fix was applied. Recorded as
  a known-limit failure, not a pass.
- `quality:rust` — NOT RUN. No MSVC linker on this host (`cl.exe` not found);
  `rustc 1.98.1` is present but `cargo clippy`/`cargo test` for the Tauri
  crate require the MSVC toolchain this host lacks.

### Concerns

- `jsdom@30.0.1`'s engines range (`^22.22.2 || ^24.15.0 || >=26.0.0`) is not
  satisfied by the exact host Node build used for this task (v24.11.1); it
  produced an `EBADENGINE` warning on `npm install` but did not fail the
  install or any test. CI's `actions/setup-node` with `node-version: 22`
  resolves to the newest available 22.x, which should clear
  `^22.22.2`, but this is unverified against the exact CI runner image.
- `desktop:test`'s default `forks` pool does not start worker processes
  inside this session's sandboxed Bash tool; verified as a sandbox artifact,
  not a version regression (see Verification above), but worth knowing if a
  future `npm run desktop:test` run in a similarly sandboxed shell reports
  the same 13 "Failed to start forks worker" errors with 0 tests run —
  disable the sandbox or pass `--pool=threads`.
