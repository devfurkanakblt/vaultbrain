# Phase 16.6 follow-up — clean `desktop-dist/` through the verified helper

The desktop follow-up (PR #71,
`docs/superpowers/plans/2026-09-15-phase-16-6-non-ascii-desktop.md` on
`fix/phase-16-6-desktop-removal-scan`) recorded, and did not fix, that Vite's
own `emptyOutDir` has the Phase 16.6 defect. This plan fixes it.

**The defect.** Measured on Windows 11 with Node v24.11.1: when any path
component is non-ASCII, Node's single-call recursive removal removes nothing
and returns normally (see
[`2026-09-14-phase-16-6-non-ascii-vault-removal.md`](2026-09-14-phase-16-6-non-ascii-vault-removal.md)).
Vite 8.3.0 empties `build.outDir` with exactly that call (`emptyDir` in
`node_modules/vite/dist/node/chunks/node.js` calls it on each entry). So under
`OneDrive\Masaüstü` stale files in `desktop-dist/` survive a
`npm run desktop:build` that exits 0, and `tauri build`, which runs
`desktop:build` as `beforeBuildCommand` and packages `frontendDist:
../desktop-dist`, can ship them.

**Precedent.** Phase 16.2 made `scripts/clean-dist.mjs` remove `dist/` with
`scripts/fs-tree.mjs` and then prove nothing survived before `tsc` runs. This
plan points the same command at `desktop-dist/`.

## Global Constraints

- Code, comments, commits and docs in English.
- One cleaning implementation: `cleanDist` in `scripts/clean-dist.mjs`. No
  second copy for the desktop output.
- The command accepts only a known build output name (`dist`,
  `desktop-dist`), never a path, because it removes what it is pointed at.
  No argument keeps today's behavior (`dist`), so `npm run build` is unchanged.
- A removal that does not remove fails the build and names what survived; no
  retries, no fallback to Vite's emptying.
- Every path that writes `desktop-dist/` goes through the clean: CI's
  `npm run desktop:build`, and `tauri build` (CI `rust` job, release workflow
  via `npm run tauri:build`, local) through `beforeBuildCommand`. No workflow
  calls `vite build` or `tauri build` directly.
- Release CI behavior on ASCII paths stays equivalent: the output directory is
  still empty before Vite writes to it; only the code that empties it changes.
- `docs/ROADMAP.md` is not edited here: PR #71 edits the same 16.6 entry. The
  ROADMAP link to this plan lands after #71 merges.
- Do not commit the unrelated `package-lock.json` diff.

## Task 1: Tests first

**Files:** `test/clean-dist.test.mjs` (already in `npm test`).

- Under a `mkdtemp` root named `clean-dist-ü-é-`, copy `scripts/clean-dist.mjs`
  and `scripts/fs-tree.mjs` into `<root>/scripts/` and run the real command
  with `spawnSync`:
  - `desktop-dist` seeded with `index.html`, `stale.txt`, `stale-dir/x.txt` and
    `assets/index-old.js` is gone after `clean-dist.mjs desktop-dist`, exit 0,
    and a sibling `dist/` is left alone.
  - No argument still cleans `dist/`.
  - `src`, `..`, and two names at once are refused with a nonzero exit, and
    `src/` is left in place.
  - A linked `desktop-dist` fails with exit 1 and
    `Refusing to clean a linked desktop-dist directory`, and the link target's
    contents survive.
- Unit: `cleanDist` on a non-ASCII `desktop-dist` with a removal that returns
  without removing (what Vite's emptying does on this host) throws, naming
  `stale.txt` and `x.txt`.
- Wiring: `desktop:build` starts with `node scripts/clean-dist.mjs
desktop-dist && `; every npm script running `vite build` does too;
  `tauri.conf.json` keeps `beforeBuildCommand: "npm run desktop:build"` and
  `frontendDist: "../desktop-dist"`; no `tauri.*.conf.json` overlay replaces
  `beforeBuildCommand`; no workflow calls `vite build` or `tauri build`
  directly; `desktop/vite.config.ts` writes to `../desktop-dist` with
  `emptyOutDir: false`.
- Test cleanup uses `removeTree` from `scripts/fs-tree.mjs`, so
  `test/fs-removal.test.mjs` stays green.

## Task 2: Wiring

**Files:** `scripts/clean-dist.mjs`, `package.json`, `desktop/vite.config.ts`.

- `scripts/clean-dist.mjs`: export `BUILD_OUTPUTS = ["dist", "desktop-dist"]`;
  the entry point takes at most one name from that list (default `dist`) and
  refuses anything else; the linked-directory message names the directory
  (`dist` keeps its existing wording).
- `package.json`: `desktop:build` becomes
  `node scripts/clean-dist.mjs desktop-dist && tsc -p desktop/tsconfig.json &&
vite build --config desktop/vite.config.ts`.
- `desktop/vite.config.ts`: `emptyOutDir: false`, with a comment saying the
  clean runs first and why Vite's own emptying is not used.
- `src-tauri/tauri*.conf.json` and `.github/workflows/*` need no change: they
  already reach `desktop-dist/` only through `npm run desktop:build`.
  `desktop:dev` serves from memory and writes no `desktop-dist/`.

## Task 3: Documentation

**Files:** this plan.

- Fill in Evidence below. ROADMAP after #71 (see Global Constraints).

## Evidence

Base: `origin/main` at `54364c8`. Host: Windows 11, Node v24.11.1, Vite 8.3.0
(from `npm ci` in the worktree).

### RED: the old wiring under a non-ASCII path

- Vite alone, old config (`emptyOutDir: true`): with `stale.txt` and
  `stale-dir/x.txt` seeded into `<scratchpad>/vite-red-ascii/desktop-dist` and
  `<scratchpad>/vite-red-ü/desktop-dist`, `npx vite build --config
desktop/vite.config.ts --outDir <dir> --emptyOutDir` exited 0 both times. The
  ASCII directory held only `assets/` and `index.html`; the `ü` directory held
  `assets/`, `index.html`, `stale.txt` and `stale-dir/`.
- End to end: a detached worktree of `54364c8` at `<scratchpad>/desktop-ü-red`
  (with `node_modules` junctioned in), `desktop-dist/` seeded with `stale.txt`
  and `stale-dir/x.txt`, `npm run desktop:build` exited 0 and left
  `assets/`, `index.html`, `stale-dir/` and `stale.txt`.
- Tests: with Task 1's tests added and Task 2 not yet applied,
  `node --test test/clean-dist.test.mjs` gave `tests 12`, `pass 8`, `fail 4`:
  the non-ASCII `desktop-dist` clean (the command ignored the argument and
  cleaned `dist/`, so `desktop-dist must be gone, stale files included`
  failed), the refusal of a non-output name, the linked-`desktop-dist`
  refusal, and the wiring test (`desktop:build` did not start with the clean).
  The six existing tests and the no-argument and silent-removal tests passed.

### GREEN

- `node --test test/clean-dist.test.mjs`: `tests 12`, `pass 12`, `fail 0`.
- Manual, new config (`emptyOutDir: false`): `<scratchpad>/vite-green-ü` with
  copies of the two scripts and `desktop-dist/` seeded with `stale.txt`,
  `stale-dir/x.txt` and `assets/index-old.js`. `node
scripts/clean-dist.mjs desktop-dist` exited 0 and removed `desktop-dist/`;
  `npx vite build --config desktop/vite.config.ts --outDir
<scratchpad>/vite-green-ü/desktop-dist` exited 0 and wrote `assets/` (23
  files, no `index-old.js`) and `index.html`. Control without the clean, same
  config, `vite-control-ü`: `stale.txt` survived next to the new output, as
  expected once Vite no longer empties.
- End to end: a detached worktree of the Task 2 commit `e685460` at
  `<scratchpad>/desktop-ü-green`, seeded the same way plus
  `assets/index-old.js`: `npm run desktop:build` exited 0, printed
  `node scripts/clean-dist.mjs desktop-dist && tsc -p desktop/tsconfig.json &&
vite build --config desktop/vite.config.ts`, and left only `assets/` (23
  files, `index-old.js` absent) and `index.html`.
- Fails loudly, end to end: in the same worktree, with `desktop-dist` replaced
  by a junction to a sibling directory holding `keep.js`, `npm run
desktop:build` exited 1 with `Refusing to clean a linked desktop-dist
directory.`, Vite never started, and `keep.js` survived.
- Both `ü` worktrees were removed with `git worktree remove --force` after
  their `node_modules` (and `desktop-dist`) junctions were unlinked with
  `rmdir`, leaving the linked `node_modules` intact.

### CI finding: the entry-point guard skipped the command through a link

The first CI run on PR #72 (`498a699`) failed `node-platform (macos-15)`: the
four tests that run the real command saw it exit 0 having done nothing.
`scripts/clean-dist.mjs` ran its CLI only when `path.resolve(process.argv[1])`
equaled `fileURLToPath(import.meta.url)`. Node resolves links in the main
module's URL but not in `argv[1]`, and on macOS `os.tmpdir()` (`/var/...`) is a
link to `/private/var/...`, so the guard was false, the command skipped
itself, and exit 0 reported a clean that never happened. The same holds for
any checkout reached through a link, on any platform. Every other job passed,
`node-platform (windows-latest)` and `typescript` included.

- Fix: the guard compares `fs.realpathSync` of both sides.
- Test: "the clean command still cleans when run through a linked checkout
  directory" runs the command through a junction (a symlink on macOS and
  Linux) to the non-ASCII root, so every platform covers this.
- RED on this host: with the new test and `scripts/clean-dist.mjs` from
  `e685460` (old guard), `node --test --test-name-pattern "linked checkout"
test/clean-dist.test.mjs` gave `pass 0`, `fail 1`
  (`desktop-dist must be gone when the command runs through a link`).
- GREEN: with the new guard the same command passed; `node --test
test/clean-dist.test.mjs test/fs-removal.test.mjs` gave `tests 22`,
  `pass 22`, `fail 0`, and `npx eslint scripts/clean-dist.mjs
test/clean-dist.test.mjs` was clean.

Found beyond this plan: `scripts/rust-toolchain.mjs`,
`scripts/platform-artifacts.mjs` and
`scripts/release/native-update-acceptance.mjs` use the same
`path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)` guard, so
run through a linked checkout they would also skip themselves and exit 0.
CI checkouts are not linked, and none of them removes a build output, so this
is recorded, not fixed.

### Local verification

Run in the ASCII worktree on the Task 2 commit `e685460`.

- `npm ci`: PASS (exit 0, `package-lock.json` unchanged).
- `npm run build`: PASS.
- `node --test test/clean-dist.test.mjs`: PASS, 12/12.
- `npm test`: PASS, `tests 503`, `pass 503`, `fail 0` (was 497 before this
  plan; six new tests). After the entry-point guard fix and its test:
  `tests 504`, `pass 504`, `fail 0`, and `npm run desktop:build` PASS again.
- `npm run lint`: PASS.
- `npm run typecheck`: PASS.
- `npm run desktop:test`: PASS, 13 files, 145 tests.
- `npm run desktop:build`: PASS; the output starts with
  `node scripts/clean-dist.mjs desktop-dist && ...` and Vite reports
  `built in 357ms`.
- `npm run package:check`: PASS; no `desktop-dist` path in the packed file
  list.
- `npm run test:release`: PASS, 12/12.
- `npm run format:check`: FAIL on this host, CRLF only. Prettier warns on all
  13 checked files, including `package.json` and `desktop/vite.config.ts`.
  The other 11 match `origin/main` (`git diff` over them is empty).
  `npx prettier --check --end-of-line auto` over the same 13 files plus this
  plan passes, and `cargo fmt -- --check` passes. This is the known Windows
  `core.autocrlf=true` artifact, identical on `origin/main`.
