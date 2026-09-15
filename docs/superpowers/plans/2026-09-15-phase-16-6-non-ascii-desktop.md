# Phase 16.6 follow-up — non-ASCII removal in desktop/

The tests follow-up
([`2026-09-15-phase-16-6-non-ascii-tests.md`](2026-09-15-phase-16-6-non-ascii-tests.md))
recorded `desktop/` as out of scope: a grep found no banned call there, but the
source scan in `test/fs-removal.test.mjs` does not walk it, so a new call could
land unnoticed. This plan closes that.

**The defect.** Measured on Windows 11 with Node v24.11.1: when any path
component is non-ASCII, every `fs.rmSync` call removes nothing and returns
normally, and `fs.cpSync({ recursive: true })` aborts the process with
0xC0000409. The main checkout lives under `OneDrive\Masaüstü`, so any Node code
under `desktop/` that removes files is exposed on this host.

## Global Constraints

- Code, comments, commits and docs in English.
- Any real banned call under `desktop/` moves onto the existing helpers: code
  loaded by Node at build or test time takes `scripts/fs-tree.mjs`; nothing in
  the webview bundle may import either helper, since it has no Node runtime.
- The scan covers everything under `desktop/` that Node can load, including
  webview sources: they are cheap to scan, and a file that is bundle-only today
  can be imported by a Vitest file tomorrow.
- Exclusions: third-party code only (`node_modules`). No exemption for any
  first-party file. Build output needs no rule: Vite writes to `desktop-dist/`
  at the repository root, outside the scanned tree.
- Do not commit the unrelated `package-lock.json` diff.

## Task 1: Inventory `desktop/`

**Files:** every tracked file under `desktop/`.

- Run `findBannedCalls` over every `.ts`/`.tsx`/`.mts`/`.cts`/`.mjs`/`.cjs`/
  `.js`/`.jsx` file under `desktop/`, and a plain grep for the rm/cp family,
  `node:` imports, `require(` and `fs/promises`.
- For each file, record whether Node's `fs` is reachable at all.
- Convert any real banned call per the rules of the tests follow-up.

## Task 2: Extend the source scan to `desktop/`

**Files:** `test/fs-removal.test.mjs`.

- Add `desktop/` as a fourth tree with the extensions above.
- Skip `node_modules` directories by name, with a comment saying why and why
  build output needs no rule.
- Update the test title and the comment above `findBannedCalls` to name
  `desktop/`.
- Non-vacuity: temporarily add one banned call to a Vitest file and one to
  `desktop/vite.config.ts` (uncommitted), record the failure naming both, and
  revert. Separately, put a banned call in a throwaway `desktop/node_modules/`
  file and confirm the scan still passes, so the exclusion is shown to work
  rather than assumed.

## Task 3: Documentation

**Files:** this plan, `docs/ROADMAP.md`.

- ROADMAP 16.6: add one sentence that the scan now covers `desktop/`, linking
  this plan. No checkbox change.
- Fill in Evidence below.

## Evidence

Base: `origin/main` at `54364c8`. Host: Windows 11, Node v24.11.1.

### Task 1: inventory

`findBannedCalls` over all of `desktop/`: zero offenses. A grep for
`rmSync|rmdirSync|cpSync|rm(|rmdir(|cp(|unlink|node:|fs/promises|require(`
matched no file removal call. Its hits were `unlinkedMentions` identifiers and
the `get_unlinked_mentions` / `link_unlinked_mention` Tauri command strings (a
backlinks feature), a `node: CanvasNode` parameter in
`desktop/src/CanvasBoard.tsx`, and one `import path from "node:path"` in
`desktop/vite.config.ts`. No
file under `desktop/` imports `node:fs`, `fs`, or `node:fs/promises`. Nothing
needed converting.

Where Node's `fs` is reachable:

- `desktop/vite.config.ts`: loaded by Node through Vite and Vitest, so `fs`
  is reachable. No banned call; it imports only `node:path`.
- The 13 Vitest files (`desktop/src/*.test.ts(x)` and
  `desktop/src/plugins/host.test.ts`) and `desktop/src/test-setup.ts`: run
  under Node with jsdom, so `fs` is reachable. No banned call; none imports
  `fs`.
- Every other `desktop/src/**/*.ts(x)` file (`App.tsx`, `bridge.ts`,
  `updater.ts`, `plugins/*`, and the rest): bundled by Vite into the Tauri
  webview, which has no Node runtime. `desktop/tsconfig.json` targets `DOM`,
  and file access goes through `invoke` from `@tauri-apps/api/core` to Rust.
  `fs` is not reachable at run time; these files are still scanned because a
  Vitest file can import them.
- `desktop/index.html`, `desktop/src/styles.css`, `desktop/tsconfig.json`:
  the Vite entry, styles and compiler config. No code that makes file calls.

The webview sources import `../../../src/plugins` and
`../../src/desktop-sync-protocol.js`; those live under `src/`, which the scan
already covers. There are no Node-side scripts under `desktop/`.

### Task 2: scan extension

- RED: with `import { rmSync } from "node:fs";` appended to
  `desktop/src/App.test.tsx` and
  `fs.rmSync("x", { recursive: true, force: true });` appended to
  `desktop/vite.config.ts` (both uncommitted), `node --test
test/fs-removal.test.mjs` gave `tests 9`, `pass 8`, `fail 1`, with offenses
  `desktop/src/App.test.tsx:964: import { rmSync } from "node:fs";` (listed
  twice, because two regexes match the same import line, as in the tests
  follow-up) and
  `desktop/vite.config.ts:27: fs.rmSync("x", { recursive: true, force: true });`.
  Both files were reverted with `git checkout --`.
- Exclusion: with a throwaway `desktop/node_modules/probe/index.js` holding
  `fs.rmSync("x", { recursive: true, force: true });`, the same command gave
  `tests 9`, `pass 9`, `fail 0`. The directory was then deleted.
- GREEN on the branch: `npm run build`, then `node --test
test/fs-removal.test.mjs`: `tests 9`, `pass 9`, `fail 0`, including the
  renamed "no source file under src/, scripts/, test/, or desktop/ calls
  Node's non-ASCII-unsafe recursive removal helpers" test and the unchanged
  `findBannedCalls` probe test.

### Local verification

- `npm ci`: PASS (exit 0, `package-lock.json` unchanged).
- `npm run build`: PASS.
- `node --test test/fs-removal.test.mjs`: PASS, 9/9.
- `npm test`: PASS, `tests 497`, `pass 497`, `fail 0`.
- `npm run lint`: PASS.
- `npm run typecheck`: PASS.
- `npm run desktop:test`: PASS, 13 files, 145 tests.
- `npm run desktop:build`: PASS.
- `npm run format:check`: FAIL on this host, CRLF only. Prettier warns on
  all 13 checked files, none of which this branch changes (`git diff
origin/main` over them is empty); `npx prettier --check --end-of-line auto`
  over the same files passes, and `cargo fmt -- --check` passes. This is the
  known Windows `core.autocrlf=true` artifact, identical on `origin/main`.

## Found beyond this plan

Vite's own `emptyOutDir` has the same defect. `desktop/vite.config.ts` sets
`emptyOutDir: true`, and Vite 8.3.0 empties the output directory by calling
Node's recursive removal on each entry (`emptyDir` in
`node_modules/vite/dist/node/chunks/node.js`). Measured on this host: after
seeding an output directory with `stale.txt` and `stale-dir/x.txt`, `npx vite
build --config desktop/vite.config.ts --outDir <dir> --emptyOutDir` exited 0
in both cases, but only the ASCII directory was emptied; under a directory
named `vite-out-ü` both stale entries survived next to the new `index.html`
and `assets/`. In the main checkout `desktop-dist/` sits under `Masaüstü`, and
`src-tauri/tauri.conf.json` uses it as `frontendDist` after running `npm run
desktop:build`, so a local `tauri build` there can bundle stale frontend files
left by an earlier build. CI checkouts have ASCII paths and are not affected.

This is third-party code the scan deliberately skips, so it is recorded, not
fixed. A fix would clean `desktop-dist/` with `scripts/fs-tree.mjs` before the
Vite build (the way `scripts/clean-dist.mjs` owns `dist/`) and set
`emptyOutDir: false`; it changes the release build path and is left for a
separate decision.

### Review follow-up

A read-only review approved the branch. Its low-severity point is applied: the
scan now asserts every tree yields at least one file, so an emptied tree or a
renamed extension fails instead of passing as "no offenses" (today: desktop 47,
src 60, scripts 18, test 52). The grep evidence above now lists every hit, and
the `findBannedCalls` comment no longer claims the function is exported.
