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

_To be filled by Task 1._
