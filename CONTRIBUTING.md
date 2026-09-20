# Contributing to Vault Brain

Vault Brain is a local-first encrypted knowledge workspace with a TypeScript
CLI/compatibility core, a React desktop interface and a Rust security core. A
change is complete only when it preserves the vault's confidentiality,
durability, portability and cross-core behavior.

## Before you start

- Use a normal GitHub issue for bugs, features and design proposals.
- Follow [`SECURITY.md`](SECURITY.md) instead of opening a public issue for a
  suspected vulnerability.
- Discuss changes to the encrypted format, sync protocol, plugin capability
  model or trust boundaries before implementing them.
- Never use a personal vault, real secret or identifying data in an issue,
  fixture, test or benchmark.

## Development environment

The npm package supports Node.js 20 or newer; CI uses Node.js 22. The complete
native test surface also requires stable Rust with `rustfmt` and `clippy`.
Windows is the primary desktop and native integration target.

```bash
npm ci
npm run typecheck
npm test
npm run desktop:test
npm run desktop:build
```

Use `npm run desktop:dev` for the webview alone, `npm run tauri:dev` for the
native application and `npm run dev -- --help` for the TypeScript CLI.

### On Windows

Four things about a Windows checkout produce failures that look like defects in
this repository and are not. None is caught by CI, because a Linux or Windows
runner has none of them. Read this before filing a bug against a failing check.

**Do not put the checkout under a path containing a non-ASCII character.** This
is the serious one. Measured on Windows 11 with Node v24.11.1: when any
component of a path is non-ASCII — `Masaüstü`, `café`, an accented user name —
every `fs.rmSync` call removes nothing and returns normally (file or directory,
with or without `recursive`, with or without `force`, never even `ENOENT`), and
`fs.cpSync(src, dst, { recursive: true })` aborts the process with `0xC0000409`
(`STATUS_STACK_BUFFER_OVERRUN`). Under an all-ASCII path both behave, and the
same removal from PowerShell succeeds, so this is Node's defect and not the
filesystem's. Cloud sync is not a factor; it was isolated against ASCII and
non-ASCII siblings in the same temp directory. A build that cannot clean its own
output silently compiles over the previous build, so clone to something like
`C:\src\vaultbrain`. The
repository's own scripts walk trees with single-entry calls (see
`scripts/fs-tree.mjs`) rather than relying on those helpers.

**Run the suite from PowerShell or from Git Bash, but know which `tar` you
get.** Git for Windows puts GNU tar ahead of `C:\Windows\System32\tar.exe`
(bsdtar) on PATH. GNU tar reads the leading `C:` of an absolute path as a remote
host and fails with `Cannot connect to C: resolve failed`.
`test/platform-artifacts.test.mjs` now picks the system bsdtar itself and
explains it if no usable reader exists, so this should no longer surprise you.

**`npm run format:check` runs on Windows.** It used to report every checked file
as a style violation: `.gitattributes` sets `* text=auto`, so Windows checks
files out with CRLF, while Prettier defaults to `endOfLine: "lf"`. The advice
was to confirm carriage returns were all it reported and leave them alone, which
meant the one formatting check in `npm run quality` could not be read on the
platform most of this project is developed on. `.prettierrc.json` now sets
`endOfLine: "auto"`, so Prettier accepts the endings the platform checked out
and still reports every real formatting difference. Git continues to normalise
to LF on commit, so the bytes in the repository are unchanged.

**`npm run quality:rust` needs Visual Studio Build Tools** with the "Desktop
development with C++" workload; the Rust core links with MSVC's `link.exe`.
Without it, nothing in `src-tauri/` can be verified locally and every Rust
guarantee rests on CI alone. The command now refuses up front and says so rather
than letting cargo fail per crate. Note that Git for Windows also ships GNU
coreutils `link` as `usr\bin\link.exe`; from Git Bash that shadows the MSVC
linker on PATH, and cargo then reports `link: extra operand '...'`, which names
neither problem.

A check that could not run on your host is a verification gap, not a pass.
Report it as not run; do not convert it into a skip.

## Repository map

- `src/` — CLI, encrypted document engine, grants, plugins, sync and MCP server
- `desktop/` — React workspace and browser-side plugin host
- `src-tauri/` — Tauri application and privileged Rust core
- `test/` — Node integration tests and checked-in compatibility fixtures
- `docs/` — product contract, architecture, roadmap and protocol designs
- `scripts/` — benchmarks and reproducible fixture generation

## Required checks

Run the checks that cover your change while developing. Before opening a pull
request, run the complete suite when your environment supports it:

```bash
npm run quality
npm run quality:rust
npm run benchmark
npm run package:check
```

`npm run quality` covers linting, formatting, both TypeScript projects, Node
tests, desktop interaction tests and the production webview build.
`npm run quality:rust` treats Clippy warnings as errors and runs the Rust core
tests. The default benchmark enforces the 1,000-note budget; use
`benchmark:10k` or `benchmark:100k` when changing indexing, search, storage or
unlock performance.

## Change-specific expectations

- **Encrypted formats:** keep old vaults readable, version new envelopes and
  add a synthetic compatibility fixture plus migration/tamper tests. The
  `secondbrain-vault:*` AAD namespace and
  `secondbrain-vault-plugin-signature-v1\n` signature prefix are immutable
  protocol identifiers.
  Changing one requires an intentional format reset or version bump plus new
  fixtures and migration coverage.
- **Persistence and sync:** add crash, stale-writer, replay, idempotency or
  concurrency coverage as appropriate. Canonical encodings and change IDs must
  remain deterministic.
- **Desktop:** include an interaction test. Preserve keyboard access, focus
  behavior, readable contrast, reduced motion and the rule that the webview
  never receives a vault master key or raw filesystem access.
- **Plugins:** deny unknown capabilities. Keep the TypeScript/browser and Rust
  capability tables aligned, and add signature vectors when canonical package
  encoding changes.
- **MCP and grants:** test both allowed and denied paths. Do not describe agent
  names or redaction as authentication; `VBRAIN_AGENT` is caller-selected.
- **Performance:** report the relevant benchmark before and after the change.
  Do not relax a budget solely to make CI pass.

Generate compatibility fixtures with `npm run fixtures`, review the resulting
diff and commit only synthetic data. Encrypted fixtures are binary and must not
be reformatted or hand-edited.

## Pull requests

Keep each pull request focused and explain:

1. the user-visible behavior or failure being addressed;
2. any storage, compatibility or security impact;
3. the checks and benchmarks run, including anything not run and why;
4. migration or recovery behavior, when persistent data changes.

Do not commit `node_modules/`, build output, local vaults, passphrases, audit
logs or `.env` files. Do not weaken a failing security, durability or
performance gate without a documented design decision.
