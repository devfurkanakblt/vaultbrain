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
