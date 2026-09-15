# Phase 16.5 — crypto crate majors

Phase 16.5 triages the open Dependabot updates. Five are major bumps of crates in
the audited cryptographic surface (see "Phase 16.5" in
[`2026-09-14-phase-16-verification-findings.md`](2026-09-14-phase-16-verification-findings.md)).
Rebased onto main, `ed25519-dalek` 3 (#10) builds and passes every Rust test,
including the cross-core vectors. The other four fail to compile on their own:

- `sha2` 0.11 (#9) and `hmac` 0.13 (#11) move to `digest` 0.11; either one alone
  mixes `digest` 0.10 and 0.11 traits (`CoreProxy`, `KeyInit` and `LowerHex`
  bounds unsatisfied at `src-tauri/src/lib.rs` and `src-tauri/src/audit.rs`).
- `aes-gcm` 0.11 (#5) deprecates `AeadInPlace`, the `*_in_place_detached`
  methods and `Array::from_slice`; CI's `clippy -D warnings` turns those into
  errors.
- `rand` 0.10 (#7) no longer exports `rand::rngs::OsRng` or `rand::RngCore`.

This branch starts from the #10 branch and takes the other four as one reviewed
upgrade, one commit per crate family.

## Global Constraints

- Code, comments, commits and docs in English.
- No byte on the wire or on disk may change. The committed cross-core vectors
  (`test/fixtures/keyring-vector.json`, `test/fixtures/keyring-legacy-vector.json`,
  `test/fixtures/audit-vector.json`, `test/fixtures/portable-workspace-vector.json`)
  and every other file under `test/fixtures/` stay untouched:
  `git diff origin/main -- test/fixtures` is empty at every commit.
- Existing Rust tests are not weakened, renamed, skipped or deleted, and no new
  `#[allow(deprecated)]` or other lint suppression is added to get past the
  upgrade. Deprecated APIs are replaced with their successors.
- Randomness for keys, salts and IVs stays an operating-system CSPRNG with the
  same failure behavior as today (today `OsRng.fill_bytes` panics on OS RNG
  failure; a successor that returns an error must surface it or keep the same
  panic, never fall back to a non-OS generator).
- AES-256-GCM stays detached-tag, 12-byte IV, same AAD, same tag length; HMAC
  stays HMAC-SHA-256 over the same input; hex output stays lowercase.
- The only compiler for this branch is CI (no MSVC on the development host).
  `cargo update -p <crate> --precise <version>` and `cargo fmt --check` run
  locally; compile, clippy and tests are judged only from the PR's CI `rust`
  jobs on Linux, macOS and Windows. A commit is done when all three are green.
- `Cargo.lock` changes only through cargo commands, never by hand.
- Do not touch Node/TypeScript code, workflows, or `package.json`.

## Task 1: `sha2` 0.11 and `hmac` 0.13 together

- Bump both in `src-tauri/Cargo.toml` (`sha2 = "0.11.0"`, `hmac = "0.13.0"`),
  update the lockfile with cargo, and adapt `src-tauri/src/audit.rs` and
  `src-tauri/src/lib.rs` (and `keyring.rs` if needed) to the `digest` 0.11 API.
- After this task `cargo tree -i digest` in `src-tauri` shows `digest` 0.11 only
  for these crates (record the output; if `aes-gcm` 0.10 still pulls 0.10
  transitively, record that — Task 2 resolves it).
- Gate: CI `rust` jobs green on all three platforms, with the five cross-core
  vector tests listed as `ok` in the Linux log.

## Task 2: `aes-gcm` 0.11

- Bump `aes-gcm = "0.11.1"`, update the lockfile, replace `AeadInPlace` with
  `AeadInOut`, `encrypt_in_place_detached`/`decrypt_in_place_detached` with
  their `inout` successors, and `Nonce::from_slice`/`Tag::from_slice` with the
  `TryFrom` conversions, returning the existing error strings on a bad length.
- Gate: as Task 1.

## Task 3: `rand` 0.10

- Bump `rand = "0.10.2"`, update the lockfile, and replace `OsRng` +
  `RngCore::fill_bytes` with the rand 0.10 operating-system generator
  (read the resolved crate source under `~/.cargo/registry/src` to confirm the
  type and whether filling is fallible), per the randomness constraint above.
- Gate: as Task 1, plus `cargo tree -d` recorded (duplicate crate versions left
  after the upgrade).

## Task 4: Evidence and ROADMAP

- Fill in Evidence below: per task, commit, CI run URL, the three platform job
  results and the vector test lines, `git diff origin/main -- test/fixtures`
  (empty), `cargo tree` records.
- ROADMAP 16.5: do not tick; add nothing until the whole of 16.5 closes.

## Evidence

_To be filled by Task 4._
