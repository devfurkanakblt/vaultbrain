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

Base: `4b8c6ed` (Dependabot #10, `ed25519-dalek` 2.2.0 -> 3.0.0), plan commit
`9b69b74`. All three commits below are on branch
`chore/phase-16-5-crypto-majors`, PR #57. Every run listed is `success` with
all 11 jobs green (also typescript, codeql, secret-scan, node-platform on
macOS/Windows, native-keychain on all three OSes). Clippy ran as
`cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D
warnings` on every `rust` job and produced no `warning:` or `error[` lines in
any of the nine job logs checked. `git diff origin/main <commit> --
test/fixtures` is empty for every commit (checked against `origin/main` at
`8fe108d`; the worktree's own `git status` shows long-path `test/fixtures`
files as changed only because of a Windows checkout limitation, not a real
diff).

Dependabot PRs: this branch supersedes #5 (`aes-gcm`), #7 (`rand`), #9
(`sha2`) and #11 (`hmac`); it is based on #10 (`ed25519-dalek` 3), which must
merge first.

### `ed25519-dalek` 2.2.0 -> 3.0.0 (branch base, #10)

Diffed the 2.2.0 and 3.0.0 sources directly (`~/.cargo/registry/src`):
`VerifyingKey::from_bytes` is byte-identical. `Verifier::verify` now goes
through `MultipartVerifier::multipart_verify(&[message], signature)`, which
calls the same `raw_verify::<Sha512>` as 2.2.0 did directly, hashing the same
message bytes as a one-part list; it stays non-strict (`verify`, not
`verify_strict`). The signature scalar check is still
`Scalar::from_canonical_bytes` in both versions, gated the same way behind a
`legacy_compatibility` feature that is off on both sides.
`Signature::from_slice`/`from_bytes` (in the `ed25519` crate, 2.2.3 -> 3.0.0)
only gained `#[must_use]`; the bodies are unchanged. VaultBrain uses none of
`SigningKey`, PKCS#8, serde or batch verification, and does not enable the
`rand_core` feature, so ed25519-dalek's own `rand_core` dependency has no
edge into this upgrade. The three TS-pinned Ed25519 tests (see Task 3 below)
pass on all three OSes in CI run 34986728228.

### Task 1: `sha2` 0.11 and `hmac` 0.13

- Commit `296cf5a`.
- CI run [34969211274](https://github.com/devfurkanakblt/vaultbrain/actions/runs/34969211274).
- `rust (ubuntu-latest, linux)`: success, 94 tests passed.
- `rust (macos-15, macos)`: success, 94 tests passed.
- `rust (windows-latest, windows)`: success, 95 tests passed.
- The five cross-core vector tests are `ok` on Linux, macOS and Windows:
  `audit::tests::audit_entry_hashes_match_the_committed_cross_core_vector`,
  `audit::tests::the_audit_head_mac_matches_the_committed_cross_core_vector`,
  `keyring::tests::the_cross_core_vector_unwraps_to_its_recorded_keyset`,
  `keyring::tests::the_legacy_vector_round_trips_through_this_core_byte_for_byte`,
  `tests::shared_portable_workspace_vector_opens_in_native_core`.
- `cargo tree -i digest@0.11.3` in `src-tauri`: only `hmac 0.13.0`, `sha2
0.11.0` and `ed25519-dalek 3.0.0` (via `curve25519-dalek 5.0.0`) resolve to
  `digest` 0.11. `digest 0.10.7` is still present, pulled by `scrypt 0.11.0`
  (through `hmac 0.12.1`/`pbkdf2 0.12.2`/`sha2 0.10.9`) and by
  `tauri-codegen 2.6.3`; neither is used directly by VaultBrain code, and
  neither is in scope for this branch. The plan's original expectation that
  `digest` 0.11 would be the only version, and its guess that `aes-gcm` 0.10
  pulled in `digest` 0.10, were both wrong: `aes-gcm` 0.10 never depended on
  `digest`.

### Task 2: `aes-gcm` 0.11

- Commit `2895ed6`.
- CI run [34984266648](https://github.com/devfurkanakblt/vaultbrain/actions/runs/34984266648).
- `rust (ubuntu-latest, linux)`: success, 94 tests passed.
- `rust (macos-15, macos)`: success, 94 tests passed.
- `rust (windows-latest, windows)`: success, 95 tests passed.
- The same five cross-core vector tests are `ok` on Linux, macOS and Windows.
- The `Nonce`/`Tag` `from_slice` -> `TryFrom` change has no observable effect:
  at every call site the old panic was unreachable (a prior length check, or a
  fixed-size local array), and a bad-length input still produces the same
  existing error string as before. `aes-gcm` 0.11's size limits changed
  (decrypt buffer max `P_MAX = 2^36-32` vs. the old `C_MAX = 2^36+16`, AAD max
  `2^61-1` vs. the old `2^36`); only buffers of roughly 64 GiB or more are
  affected, well outside anything VaultBrain handles. `aes-gcm`'s default
  `getrandom` feature adds `getrandom`/`rand_core 0.10` lockfile edges, which
  are harmless and later folded into Task 3's `rand` bump.
- `cargo tree -i aes-gcm` after this commit shows `aes-gcm 0.11.1` as a direct
  dependency only. `aes-gcm` never depended on `digest`, at 0.10.3 or at
  0.11.1.

### Task 3: `rand` 0.10

- Commit `4901e00`.
- CI run [34986728228](https://github.com/devfurkanakblt/vaultbrain/actions/runs/34986728228).
- `rust (ubuntu-latest, linux)`: success, 94 tests passed.
- `rust (macos-15, macos)`: success, 94 tests passed.
- `rust (windows-latest, windows)`: success, 95 tests passed.
- The same five cross-core vector tests are `ok` on Linux, macOS and Windows.
  The three TS-pinned Ed25519 tests
  (`tests::a_typescript_signed_package_verifies_in_the_rust_core`,
  `tests::a_rotated_registry_written_by_the_typescript_core_still_verifies`,
  `tests::a_tampered_registry_body_fails_verification`) are also `ok` on all
  three OSes in this run.
- `UnwrapErr(SysRng).fill_bytes` replaces `OsRng.fill_bytes` at the seven call
  sites (four in `keyring.rs`, two in `lib.rs`, one Windows-only in
  `memory.rs`). `SysRng` is `getrandom` 0.4's direct OS source: the Linux
  `getrandom` syscall falling back to `/dev/urandom` only on `ENOSYS`/`EPERM`,
  `getentropy` on macOS, and `ProcessPrng` on Windows — the same Windows
  system CSPRNG the prior `getrandom` 0.2.17 reached via `BCryptGenRandom`.
  Failure still panics; only the message text changed, from `Error: ...` to
  `rand_core::UnwrapErr: failed to unwrap: ...`. `rand`'s default features
  (`std_rng`, `thread_rng`) pull in `chacha20` even though VaultBrain does not
  use it; this is recorded here as a possible later trim, not done in this
  branch.
- `cargo tree -d` after this commit: the crypto-relevant duplicates left are
  `sha2 0.10.9`/`digest 0.10.7`/`hmac 0.12.1`/`block-buffer 0.10.4`/
  `crypto-common 0.1.7` (all via `scrypt 0.11.0` and `tauri-codegen 2.6.3`),
  `cipher 0.4.4`/`inout 0.1.4` (via `scrypt -> salsa20 0.10.2`), `rand_core
0.6.4` (via `scrypt -> password-hash 0.5.0`), and `getrandom 0.2.17`/`0.3.4`
  (via `password-hash` and `tauri` respectively). `rand 0.8.8`, `rand_chacha
0.3.1`, `ppv-lite86` and `zerocopy` are gone from the lockfile.

### Remaining `digest`/`sha2`/`hmac` 0.10-line crates

After all three tasks, `digest 0.10.7`, `sha2 0.10.9` and `hmac 0.12.1` remain
in the lockfile, reached through `scrypt 0.11.0` (via `pbkdf2`/
`password-hash`), `tauri-codegen 2.6.3`, and `wry 0.55.1` (an Android-only
target dependency of `tauri-runtime-wry`, so a host `cargo tree` run on
Linux/macOS/Windows does not show it). None of these three crates is used
directly by VaultBrain code; the direct dependency versions are `digest`
0.11, `sha2` 0.11 and `hmac` 0.13 throughout.

### HMAC and the `KeyInit` change

HMAC key initialization after the upgrade goes through `hmac` 0.13's RFC 2104
any-length `HmacCore::new_from_slice`. The plugin `key_id` hex output stays
byte-identical, pinned by the existing test
`a_typescript_signed_package_verifies_in_the_rust_core`. There is no
known-answer test pinning `verifier` (`lib.rs` around line 872) or
`attachment_id` (`lib.rs` around line 5226) directly, but HMAC itself is
covered by the audit cross-core vectors above.

### `cargo fmt`/`prettier`

`cargo fmt --manifest-path src-tauri/Cargo.toml -- --check` passed locally
before each of the three commits (recorded in each task report). This
worktree has no `node_modules`, so
`npx prettier --check docs/superpowers/plans/2026-09-15-phase-16-5-crypto-majors.md`
was run from the main checkout
(`C:\Users\bekircan\OneDrive\Masaüstü\yazilim\vaultbrain`) against this file
after the Evidence section was first written: the check failed on wrap-column
continuation indentation for a few lines, `prettier --write` was run to match
the doc's own style, and the re-check then passed clean. `--check` was run
again from the main checkout after this final-review pass and passed clean
on the first try.

The head commit's CI run for this evidence-doc update will be recorded in
the PR.
