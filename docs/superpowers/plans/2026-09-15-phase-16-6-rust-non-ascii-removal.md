# Phase 16.6 follow-up — non-ASCII removal in the Rust desktop core

The Phase 16.6 plan
([`2026-09-14-phase-16-6-non-ascii-vault-removal.md`](2026-09-14-phase-16-6-non-ascii-vault-removal.md))
left one item UNVERIFIED: the Rust analogue of the Node defect. On Windows 11
with Node v24.11.1, `fs.rmSync` removes nothing and returns normally when any
path component is non-ASCII. The desktop core removes vault data with
`std::fs::remove_dir_all` (attachment purge, `remove_attachment` in
`src-tauri/src/lib.rs`) and `std::fs::remove_file` (notes, canvases, plugins,
revisions, journals, lock files, the memory pairing secret). Rust's standard
library calls the wide-character Win32 APIs directly and is not expected to
share Node's defect, but it could not be built on the host that found it, and
an expectation is not evidence. This plan turns the expectation into CI
evidence.

**Goal:** Prove, on the Windows CI runner, that the real production removal
paths of the Rust core remove their targets when the vault path has non-ASCII
components; and make any removal whose silent failure would leave
security-relevant state report that failure.

## Global Constraints

- Code, comments, commits and docs in English.
- Tests drive the production functions (`remove_attachment`, `remove_note_in`,
  `with_vault_write`, the pairing removal helper), never a copy of their
  bodies.
- Each test builds its own non-ASCII path under `std::env::temp_dir()`:
  `Masaüstü`, `çğış` and a non-BMP character (`𝄞`, U+1D11E, a UTF-16 surrogate
  pair on Windows). The test asserts the path really is non-ASCII and really
  contains a non-BMP character, so it cannot pass vacuously on a runner whose
  own temp directory is ASCII.
- "Removed" means both `!path.exists()` and `fs::symlink_metadata(path)`
  failing with `NotFound` (`exists()` alone also returns `false` on permission
  errors).
- Keep every existing error-handling decision unless a silent failure leaves
  security-relevant state behind. Cleanup that deliberately ignores a failure
  so the original error is reported keeps ignoring it; a tolerated missing
  target stays tolerated. No retry loops.
- No on-disk format, file name or AAD changes.
- No MSVC toolchain on the authoring host: `cargo fmt --check` runs locally;
  compile, `cargo clippy --all-targets -- -D warnings` and `cargo test --lib`
  are judged by the PR's CI `rust` jobs (Linux, macOS, Windows).
- Do not commit the unrelated `package-lock.json` diff.

## Audit of production removal call sites

Test-only removals (`#[cfg(test)]` modules in `lib.rs` and `keyring.rs`) are
out of scope. `audit.rs`, `keyring.rs`, `desktop_sync.rs` and `updater.rs`
have no production removal call. The production sites:

| Site (`src-tauri/src/`)                                                    | Error handling                   | Classification                                                                                                                                                                                                                                                                                              |
| -------------------------------------------------------------------------- | -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `lib.rs` `remove_attachment` — `remove_dir_all(attachment_dir(..))`        | propagated                       | Reported. Tested (Task 1).                                                                                                                                                                                                                                                                                  |
| `lib.rs` `remove_note_in` — note object                                    | propagated                       | Reported. Tested (Task 1).                                                                                                                                                                                                                                                                                  |
| `lib.rs` `end_journal` — `journal.json`                                    | propagated                       | Reported. Tested through `remove_note_in` (Task 1).                                                                                                                                                                                                                                                         |
| `lib.rs` revision pruning, `remove_plugin_in`, `delete_canvas`             | propagated                       | Reported; same `std::fs::remove_file` call as the tested note path.                                                                                                                                                                                                                                         |
| `lib.rs` `VaultWriteGuard` drop, `VaultTransitionGuard` drop — lock files  | ignored (`let _`)                | Not security state: the lock record holds a token, PID, host and time. A `Drop` cannot report, and a surviving record is reclaimed by the existing stale-lock logic. Unchanged; removal is still asserted by the Task 1 tests, which run through `with_vault_write`.                                     |
| `lib.rs` `VaultWriteGuard::acquire`, `with_lock_transition` — failed write | ignored (`let _`)                | Cleanup on an error path; the original write error is returned. Unchanged, per the 16.6 constraint.                                                                                                                                                                                                         |
| `lib.rs` `VaultWriteGuard::acquire`, `with_lock_transition` — stale reclaim | ignored (`let _`)                | A failed reclaim leaves the lock held, and the loop then times out with an error. Unchanged.                                                                                                                                                                                                                |
| `lib.rs` `write_atomic` — `.tmp` cleanup                                   | ignored (`let _`)                | The temp file only survives when `replace_atomic` failed, and that error is returned. Its bytes are the ones the caller asked to persist at the target (ciphertext, wrapped keys, DPAPI blobs), so a leftover adds no exposure beyond the target. Unchanged.                                              |
| `memory.rs` `delete_pairing_material` (Windows) — pairing secret           | **ignored (`let _`)**            | **Defect.** The file holds the DPAPI-protected bearer secret, and the memory pipe server authorizes a client solely by comparing against it (`broker_secret()`). `disconnect` reported success even when the secret survived. Fixed and tested (Task 2).                                                |

## Task 1: Prove the vault removal paths on a non-ASCII vault path

**Files:** `src-tauri/src/lib.rs` (test module only).

- Add `non_ascii_vault(label)`: a fresh `vault-brain-<label>-<uuid>` directory
  under `temp_dir()`, with the vault at `Masaüstü/çğış-𝄞/vault` inside it;
  returns the outer directory (for cleanup) and the vault path, and asserts the
  vault path is non-ASCII with a non-BMP character.
- Add `assert_removed(path)`: `!path.exists()` and `symlink_metadata` is
  `NotFound`.
- `an_attachment_purge_removes_its_directory_under_a_non_ascii_vault_path`:
  open a vault there, `put_attachment` a multi-chunk attachment, check its
  directory holds chunk files, purge it through
  `with_vault_write(.., remove_attachment)` (what `delete_attachment` runs),
  assert the directory, the lock file and the transition file are removed and
  `load_attachments` is empty.
- `a_note_delete_removes_its_object_under_a_non_ascii_vault_path`: store a note
  through `with_vault_write`, delete it through
  `with_vault_write(.., remove_note_in)` (what the delete command runs), assert
  the note object, `journal.json`, the lock file and the transition file are
  removed.
- Both tests remove the outer directory at the end and assert it is removed.
- Verify: `cargo fmt --check` locally; CI `rust` jobs.

## Task 2: Report a pairing secret that was not removed

**Files:** `src-tauri/src/memory.rs`.

- Extract `remove_pairing_file(path)` (Windows-only, like the rest of the
  pairing code): `remove_file`; `NotFound` is `Ok` (never paired); any other
  failure, or a path that still resolves afterwards, returns
  `Err("memory pairing material could not be removed")`. No retry.
- `delete_pairing_material` returns `Result<(), String>`; a missing
  `LOCALAPPDATA` stays tolerated (no material can have been written).
- `disconnect` propagates the error before saving, so a failed removal leaves
  the vault's memory state still paired and the owner can retry, instead of
  recording "disconnected" over a secret that still authenticates.
- `pairing_material_removal_is_verified_under_a_non_ascii_path`
  (`#[cfg(windows)]`): under a non-ASCII, non-BMP path, a written pairing file
  is removed (both checks); removing it again is `Ok`; a directory at the path
  is reported as an error and left in place.
- Verify: `cargo fmt --check` locally; CI `rust` job on `windows-latest` (the
  only job that compiles the Windows-only code).

## Task 3: Evidence

- Push, open the PR, wait for CI. Record the job names and conclusions, and
  from the Windows `rust` job log (`gh run view --job <id> --log`, available
  only after the whole run finishes) the lines naming each new test and the
  `test result:` lines.
- Record whether the Windows runner's own temp directory is ASCII.

## Evidence

Filled in after CI.
