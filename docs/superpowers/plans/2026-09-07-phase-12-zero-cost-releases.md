# Phase 12 implementation plan

Spec: docs/superpowers/specs/2026-09-07-phase-12-zero-cost-releases-design.md

Baseline: origin/main 7226c13. Isolated branch phase-12. User approved parallel
development on 2026-09-08; Phase 11 repair belongs to another contributor.

## Global Constraints

Follow the spec. No paid services, production secret generation, push, merge or release
publication in this turn. Preserve Phase 11 files outside this worktree. Missing
production signing configuration must fail closed, never use a test key as production.

### Task 1: Release artifacts and draft publication

Implement .github/workflows/release.yml and focused scripts/release/ helpers/tests.
Build Windows x64 MSI/NSIS, macOS ARM64 app/DMG and Linux x64 DEB on standard
public-repository runners. Reuse pinned actions. Remove paid Authenticode requirement.
Validate strict release semver, equal package/Cargo/Tauri versions, commit ancestry on
main and same-SHA successful CI before publishing a draft. Manual dispatch also creates
only a draft and must resolve a valid tag. No overwriting published releases.
Use TAURI_SIGNING_PRIVATE_KEY and TAURI_SIGNING_PRIVATE_KEY_PASSWORD only in the
signing build step; public key may come from a repository variable at build time and
must become embedded in shipped configuration (never runtime-controlled by frontend).
Do not generate real signing keys. Fail closed on missing key configuration.
Create Tauri updater artifacts using official bundling; generate stable latest.json
with correct bundle-specific target keys verified against the pinned updater protocol.
Upload final packages, .sig, SHA256, SPDX SBOM and provenance bundle as draft assets;
verify downloaded bytes/checksums/signatures before handing off for manual publish.
HTTPS fixed repository feed, no partial public latest metadata. Add executable unit
tests of validation, manifest/artifact packaging, wrong/missing targets, duplicates,
unsafe paths, invalid versions and corrupted assets. RED before GREEN.
Coordinate updater plugin versions/manifest contract with controller. No modifications
to desktop UI or src-tauri Rust code; any build config overlay lives under scripts/release.

### Task 2: Native updater and install gate

Add pinned compatible Tauri updater dependency and lockfile, narrow native commands,
permissions and typed bridge. Native owner controls check/download/install state and
signature verification. Check only on request; require successful verified download
before install. Enforce semver upgrade, supported bundle and fixed HTTPS repository
source, timeouts and exclusive update operations. No arbitrary frontend URL/key/path.
Installation requires locked vault and prevents concurrent unlock/writes. Failed/cancelled
operations release the gate safely. No secrets in errors. Tests cover invalid metadata,
version/platform rejection, download failure, wrong signatures and concurrent operations.

### Task 3: User interface and save coordination

Add manual update panel with check, version/notes, download progress, cancel and final
install/restart confirmation. Integrate all dirty note and canvas editor saves; errors
retain edits and block install. Ensure no outstanding save can race locking. Ordinary
offline operation remains available. UI tests cover user consent, no automatic network
activity, save failures, cancellation and lock/install ordering.

### Task 4: CI evidence and native update drill

Add recovery:drill and 10k benchmarks to PR validation; 100k on main and release.
Preserve existing budgets. Add synthetic two-version update acceptance harness for native
CI, including package/version and vault content/identity checks. Do not run installers
on the user's host; native install drills run only on ephemeral CI runners. Keep any
unexecuted cross-platform proof clearly pending. Update quality scripts for new tests.

### Task 5: Documentation and final verification

Update README, SECURITY, architecture, changelog, roadmap and release guide to match actual
behavior. Explain free updater versus absent OS signature, bootstrap installs, offline key
backup, user approval, recovery-kit limitations and no automatic rollback. Do not mark
acceptance complete without evidence. Run focused/full quality, Rust quality, benchmarks,
recovery drill, package check and graphify update. Compare failures against baseline;
do not repair unrelated Phase 11 failures. Review each task and whole branch. Prepare
focused local commits only; leave publication and production key provisioning to maintainer.
