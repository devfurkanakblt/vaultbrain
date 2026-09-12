# Release runbook

Vault Brain releases use public GitHub-hosted runners and a draft-first workflow.
The workflow prepares a release; a maintainer reviews and publishes it separately.
Documentation and CI evidence do not constitute a production release. Production
signing, real native installation acceptance and publication remain explicit
maintainer-owned gates.

## One-time signing setup

Generate the production Tauri updater signing key outside this repository. Store the
private key and its password as GitHub Actions secrets named
`TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`, and store the
matching public key as the repository variable `TAURI_UPDATER_PUBLIC_KEY`. Keep an
offline backup of the private key and password in separate protected storage. Never
use a test key for a production tag and never commit either key to the repository.

The vault recovery kit does not contain or recover the updater signing key. Losing
the updater key can require users to perform a manual bootstrap installation.

## Prepare a release

1. Set the same stable semantic version in `package.json`, `src-tauri/Cargo.toml`,
   `src-tauri/tauri.conf.json`, and their lockfiles.
2. Merge the release commit to `main` and wait for that exact commit's complete CI
   run, including Rust, release-contract, recovery, benchmark, and synthetic native
   package-transition evidence.
3. Create and push the matching immutable tag, such as `v0.3.0`. The tag must point
   to the accepted commit on `main`. A manual workflow dispatch may package only an
   already-existing valid tag.
4. Let `.github/workflows/release.yml` build Windows x64 MSI/NSIS, macOS ARM64
   app/DMG, and Linux x64 DEB outputs. Missing signing material fails the build
   closed. The workflow creates a draft and refuses to overwrite any existing
   release.

## Review the draft

Before publishing, confirm that the draft contains the complete package set, Tauri
`.sig` files, `latest.json`, `checksums.sha256`, `sbom.spdx.json`, and
`provenance.intoto.jsonl`. The workflow downloads the draft again and verifies its
checksums, updater signatures, and provenance; retain the successful run URL as
release evidence.

Run a real vN to vN+1 updater drill on ephemeral Windows x64, macOS ARM64, and Linux
x64 hosts. On each host, use a synthetic encrypted vault and record that:

- the user initiates check, download, and final install;
- the installed version increases and the native application identifier is stable;
- the same vault opens after restart with unchanged keyring identity, note IDs, and
  content hashes; and
- cancellation, offline failure, and a rejected signature do not impair the vault.

The CI package-transition harness is a pre-release regression gate, not a substitute
for this production-signed updater drill. SmartScreen/Gatekeeper prompts and Linux
authentication behavior must be recorded rather than described as bypassed.

Retain an evidence record for each host with the exact reviewed commit, package
checksums, signing-key configuration provenance, command transcript, platform and
tool versions, result, and artifact location. Missing signing material, a missing
host drill, or an unreviewed result keeps the release gate open.

## Publish or recover

Publish only after every target passes the drill. There is no automatic updater
rollback. If validation fails, keep the release as a draft, diagnose it, and create a
new version and tag; never replace assets under a published version. If a bad release
was already published, remove it from the update channel, document the affected
version, and ship a newly signed higher version or manual bootstrap package.

