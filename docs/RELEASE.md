# Release runbook

Vault Brain releases use public GitHub-hosted runners and a draft-first workflow.
The workflow prepares a release; a maintainer reviews and publishes it separately.
Documentation and CI evidence do not constitute a production release. Production
signing, real native installation acceptance and publication remain explicit
maintainer-owned gates.

The detailed evidence checklist is [RELEASE-ACCEPTANCE.md](RELEASE-ACCEPTANCE.md).

There are two release paths, and they are deliberately independent:

| Path | Artifact | Workflow | Gate |
| --- | --- | --- | --- |
| npm | the `vault-brain` package: CLI, library, MCP server | `npm-publish.yml`, manual | maintainer runs it |
| Desktop | signed installers and the updater feed | `release.yml`, on a stable tag | signing key, then the three-platform acceptance below |

The npm package carries no desktop application and needs no signing key, so it
does not wait on the desktop gates. Tagging is what starts the desktop path, so
the npm workflow deliberately does not tag.

## Publishing the npm package

One-time setup: create an npm account, then a **granular access token** scoped
to read and write this one package, and store it as the repository secret
`NPM_TOKEN`. Nothing else is needed — provenance comes from the workflow's OIDC
token rather than from a secret. Once the package exists, npm's trusted
publishing can replace the token entirely; configure it in the package settings
and the secret can be removed.

First published on 2026-09-22: `vault-brain@0.2.0`, from `9fdef37`, with
provenance. The evidence is in
[RELEASE-ACCEPTANCE.md](RELEASE-ACCEPTANCE.md).

Release steps:

1. Raise the version in `package.json` and merge it to `main`. The workflow
   refuses a version that is already on the registry, because an npm version is
   permanent.
2. Wait for that commit's CI.
3. Run the **Publish to npm** workflow from the Actions tab.

The workflow refuses any ref but `main`, refuses a version that already exists
on the registry, and runs lint, types, the Node suite and the packaging check on
the commit it is about to publish rather than trusting an earlier run. It
publishes with provenance, so the tarball carries a signed statement tying it to
the repository, the workflow and the commit.

**An npm version is permanent.** It cannot be replaced, and unpublishing is
restricted and breaks anyone who already installed it. A mistake is fixed by
publishing a higher version, never by rewriting one. Before publishing a
version, install the packed tarball into an empty prefix and run the CLI from
it — a missing runtime dependency is invisible in the repository, where every
dependency is already present:

```bash
npm pack
npm install --global --prefix ./tmp-prefix ./vault-brain-<version>.tgz
# macOS and Linux put the command in ./tmp-prefix/bin; Windows puts it at the
# prefix root.
./tmp-prefix/bin/vbrain --version
./tmp-prefix/bin/vbrain --vault ./tmp-vault init
```

## One-time signing setup

Generate the production Tauri updater signing key using the installed Tauri CLI,
outside this repository. Store the
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
x64 hosts. The old vN package must itself be production-signed; the unsigned local
`0.2.0` packages are not a valid old baseline. On each host, use a synthetic
encrypted vault and record that:

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

The script `scripts/release/native-update-acceptance.mjs` is a synthetic package
transition check. It verifies version, identifier, package-byte and vault-tree
invariants without installing an updater package, so it cannot satisfy the real
three-platform gate by itself.

## Publish or recover

Publish only after every target passes the drill. There is no automatic updater
rollback. If validation fails, keep the release as a draft, diagnose it, and create a
new version and tag; never replace assets under a published version. If a bad release
was already published, remove it from the update channel, document the affected
version, and ship a newly signed higher version or manual bootstrap package.

