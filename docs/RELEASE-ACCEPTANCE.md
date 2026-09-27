# Production release acceptance

This is the maintainer checklist for a production-signed **desktop** draft. CI
contract tests and synthetic package transitions are supporting evidence only.
A release is not accepted until the three real signed updater transitions below
have artifacts and reviewer sign-off.

The npm package is a separate artifact on a separate path and is not gated by
anything below; it needs no signing key, ships no desktop application, and is
already out. Its record is the next section.

## npm — accepted and published

| Item | Value |
| --- | --- |
| Package | `vault-brain@0.2.0` |
| Published | 2026-09-22, by the manual `Publish to npm` workflow |
| Commit | `9fdef37` |
| Workflow run | https://github.com/devfurkanakblt/vaultbrain/actions/runs/35757515587 |
| Contents | 65 files, 969,529 bytes unpacked |
| Integrity | `sha512-YbVG8LpS0kntRlngEsQUZtbBu69vqiS+G3ao0CrDKY0SZna37n5mJCdGeB7XiVmoM4xSiPlICGBTsNNQQezX0w==` |
| Provenance | SLSA v1 attestation on the registry, tying the tarball to this repository, workflow and commit |
| Post-publish check | Installed from the registry into an empty prefix on Windows x64; `vbrain --version`, `init`, `add` and `get` ran from the installed command |

What that does and does not say: the tarball is the one this repository built,
from a commit anyone can read, and the registry can prove it. It says nothing
about the independent security audit, which is still open — `SECURITY.md` and
`README.md` continue to state that this software is not presented as suitable
for real medical, financial or identity data until that review is complete.

An npm version is permanent. The workflow refuses a version already on the
registry, so the next publish begins by raising the version in `package.json`.

## Desktop — still open

Everything below this line is the desktop path: the signing material, the draft
contents, the three real updater transitions and the publication decision. None
of it has been run, and the table at the end records that rather than implying
otherwise.

### Signing and build inputs

Use the Tauri updater signing material only through the protected release
environment. The repository workflow reads `TAURI_SIGNING_PRIVATE_KEY` and
`TAURI_SIGNING_PRIVATE_KEY_PASSWORD` as secrets and
`TAURI_UPDATER_PUBLIC_KEY` as a repository variable. Keep an offline backup of
the private key and password separately. Do not generate or commit signing
material in this repository.

The checked-in release workflow's build command is:

```bash
npm run tauri:build -- --config scripts/release/tauri.release.conf.json --config <platform-config>
```

The release overlay enables updater artifacts and embeds the public key and the
fixed `latest.json` feed. The ordinary local command in `package.json` is useful
for a local bundle check, but without production secrets it produces unsigned
local packages:

```bash
npm run tauri:build
```

The updater `.sig` files and OS publisher signatures serve different purposes.
Tauri updater signatures authenticate bytes accepted by the in-app updater. OS
publisher signatures and notarization determine platform trust prompts such as
SmartScreen or Gatekeeper. An updater-signed package can still show an OS trust
warning when no Authenticode or Apple publisher identity is configured.

### Draft contents

Before publication, verify the draft has exactly the required platform packages,
updater signatures, `latest.json`, `checksums.sha256`, `sbom.spdx.json`, and
`provenance.intoto.jsonl`. Retain the successful workflow URL, commit SHA, tag,
checksums, public-key fingerprint, and configuration provenance.

The current repository has no old production-signed baseline package. Therefore
the first real updater drill cannot be backfilled from the unsigned local
`0.2.0` packages recorded in `PHASE-14-VERIFICATION.md`; obtain and retain a
previous production-signed vN package before running vN to vN+1.

### Real three-platform updater acceptance

For each row, install the old signed vN package on an ephemeral real device,
point it at the fixed feed, and use the native Updates flow to approve check,
download, and installation separately. Record the old and new versions,
identifier, package and `.sig` hashes, vault identity, note IDs, content hashes,
tool versions, prompts, cancellation/offline behavior, and retained logs.

| Platform | Required transition | Evidence | Result |
| --- | --- | --- | --- |
| Windows x64 | signed vN MSI or NSIS → signed vN+1 | old/new package and `.sig`, SmartScreen result, vault reopen | NOT RUN |
| macOS ARM64 | signed vN app/DMG → signed vN+1 | app archive/DMG and `.sig`, Gatekeeper result, vault reopen | NOT RUN |
| Linux x64 | signed vN DEB → signed vN+1 | DEB and `.sig`, authentication result, vault reopen | NOT RUN |

The native transition must show a higher semantic version, stable application
identifier, changed package bytes, unchanged keyring identity, unchanged vault
tree, and unchanged file inventory. Cancellation, offline failure, and rejected
signature must leave the vault usable. The script
`scripts/release/native-update-acceptance.mjs` checks these invariants
synthetically; it does not install a package or prove a real signed update.

### Publication decision

| Gate | Result | Reviewer / evidence |
| --- | --- | --- |
| Independent audit handoff accepted | NOT RUN |  |
| Production signing secrets and offline backup verified | NOT RUN |  |
| Complete draft, signatures, checksums, SBOM and provenance verified | NOT RUN |  |
| Windows x64 signed transition | NOT RUN |  |
| macOS ARM64 signed transition | NOT RUN |  |
| Linux x64 signed transition | NOT RUN |  |
| Maintainer publication approval | NOT RUN |  |
