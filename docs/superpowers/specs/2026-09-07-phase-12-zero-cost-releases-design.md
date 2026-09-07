# Phase 12: Zero-cost releases and manual updates

Approved design, amended 2026-09-08: development runs independently of Phase 11.
Phase 11 CI success remains a final integration and publication prerequisite;
another contributor owns its failures. Do not repair those failures here.

## Global Constraints

- Public GitHub repository and standard hosted runners only. No paid services,
  publisher certificates, Apple account, server, mobile distribution or billing changes.
- Tauri updater signatures are required, independently of OS publisher signing.
  Never promise that unsigned OS packages bypass SmartScreen or Gatekeeper.
- User explicitly checks, approves download, and confirms installation. No startup
  checks, automatic downloads, silent installation or automatic rollback.
- Pin update source and public key in native application code/configuration.
  Never accept arbitrary URLs, keys, installer commands or paths from the UI/plugins.
- Before installation, flush all note/canvas edits, abort on save failure, lock and
  zeroize the vault, and prevent concurrent unlock/writes until cancellation/failure.
- Invalid signatures, malformed metadata, wrong platforms, old versions and network
  failures cannot cause installation or impair ordinary offline vault use.
- No private keys, passphrases, personal data or real vault fixtures in source/logs.
  Provision production signing secrets separately; missing configuration fails closed.
- Publish only complete immutable versioned releases: final artifacts, signatures,
  checksums, SPDX SBOM and provenance. Create a draft; maintainer publishes separately.
- Tag must match npm/Cargo/Tauri versions and belong to main. Same-commit acceptance
  evidence is mandatory. No push, merge, actual release publication or secret provisioning
  in this implementation turn.

## Targets and update channel

Windows x64 NSIS/MSI; macOS ARM64 app/DMG; Linux x64 DEB. Use a pinned
compatible Tauri updater supporting these bundle formats. One stable GitHub Releases
channel; pre-releases excluded. Older installations without an updater need one manual
bootstrap installation. Linux may use the OS authentication prompt, never a stored sudo
password. Production signing key needs an offline backup; its loss can require reinstall.

## Acceptance

Typecheck, targeted tests, full TS and Rust quality suites, package validation,
recovery drill, 10k/100k benchmarks, and real two-version native updates on all supported
targets. Existing Phase 11 failures are reported, not silently waived. Native CI and
signing-secret provisioning are external release gates, not claims of local completion.
Run graphify update after source changes. Document all remaining verification gaps.
