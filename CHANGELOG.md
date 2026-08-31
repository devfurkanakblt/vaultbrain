# Changelog

All notable changes will be documented here. The project follows Semantic
Versioning once the encrypted storage format reaches 1.0.

## Unreleased

- Added synchronized document sessions that automatically capture note, canvas
  and attachment puts/deletes, keep an encrypted per-object application cursor,
  and idempotently apply conflict-free remote histories to the live vault.
- Added optimistic revision checks to TypeScript note writes, matching canvas
  writes and preventing a stale synced edit from silently overwriting a note.
- Started Phase 6 with a transport-independent encrypted immutable change log:
  keyed content IDs, per-device chains, causal DAG validation, fail-closed
  imports, deterministic conflict inspection, and CLI import/export tooling.
- Kept the Rust desktop and TypeScript CLI on the same derived index layout,
  including Unicode-normalized note lookup maps and canvas text-link refreshes,
  so a desktop write no longer forces a full CLI index rebuild.
- Added the capability manifest and sandboxed plugin runtime: plugins are stored
  encrypted in the vault, run in a network-less worker without `eval`, and reach
  only the host methods their manifest declared.
- Added Ed25519-signed plugin packages, signed-only restricted mode, and an
  encrypted per-vault signer revocation list enforced by both application cores.
- Fixed the desktop content-security policy, which blocked the `blob:` URLs
  attachment previews depend on.
- Added per-agent scoped grants with expiry, out-of-band single-use confirmation
  and immediate revocation, enforced by the MCP server.
- Added redaction-aware MCP results, and audit entries that sign who asked,
  under which grant, and how much of the value came back.
- Added opt-in semantic document recall with a revision-aware in-memory index,
  plus a loopback-only Ollama adapter for embedding and local generation.
- Added a whole-vault Obsidian importer for Markdown, encrypted attachments and
  JSON Canvas, with symlink refusal and a machine-readable integrity report for
  malformed files, ambiguous assets and unresolved links.
- Added the desktop note lifecycle: move/retitle, delete with recovery,
  encrypted revision history, and restore-forward.
- Added desktop templates and idempotent daily notes, matching the CLI's
  variable grammar.
- Added the encrypted canvas document format and the desktop canvas workspace,
  with text, group, link, note and attachment nodes on one spatial surface.
- Added the desktop attachment library: encrypt on add, decrypt only on preview
  or download, with revoked object URLs.
- Added cross-process desktop writer locking, write-journal recovery, and stale
  revision protection.
- Added sanitized npm packaging and Windows MSI/NSIS installer generation.
- Added CI, formatting, linting, dependency updates, and release quality gates.

## 0.2.0

- Added the encrypted document engine, native desktop workspace, knowledge views,
  attachments, templates, daily notes, and large-vault performance gates.
