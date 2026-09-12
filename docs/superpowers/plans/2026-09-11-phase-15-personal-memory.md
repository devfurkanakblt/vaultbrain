# Phase 15 — opt-in personal-memory integration design and implementation plan

Design: [Phase 15 personal memory](../specs/2026-09-12-phase-15-personal-memory-design.md).

Phase 14.4 keeps the existing `src/memory/` modules experimental and disabled by
default. This plan turns the Phase 7.6 design into a separately reviewable product
slice. It does not authorize live account setup, real transcript capture, external
MCP or desktop integration, or production rollout.

## Product and security decision

Personal memory is opt-in per vault, per unlocked desktop session and per explicitly
paired local client. The native desktop broker owns the vault session, pairing
credential and privileged operations. A client never receives a passphrase, data
key, arbitrary vault path or shell capability. Pairing requires visible owner
consent and records the keyring fingerprint; identity rotation invalidates the old
pairing and requires clean re-enrollment.

Memory capture begins only after enrollment. It imports no history, stores no raw
transcript archive or plaintext cache, and sends only bounded, secret-filtered
source text to the configured local worker. Assistant inferences, conflicts and
sensitive candidates require review. Pinned or manually edited notes are never
silently overwritten.

## Phase 15.1 — native broker and session lifecycle

- Define and version the bounded request/response protocol.
- Implement explicit pairing, current-user-only native transport, broker identity
  checks, keyring fingerprint checks and unlocked-session enforcement.
- Keep credentials in the OS-protected store and queue only encrypted/pointer data
  while locked; bound the queue, use a seven-day expiry, and expose counts.
- Reuse existing note, revision, journal, lock, grant, index and authenticated audit
  paths. Add no new encryption format.
- On lock, exit, stale session generation or re-key, cancel work and reject results
  from the old session. Rekey restore compatibility must preserve the new owner
  epoch and require peer/client re-enrollment.

## Phase 15.2 — safe capture and worker boundary

- Parse only supported synthetic/versioned transcript and hook records newer than
  enrollment; reject unknown records that affect interpretation.
- Validate bounded candidates against exact user evidence, exclude secrets, derive
  stable source dedupe keys and label untrusted model output.
- Run one owner-approved local worker through anonymous stdin/stdout with no shell,
  inherited tools, credentials or ambient configuration. Enforce timeout, output,
  cancellation and quota limits with generic scrubbed errors.
- Auto-commit only unambiguous user-stated facts. Route inferences, conflicts and
  sensitive content to review.

## Phase 15.3 — MCP, desktop controls and lifecycle actions

- Add setup/status/doctor/disconnect and internal hook/MCP entrypoints only after
  the native protocol is tested. Setup merges only managed config entries, creates
  backups, and never replaces unrelated MCP or hook configuration.
- Provide owner-only controls for queue/review, source inspection, pause/exclude,
  approve/reject, pin, forget/relearn and disconnect. Public memory reads remain
  bounded and grant-aware.
- Forget removes active recall and invalidates dependent summaries and queued
  sources while retaining an encrypted tombstone. It does not claim physical
  erasure from revisions, backups or provider history; relearning requires an
  explicit owner action.

## Acceptance and evidence

Use synthetic vaults, transcripts, credentials and worker executables. Verify native
Windows pairing/ACL behavior, lock and cancellation races, queue durability,
fingerprint changes, grants/redaction, review and forget semantics, re-key/restore
compatibility, config backup/merge/removal, bounded MCP/hook output and accessible
desktop controls. Real Codex accounts, real personal data, live setup, external
integrations and production signing remain outside this plan until separately
authorized. Phase 15 stays unchecked until those acceptance results are recorded.
