# Phase 15 — Opt-in personal memory design

Status: planned, not enabled. Product owner chose deferral during Phase 14.
The existing implementation plan is
[Phase 15 personal memory](../plans/2026-09-11-phase-15-personal-memory.md),
with detailed historical requirements in
[the original personal-memory plan](../plans/2026-09-05-phase-7-6-personal-memory.md).

## Ownership and boundaries

The Rust desktop owns the unlocked vault session, Windows current-user named-pipe
broker, DPAPI pairing material, writer lock, grants and authenticated audit. The
existing Node modules provide parsing, candidate validation, bounded summaries,
pointer queues and model-runner scaffolding. They are not an integrated product:
there is no production CLI/MCP/desktop call path enabling them by default.

Public MCP operations are `memory_bootstrap`, `memory_search`, `memory_read`,
`memory_remember`, `memory_forget`, and `memory_status`. They require explicit
pairing and scoped grants; they receive neither a vault passphrase nor a data key.
Native transport uses protocol v1 with `{version, method, params}` requests and
`{version, ok, result}` or `{version, ok, error: {code, message}}` responses.
The original plan's bounds and error codes remain the implementation contract.

## Data and lifecycle

Enrollment starts capture from that point onward; no historical transcript scan.
Store accepted facts as ordinary encrypted notes under `Memory/`, with stable
note IDs, revisions and source links. Do not introduce a parallel encrypted format
or a plaintext transcript cache. Queue only protected source references, expire
them after seven days, and show queue/review counts to the owner.

Only unambiguous user-stated, non-sensitive facts qualify for automatic commit.
Assistant inferences, conflicts and sensitive candidates require review; secrets
are rejected before any model invocation. Pinned and manually edited facts are
not overwritten. Forget excludes facts and their sources from future compilation
and recall while retaining an encrypted tombstone; it does not promise deletion
from backups, revisions or provider history.

Lock/exit cancels workers and invalidates the session generation. A stale worker
cannot commit after unlock. Pairing binds the keyring fingerprint. Recovery,
passphrase changes and re-key must be tested separately; changed key identity
invalidates pairing and requires explicit re-enrollment.

## Rollout and acceptance

Phase 15 first implements the broker and synthetic tests, then capture/worker,
then MCP and desktop review controls. Real account setup and transcript capture
are separate user-authorized runtime actions. The runner's currently hard-coded
CLI compatibility assumptions must be revalidated before enabling it; existing
scaffolding is not proof of a working installed Codex integration.

Acceptance requires real Windows transport/DPAPI tests, bounded hostile IPC,
duplicate delivery and interrupted queue recovery, lock/stale-result races,
grant redaction, owner review, forget/relearn, and re-key/restore compatibility.
No Phase 15 feature is marked delivered by this document.
