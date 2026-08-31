# Phase 6 — Encrypted Sync, Multi-Device, and Mobile Design

Date: 2026-08-31  
Status: Approved for staged implementation  
Compatibility baseline: repository `c46fdcd`, protocol-v1 foundation `e5ce271`

## Purpose

Phase 6 turns the existing relay-independent TypeScript sync foundation into a
recoverable, authenticated, multi-device system and then carries the same
security boundary through desktop and a deliberately narrow mobile client.
Delivery is incremental. Every slice remains useful on its own, continues to
open legacy vaults and protocol-v1 objects, and must pass its acceptance gate
before the roadmap can describe it as complete.

This document is the product and security design. The companion implementation
plan decomposes it into test-first tasks and review checkpoints.

## Product decisions

- Sync is optional and the vault remains fully usable without an account,
  relay, or network connection.
- Phase 6 is single-user, multi-device sync. Real-time collaborative editing,
  public publishing, traffic-pattern hiding, and server-side plaintext search
  are out of scope.
- The official hosted relay and the self-hosted relay use the same open binary,
  wire protocol, and compatibility suite. Hosted account and billing control
  planes are outside Phase 6.
- Mobile v1 supports offline note read/write, search, attachment viewing,
  synchronization, conflict resolution, and device management. Canvas editing
  and plugin execution are excluded from the first mobile release.
- A new device is enrolled by an existing trusted device with a ten-minute,
  one-use QR/code invitation. A checksum-protected 24-word recovery kit covers
  loss of all enrolled devices and is never uploaded to the relay.

## Synchronized and local-only state

Portable object types are notes, canvases, attachments, plugin packages, and
three fixed vault objects: `plugin-policy`, `saved-views`, and `workspace`.
Bookmarks are part of the workspace snapshot.

The following remain device-local: plugin enabled state, grants, audit records,
plugin storage, theme, relay credentials, and device preferences. Receiving a
plugin package never executes it and never enables it. A device must make a
local, explicit enable decision after ordinary signature and policy checks.

The `SyncApplyResult.objectType` union therefore covers `note`, `canvas`,
`attachment`, `plugin`, and `vault`. Vault object IDs are restricted to the
three fixed names above.

## Compatibility contract

- `src/sync.ts` remains a compatibility barrel. Existing imports of
  `SyncChangeLog`, `SyncedDocumentVault`, the protocol-v1 body/envelope types,
  and low-level CLI commands continue to work.
- Internal implementation is separated into `src/sync/protocol.ts`,
  `src/sync/snapshots.ts`, `src/sync/change-log.ts`,
  `src/sync/transaction.ts`, and `src/sync/engine.ts` as the responsibilities
  become available.
- Protocol-v1 envelopes remain readable and verifiable. Manifest-v1 vaults are
  opened through a backed-up, rollback-safe migration path before v2-only
  writes occur.
- `verifySyncChanges` remains a structural-graph compatibility alias. Full
  authenticated-envelope verification has an explicitly cryptographic name.
- Applied-cursor mutation is internal/protected. Public APIs cannot move a
  cursor to an unrelated branch or to an earlier revision.
- Existing low-level `sync export|import|verify|apply` commands remain for
  compatibility and diagnostics while the higher-level engine is added.

## Public engine and transport API

```ts
interface SyncEngine {
  status(): SyncStatus;
  syncOnce(): Promise<SyncRunResult>;
  listConflicts(): SyncConflict[];
  resolveConflict(input: SyncConflictResolution): SyncApplyResult;
}

interface SyncTransport {
  push(objects: readonly SyncTransportObject[]): Promise<SyncPushResult>;
  pull(after: string | null, limit: number): Promise<SyncPullPage>;
}
```

Pull cursors are opaque relay cursors, not local applied-object cursors. Push is
idempotent by opaque object ID. Engine status exposes bounded counts, phase,
last success/error, lock state, and conflict count; it never exposes vault keys,
device private keys, bearer capabilities, or decrypted envelopes.

The CLI surface is:

```text
sync init | invite | enroll | devices | remove | rotate | status
sync push | pull | run | conflicts | resolve | recovery
```

## Protocol-v1 normative constants

The existing v1 encoding is frozen while internals are split:

- Change ID domain: `secondbrain-vault:sync-change-id:v1`, followed by NUL and
  the UTF-8 canonical body.
- Change-envelope key domain: `secondbrain-vault:sync-change-key:v1`, followed
  by NUL and the lowercase change ID.
- Change AAD: `secondbrain-vault:sync-change:v1:` followed by the lowercase
  change ID.
- Applied-state AAD: `secondbrain-vault:sync-applied:v1`.
- Change IDs are exactly 64 lowercase hexadecimal characters.
- Device IDs are lowercase RFC 4122 UUID text; accepted variant/version grammar
  is `[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}`.
- Object IDs are 1–160 ASCII characters matching
  `[A-Za-z0-9][A-Za-z0-9._:-]{0,159}`.
- Bodies are at most 8 MiB UTF-8; envelope files are at most 12 MiB; a change
  has at most 256 parents; JSON nesting is at most 32; JSON has at most 100,000
  visited nodes.
- Non-finite numbers, unpaired surrogates, prototype-shaping keys, non-plain
  objects, duplicate parents, noncanonical base64, and noncanonical timestamps
  are rejected before admission.
- JSON canonicalization recursively sorts property names by ECMAScript UTF-16
  code-unit ordering and otherwise uses the accepted JSON subset's native JSON
  scalar serialization without insignificant whitespace.

Golden and adversarial fixtures are normative. Both TypeScript and Rust must
produce byte-for-byte equal canonical bodies and IDs and must agree on opening,
rejection, and conflict outcomes.

## Local capture transaction

Every synchronized mutation starts with a preflight that validates an unlocked
session, device ID, logical object ID, and complete prospective snapshot before
touching live storage.

The durable transaction state machine is:

```text
prepared -> storage-written -> envelope-installed -> cursor-written -> cleared
```

The encrypted pending intent records a stable transaction ID, operation,
prevalidated snapshot/tombstone, expected pre-state, target revision, intended
change identity inputs, and completed phase. Each phase is idempotent and is
persisted atomically before the next phase starts. Recovery runs on unlock and
rolls forward; it never silently rolls back an acknowledged live mutation.

For note, canvas, attachment put/delete and `putMany`, failure or process death
at any boundary must result in either zero visible mutation or exactly one
completed storage/change/cursor transition after the next unlock. No successful
write may remain absent from the sync log. A batch is one logical transaction,
not a collection of independently acknowledged writes.

## Admission, DAG application, and idempotency

Import first authenticates and semantically validates the complete candidate
set in memory. Only after every envelope, parent, device chain, object revision,
snapshot, and membership rule succeeds may immutable files be admitted.

For a clean object head, the apply planner deterministically linearizes the
winner's complete same-object ancestry, including asymmetric merge chains. It
does not discard a required ancestor merely because the local cursor lies on a
different branch. A conflict retains all heads and writes nothing to live
storage.

Remote apply uses a durable receipt keyed by target change ID and intended live
state. If storage succeeds but the applied cursor does not, recovery observes
the receipt/live revision and finishes the cursor without calling the normal
mutation API a second time. Replays therefore do not increment note/canvas
revision or history twice.

All snapshots are parsed and semantically validated before the first live
write. Attachment bytes must hash to the mutation's content ID before the
attachment API is called. Invalid snapshots leave no artifact, history entry,
or cursor.

## Conflict semantics

The existing causal head rules and deterministic display winner remain. Phase
6B adds safe merge helpers:

- Note bodies may be three-way merged only when changed regions do not overlap.
- Note title, path, and properties compare both heads to their common base and
  merge only non-overlapping field changes.
- Canvas conflicts, delete-versus-edit, attachment conflicts, and plugin-package
  conflicts require an explicit user resolution.
- Concurrent plugin policy changes fail closed: restricted mode is logical OR
  and revoked signer/device sets are unions.
- A restore that weakens policy must be an explicit operation whose new change
  names every current head as a parent.

Conflict resolution appends a new change; it never erases losing heads from
history.

## Large attachments and history maintenance

Normal 250 MiB attachment limits remain. Attachments are split into 1 MiB
plaintext chunks, encrypted independently with content-separated keys, and
addressed by keyed opaque IDs. A manifest authenticates ordered chunk IDs,
plaintext size, media metadata, and whole-content digest. Upload and download
resume at chunk boundaries; existing chunk IDs deduplicate safely.

Checkpoints summarize a fully validated DAG prefix and live portable state.
Garbage collection requires a checkpoint acknowledgement from every active
device in the current membership epoch. Removal changes the active set; it does
not pretend to revoke ciphertext a removed device already downloaded.

## Manifest v2, membership, and rotation

Manifest v2 separates secrets:

- The passphrase-derived KEK wraps a random vault root key.
- Document/object keys are randomly generated and wrapped by the root key.
- Each device holds Ed25519 signing and X25519 exchange private keys in
  Rust/native secure storage.
- Protocol-v2 changes carry a membership epoch and authenticated device
  signature. Only active devices in that epoch are admitted.
- Epoch sync keys and relay bearer capabilities rotate on device removal and
  are wrapped only to active devices.

Legacy document keys are never overwritten in place. Migration creates a
backup, verifies the new hierarchy and fixtures, atomically switches the
manifest, and restores the backup on failure.

An invitation is random, expires after ten minutes, is consumed once, is bound
to the opaque vault ID and inviter, and exposes only relay URL, opaque vault ID,
and ephemeral handshake material. Replay, wrong-vault use, expiry, or an
inactive inviter fails without membership changes.

The recovery kit derives access to the vault root through a separately wrapped
recovery secret. Generation and fresh-device restore are explicit, recorded
drills. The relay never receives the words or an equivalent secret.

## Relay trust boundary

One Rust artifact exposes an Axum opaque-object REST API with idempotent create,
batch upload, ID fetch, cursor pagination, and checkpoint acknowledgement.
Self-host mode uses SQLite plus filesystem storage; hosted mode uses PostgreSQL
plus an object-store adapter.

The relay stores only opaque vault/object IDs, ciphertext bytes, ordering
cursors required for pagination, hashed device-scoped bearer capabilities, and
bounded quota counters. It rejects client timestamps, plaintext object types,
searchable metadata, and keys. Byte, object, request-rate, and page-size limits
are configurable and enforced before durable allocation.

Device chains and cross-device checkpoint comparisons expose omission and
equivocation; the relay is not trusted to claim completeness. Docker image,
Compose example, migrations, backup/restore instructions, and compatibility
tests all exercise the same artifact.

## Desktop and mobile boundaries

Tauri and the relay share a Rust `sync-protocol` crate. Desktop IPC exposes only
bounded status, device management, manual sync, conflict queue/resolution,
recovery, and rotation commands. The webview never receives private keys,
relay capabilities, recovery secrets, or raw encrypted/decrypted envelopes.

While locked, a client may stage only size-limited opaque objects. Authentication,
decryption, semantic admission, and live apply occur after unlock. Stronghold
or platform keystore commands are not granted to the webview.

Mobile transactions tolerate suspension at every durable phase. Android and
iOS implement platform-appropriate atomic replace/fsync behavior and background
retry limits. iOS builds/releases require macOS, Xcode, and external signing
coordination; Android release signing likewise remains an external release
credential.

## Release and security gates

Every behavior change follows red-green-refactor. Mandatory suites cover
tampering, wrong keys, noncanonical input, missing parents, cycles, forks,
revision jumps, tombstone ties, asymmetric DAGs, every crash boundary,
policy revoke/restore, enrollment replay/expiry, removed-device rejection,
relay duplicate/omission/quota, and 250 MiB interrupted blob resume.

At each integration gate run TypeScript lint, formatting, typecheck, core and
desktop tests/build, benchmarks, Rust fmt/clippy/test, and relay integration
tests. With sync enabled, incremental save p95 must remain below 20 ms; 100k
note unlock remains below 2 seconds; acknowledged local writes have RPO 0.

Before `1.0.0`, migrate and reopen every legacy fixture, restore from backup on
injected migration failure, run documented corruption/loss/relay/rotation/
recovery/self-host drills, and submit the threat model, normative crypto spec,
fuzz corpus, dependency inventory, and test evidence to independent audit.
Version 1.0, format freeze, or sensitive-data recommendation is forbidden while
any critical/high audit finding remains or remediation retest is incomplete.
