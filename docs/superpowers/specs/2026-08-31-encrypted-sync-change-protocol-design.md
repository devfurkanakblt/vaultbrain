# Encrypted Sync Change Protocol — Design

Date: 2026-08-31  
Roadmap item: Phase 6, immutable encrypted change protocol and conflict resolution

## Scope

The first slice defined the durable, relay-independent unit of synchronization.
The second slice observes vault transactions and applies conflict-free remote
histories to live storage. The third slice adds owner-approved device identity
and removal. Together they ensure:

- an untrusted store can persist and return changes without learning metadata;
- devices can prove their own sequence and the causal state they had observed;
- retries do not create duplicate logical changes;
- divergent offline edits remain visible until a later causal merge;
- malformed, incomplete or forked imports write nothing.

## Envelope and identity

The relay-facing JSON is:

```json
{
  "version": 1,
  "id": "64 lowercase hex characters",
  "payload": {
    "version": 1,
    "iv": "base64",
    "authTag": "base64",
    "ciphertext": "base64"
  }
}
```

`id` is `HMAC-SHA256(vaultKey, domain || NUL || canonicalBody)`. HMAC rather
than a plain digest prevents someone who can list relay objects from confirming
guesses about a change. AES-256-GCM encrypts the canonical body with a fresh
96-bit IV and authenticates the ID as associated data. Each content ID also
derives a sync-specific envelope subkey, separating the nonce domain of every
distinct change even when many devices share the vault key. Renaming an
envelope or changing either header or ciphertext therefore fails authentication.

Canonical bodies follow the RFC 8785 JSON rules used by ECMAScript: recursive
UTF-16 property sorting, no insignificant whitespace and ordinary JSON number
serialization. Inputs reject non-finite numbers, unpaired surrogates,
prototype-shaping keys, excessive depth/complexity and bodies above 8 MiB.

## Decrypted change body

```ts
interface SyncChangeBody {
  version: 1 | 2;
  deviceId: string;                 // lowercase UUID
  sequence: number;                 // starts at 1, increments by one
  previousDeviceChange: string | null;
  parents: string[];                // direct causal parents, sorted
  createdAt: string;                // canonical ISO, ordering hint only
  mutation: {
    objectType: "note" | "canvas" | "attachment" | "plugin" | "vault";
    objectId: string;
    operation: "put" | "delete";
    baseRevision: number | null;
    revision: number;               // base + 1; creation is revision 1
    value: JsonValue;               // null only for delete
  };
  authorization?: {                 // required in version 2
    certificateSerial: number;
    signature: string;              // Ed25519 over the canonical body
  };
}
```

Timestamps never decide causality or the winner. Device sequence and `parents`
form the DAG. A local append parents every currently known graph head plus the
device's prior change, so it records exactly which remote branches were known.

## Validation

Before an import writes its first file, the union of local and incoming changes
must satisfy all of these invariants:

1. Every ID authenticates and recomputes from canonical plaintext.
2. Every parent exists and the graph is acyclic.
3. A `(deviceId, sequence)` identifies exactly one change.
4. Sequence 1 has no device predecessor; every later sequence points to the
   immediately preceding change from that same device.
5. A mutation advances exactly one revision from the greatest causal ancestor
   for the same object.
6. Once a device registry exists, every new change is signed by an enrolled
   device certificate and stays at or below its revocation sequence cutoff.
7. Pre-enrollment version 1 changes are accepted only when their exact keyed IDs
   were frozen into the owner-signed legacy allowlist during initialization.

The complete batch is checked in memory first. Only then are missing envelopes
installed. Existing IDs are idempotent and never overwritten.

## Device enrollment and removal

The first device creates a separate Ed25519 enrollment authority and an
Ed25519 device key. A joining device generates its private key locally and
exports only a signed proof-of-possession request. The authority returns the
device through an encrypted, owner-signed registry. Each client pins the
authority SHA-256 fingerprint; lower registry revisions and same-revision forks
are rejected.

Version 2 changes carry an Ed25519 signature bound to their complete canonical
body and certificate serial. Revocation records the last device sequence the
owner observed. Existing history through that cutoff remains verifiable while
later or withheld post-cutoff changes fail before any envelope is stored. Local
private keys are encrypted at rest and are never included in change or registry
exports.

This does not provide freshness against a relay withholding the newest signed
registry. Epoch content-key rotation and an independently witnessed checkpoint
remain required before untrusted-relay claims.

## Conflict semantics

For one object, a head is a change that is not a causal ancestor of another
change for that object. One head is clean. Multiple heads are a conflict.

The API returns every head and selects a deterministic display winner:

1. greater logical revision;
2. delete before put at the same revision, preventing accidental resurrection;
3. lexicographically greater keyed change ID as a final stable tie-breaker.

The other heads are returned as conflicts, not discarded. A user/application
resolves the conflict by appending a new mutation whose parents include all
current heads and whose base is their greatest revision.

## Durability and exposure

Final envelope files are immutable. A sibling temporary file is fully written
and fsynced, then linked into its content-addressed destination with exclusive
creation semantics. Directory entries and ciphertext reveal change count and
approximate size, but not device IDs, object IDs, timestamps, operations or
values. Traffic analysis and access-pattern hiding are out of scope for v1.

## Transaction capture and application

`SyncedDocumentVault` captures full logical snapshots after successful local
puts and tombstones after deletes. A pre-existing object is first represented
by a revision-1 baseline. Imported histories are applied only when one causal
head remains; every object revision is written through the normal journalled
vault API before an encrypted application cursor advances. Replays are
idempotent and conflicts write nothing.

Attachment data is base64-encoded inside the authenticated snapshot in this
version, so synchronized attachments are limited to the space available in an
8 MiB change. A separate immutable blob protocol is required before the normal
250 MiB attachment ceiling can be synchronized.

## Deferred slices

- large attachment blob transport;
- epoch content keys, rotation and independently witnessed freshness;
- relay API, authentication, quotas and self-hosting;
- checkpoint/compaction rules for large histories;
- Rust/mobile implementations and cross-language fixtures;
- external cryptographic review before stable 1.0.
