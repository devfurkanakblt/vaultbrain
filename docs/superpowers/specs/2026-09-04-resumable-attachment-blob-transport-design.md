# Resumable Attachment Blob Transport — Design

Date: 2026-09-04  
Roadmap item: Phase 6, resumable chunked transport for large attachment blobs

## Scope

Attachments larger than 6,242,304 bytes cannot synchronize at all. A
synchronized attachment travels as a base64 snapshot inside a single change
envelope (`attachmentSnapshot`, `src/sync.ts`), and an envelope body is capped
at 8 MiB (`MAX_CHANGE_BYTES`); after base64 expansion and envelope overhead
that leaves `MAX_SYNC_ATTACHMENT_BYTES` = 6,242,304 raw bytes. `putAttachment`
accepts up to `MAX_ATTACHMENT_SIZE` = 250 MiB into the vault and then refuses
to synchronize anything above the smaller ceiling with an explicit "until blob
transport is available" error.

This design removes that ceiling. After it:

- an attachment of any size the vault accepts (250 MiB) synchronizes;
- change envelopes stay small and uniform regardless of attachment size;
- an interrupted transfer resumes without re-sending what already arrived;
- the relay still stores only opaque ciphertext, and gains one integrity check
  it can perform without any key;
- an attachment whose bytes have not fully arrived is never written into live
  storage;
- the offline export/import path keeps working for attachments.

Out of scope: relay-side retention or garbage collection (see Non-goals), and
any change to how attachments are stored on disk.

## What already exists

Three existing properties do most of the work, and this design is shaped to
reuse them rather than introduce parallel machinery.

**Attachments are already chunked on disk.** `src/documents.ts` splits every
attachment into `ATTACHMENT_CHUNK_SIZE` = 1 MiB pieces and seals each piece
independently under `attachmentChunkAad(id, index)` =
`secondbrain-vault:attachment-chunk:v1:<id>:<index>`, writing each as
`documents/attachments/<id>/<index>.chunk.enc`. Nothing about the storage
layout changes here.

**Attachment ids are content-addressed.** `id = HMAC-SHA256(attachmentIdKey,
AAD.attachmentId || data)`, hex-encoded (`putAttachment`, `src/documents.ts`).
`attachmentIdKey` is a dedicated, never-rotated key from the vault keyring,
equal to the document key only on legacy manifest vaults
(`src/document-crypto.ts`). The id is therefore already a commitment to the
plaintext, and `getAttachment` recomputes it on every read and refuses a
mismatch.

> `docs/FORMAT-1.0.md` currently describes this derivation as keyed by the
> vault master key and quotes `this.session.key`, which matches only the legacy
> path. That is a pre-existing specification/code divergence, unrelated to this
> design and not fixed by it; it is recorded here because this design depends on
> the derivation being stated correctly.

**The relay is already an immutable content-addressed store.**
`immutableWrite` (`src/sync-relay.ts`) writes with `wx`, returns false on an
identical re-write, and throws on a same-id-different-bytes collision. Routes
are generic `/{collection}/{id}`.

The consequence that drives the whole design: **the change envelope does not
need to carry the bytes.** It only needs to name them, because the object id
it already carries is a commitment to what those bytes must decrypt to.

## Change body version 3

`SyncChangeBody.version` gains the value `3`. The attachment snapshot has two
forms:

```ts
// version 1 | 2 — still read, no longer written
interface InlineAttachmentSyncSnapshot {
  filename: string;
  mime: string;
  data: string; // base64 of the whole plaintext
}

// version 3 — the form every new attachment change is written in
interface BlobAttachmentSyncSnapshot {
  filename: string;
  mime: string;
  size: number;   // safe integer, 1 <= size <= MAX_ATTACHMENT_SIZE
  chunks: number; // safe integer >= 1, === blobs.length
  blobs: string[]; // blob id per chunk, in chunk order, at most 256 entries
}
```

The writer always produces the version 3 form, whatever the attachment's size.
The reader must keep accepting the inline form regardless, because change logs
and committed fixtures already contain version 1 and 2 attachment bodies; that
reader-side branch is not a cost this design introduces, which is why a size
threshold that would also split the *writer* was rejected.

`chunks` must equal `blobs.length` and must equal
`Math.ceil(size / ATTACHMENT_CHUNK_SIZE)`. `size` is at least 1, because
`prepareAttachmentPut` already refuses an empty attachment ("Attachments must
be between 1 byte and 250 MiB"), so `chunks` is always at least 1. A body
failing any of these is rejected at validation, before any transfer is
attempted.

A `blobs` array is capped at 256 entries, matching the existing `parents` cap.
250 MiB at 1 MiB per chunk is 250 entries, so the cap is not reachable by a
legal attachment and exists to bound hostile input.

## Blob identity

**A blob id is the lowercase hex SHA-256 of the exact bytes uploaded**, and the
bytes uploaded are the on-disk chunk file verbatim — the JSON-encoded
`DocumentPayload` written by `putAttachment`. Upload copies the file; download
writes it back unchanged.

A keyed derivation such as `HMAC(vaultKey, AAD.syncBlobId || attachmentId ||
index)`, which would match the construction used for `AAD.syncChangeId`, was
considered and rejected. AEAD nonces are random per seal, so two devices
holding the same attachment produce *different* chunk ciphertexts. Under a
keyed id those different bytes would claim the same blob id and the relay's
`immutableWrite` would reject the second one as a content-id collision — a
correctness failure, not a storage inefficiency.

Hashing the ciphertext instead:

- keeps the relay opaque: the input is an AEAD output, so the hash reveals
  nothing about the plaintext, its size class beyond the chunk boundary
  already implied, or its type;
- lets the relay verify an upload **without holding any key** — if
  SHA-256(body) is not the id in the path, reject. The relay cannot do this
  for change envelopes today, so this is a small strengthening, not a
  concession;
- deduplicates identical uploads exactly as the change store already does.

Two devices that each add the same file produce two distinct blob sets. This
costs relay storage in a case that is rare in practice — a device that already
holds an attachment no-ops in `putAttachment` rather than re-adding it — and
is accepted deliberately rather than solved with a deterministic nonce, which
would weaken the AEAD construction to save storage.

Plaintext integrity does not depend on any of this. After reassembly the
receiving device recomputes
`HMAC-SHA256(attachmentIdKey, AAD.attachmentId || data)` and compares it with
the change's `objectId`, exactly as `getAttachment` does
on every local read. A relay that serves corrupted, substituted, or
mismatched blobs produces an attachment that fails that check and is refused.

## Relay blob collection

A `blobs` collection is added to the existing route shape.

| Route | Behavior |
|---|---|
| `PUT /blobs/<id>` | Reject unless SHA-256(body) equals `<id>`, then `immutableWrite`. Identical re-write is idempotent. |
| `GET /blobs/<id>` | The stored bytes, or 404. |

There is deliberately **no list endpoint** for blobs. Blob ids reach a device
through change bodies it has already admitted and decrypted; an enumeration
endpoint would hand a relay-authenticated party a way to count and walk
attachment storage without possessing any change. The existing paginated list
for changes stays as it is.

Per-object size limit is 2 MiB, matching the `readTextFileLimited` bound
already applied when reading a chunk file (`src/documents.ts`) — a 1 MiB
plaintext chunk becomes roughly 1.37 MiB of base64 JSON, so the bound holds
with margin. Storage and object-count quotas reuse the existing relay
mechanism; blobs count toward them like any other stored object.

## Transfer and resumability

Resumability is per-chunk idempotence, not byte-range resume. With 1 MiB
chunks, the largest unit of lost work on an interruption is one chunk, and the
server holds no session state — there is no upload session to expire, resume,
or authenticate a second time.

**Push, in this order, per change:**

1. For each blob id in the change body, upload the chunk unless the relay
   already has it. `PUT` is idempotent, so a re-run after an interruption
   re-sends only what is genuinely missing.
2. Only after every blob is present, push the change envelope.

The ordering is the invariant that matters: **the relay never advertises a
change whose bytes it does not yet hold.** A puller that sees an attachment
change can always complete it.

**Pull, per admitted change:**

1. Admit and verify the change envelope as today.
2. Fetch each blob id not already present locally, writing it to
   `documents/attachments/<id>/<index>.chunk.enc`.
3. The attachment becomes complete only when every chunk is present.

An interrupted pull leaves some chunks on disk and the attachment incomplete;
re-running fetches only the missing ones.

## Apply semantics

`sync apply attachment <id>` fails closed when any chunk is missing, naming
the count: `"5 of 12 attachment chunks are missing."` It never materializes a
partial attachment, which would in any case fail the content-addressed id
check on the next read.

- `sync relay pull` fetches blobs for the changes it admits, so the common
  path needs no extra command.
- `sync blobs status` reports, per attachment with a pending change, how many
  chunks are present and how many are missing.
- `sync blobs fetch <url>` retries only the missing blobs for changes already
  admitted — the recovery path when a pull was interrupted or a relay was
  temporarily unavailable.

## Offline bundle transport

`sync export` currently writes a JSON array of envelopes to stdout, which is
the relay-independent transport the CLI advertises. With bytes out of the
envelope, that path would silently stop carrying attachments.

- `sync export --bundle <dir>` writes `changes.json` plus `blobs/<id>` files
  for every blob referenced by an exported change.
- `sync import <source>` accepts either a JSON file, exactly as today, or a
  bundle directory.

Without `--bundle`, `sync export` behaves as it does now. A bundle is a
directory of opaque ciphertext with the same exposure as the JSON export.

## Limits and compatibility

- `MAX_SYNC_ATTACHMENT_BYTES` and the guard in `putAttachment` that raises
  "until blob transport is available" are removed. The ceiling becomes the
  vault's existing `MAX_ATTACHMENT_SIZE` = 250 MiB.
- `FORMAT_COMPATIBILITY` (`src/format-version.ts`) moves the sync change entry
  to `reads: [1, 2, 3]`, `writes: [1, 2, 3]`.
- Writing version 3 is gated the same way the rest of sync is: behind
  `--experimental-trusted-sync`.
- A reader that predates version 3 rejects such a body by version rather than
  misreading it, which is the fail-closed behavior the format policy intends.
- The Rust core counts changes without decrypting them (`sync_status`,
  `src-tauri/src/lib.rs`), so it is expected to be unaffected. Expected is not
  verified: a test pinning `sync_status` against a version 3 fixture is part
  of this work.

## Non-goals

**Relay blob retention and garbage collection.** Deleting an attachment leaves
its blobs on the relay. This matches what the relay already is — an
append-only immutable store whose change log accumulates the same way — and
retention policy is a design question of its own (who decides, on what
signal, with what protection against a relay that deletes what is still
referenced). Attempting it here would roughly double this design. It is
recorded as an operator-facing note in `docs/SYNC-RELAY.md`.

**Byte-range resume within a chunk.** 1 MiB is a small enough unit of lost
work that ranged transfer adds server state and failure modes for no
meaningful gain.

**Changing attachment storage on disk.** The chunk layout, chunk size, AAD
constants, and id derivation are untouched.

## Testing

Test first, in this order:

1. **Format conformance.** A committed fixture vault holding a version 3
   attachment change; `test/format-conformance.test.mjs` reads it, and the
   Rust suite pins `sync_status` against it.
2. **Body validation.** `chunks`/`blobs.length`/`size` disagreement, a
   `blobs` array over 256, a non-hex blob id, and a version 1 body carrying
   `blobs` are each rejected before transfer.
3. **Relay blob endpoints.** SHA-256 mismatch rejected; identical re-PUT
   idempotent; over-size body rejected; quota enforcement; no list route.
4. **Resumability.** A push interrupted between chunks re-sends only the
   missing ones; a pull interrupted mid-attachment completes on re-run.
5. **Ordering invariant.** A change is never visible on the relay before all
   of its blobs.
6. **Fail-closed apply.** Apply with a missing chunk refuses and names the
   count; live storage is untouched.
7. **Integrity.** A blob whose bytes were substituted by the relay produces a
   reassembled attachment that fails the id check and is refused.
8. **Round trip.** A 12 MiB attachment — above today's hard ceiling —
   synchronizes device to device and reads back byte-identical.
9. **Bundle transport.** `export --bundle` then `import` reproduces the
   attachment on a second vault with no relay involved.

## Documentation updates

- `docs/FORMAT-1.0.md`: version 3 body, both snapshot forms, blob id
  derivation, the validation rules above.
- `docs/SYNC-RELAY.md`: the `blobs` collection, its size and quota behavior,
  and the retention non-goal.
- `docs/AUDIT-SCOPE.md`: the accepted-risk bullet recording the 6,242,304-byte
  ceiling is replaced by a description of the blob path, which becomes review
  surface.
- `docs/ROADMAP.md`: check off the blob transport item once shipped.
- `README.md`: the sync section's statement of the 8 MiB ceiling.
