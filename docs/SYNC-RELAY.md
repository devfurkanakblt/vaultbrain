# Self-hosted sync relay

The Phase 6 relay is a deliberately small, opaque transport. It accepts only encrypted change envelopes, encrypted owner-signed device registries, encrypted owner-signed freshness checkpoints and sealed attachment chunks. It has no vault key and cannot read object types, device IDs, timestamps, note content or attachment bytes.

## Security boundary

- A bearer token of at least 32 bytes protects every vault endpoint. Supply it only through `VBRAIN_RELAY_TOKEN`; it is never accepted as a CLI argument. The pre-rename `SBRAIN_RELAY_TOKEN` is still read as a compatibility alias when the new name is unset, so an existing deployment keeps working, but new setups should use `VBRAIN_RELAY_TOKEN`.
- Vault, change and artifact routes use 64-character opaque IDs. Writes are content-addressed and immutable.
- Request size, total vault bytes, change count, pagination, header time and request time are bounded.
- Storage paths are containment-checked and symbolic links are rejected.
- The default listener is `127.0.0.1`. Put TLS and normal network access controls in front of it before binding to a non-loopback interface.
- The relay is still an availability adversary: it can delete, delay or withhold ciphertext. A pinned owner-signed checkpoint detects rollback or selective withholding of history covered by that checkpoint. Discovering a newer checkpoint still requires its ID through a trusted out-of-band channel or an independent witness.
- An enrolled device remains trusted with the plaintext it can decrypt. Epoch content-key rotation is forward-only, so revocation blocks new signed changes and denies the revoked device the new content key, but does not revoke data the device already received.

## Attachment blobs

An attachment no longer travels inside its change. A `version: 3` change body carries a manifest — `filename`, `mime`, `size`, `chunks` and one blob id per chunk — and the bytes travel separately as *blobs*: one AEAD-sealed 1 MiB chunk each, sealed under the vault's document key with the attachment's own chunk AAD. A blob id is the lowercase hex SHA-256 of the sealed bytes themselves, which is what lets the relay verify an upload while holding no key of any kind.

| Method | Route | Behaviour |
|---|---|---|
| `PUT` | `/v1/vaults/<vaultId>/blobs/<blobId>` | `201` on the first write, `200` when the identical bytes are written again (idempotent). `400` if `SHA-256(body)` is not `<blobId>`, or if a vault quota would be exceeded. `413` if the body exceeds 2 MiB. |
| `GET` | `/v1/vaults/<vaultId>/blobs/<blobId>` | `200` with `application/octet-stream` and a `Content-Length`, or `404`. |
| `HEAD` | `/v1/vaults/<vaultId>/blobs/<blobId>` | Existence probe used to skip an upload the relay already holds: `200` or `404`. |
| anything else | `/v1/vaults/<vaultId>/blobs/<blobId>` | `405`. |
| `GET` | `/v1/vaults/<vaultId>/blobs` | `404`. |

Every one of these needs the bearer token; without it the answer is `401` before the route is even parsed.

**There is deliberately no list route, and that is a security property rather than an unfinished feature.** Blob ids reach a device only through change bodies it has already admitted and decrypted. An enumeration endpoint would hand anyone holding the bearer token a way to count and walk a vault's attachment storage — how many attachments exist, how large they are, how often they change — without possessing a single change. Changes keep their existing paginated list because their ids are already covered by the checkpoint chain; blobs get none. A `GET` on the collection path answers `404`, the same as any unknown route.

Other limits:

- **2 MiB per blob**, matching the bound already applied when reading a chunk file: a 1 MiB plaintext chunk becomes roughly 1.37 MiB of base64 JSON, so the bound holds with margin. A larger body is refused with `413` and never reaches disk.
- **Blobs count toward the vault quotas** like any other stored object — both the total byte cap and the object-count cap that changes are counted against. A vault full of attachments can therefore exhaust the object budget that changes also draw on; size the relay accordingly.
- **Blob ids are 64-character opaque hex**, containment-checked and symlink-checked on the same code path as every other stored object, and writes are immutable: re-writing an id with different bytes is refused, not silently accepted.

A push uploads every blob a change references *before* it publishes the change envelope, so the relay never advertises a change whose bytes it does not yet hold. A pull fetches the blobs for the changes it admits. Both directions are idempotent per blob, so an interrupted transfer resumes by re-running and re-sends only what is genuinely missing; the largest unit of lost work is one 1 MiB chunk, and the relay keeps no upload session to expire.

Applying an attachment change whose chunks have not all arrived fails closed, naming the count (`"5 of 12 attachment chunks are missing."`), before anything is written to live storage.

### Retention: an operator-facing non-goal

**Deleting an attachment does not delete its blobs from the relay.** There is no garbage collection and no retention policy. This matches what the relay already is — an append-only immutable store whose change log accumulates the same way — but it means relay storage for a vault that repeatedly adds and removes large attachments grows without bound, and an operator who needs the bytes gone must remove them out of band, from the storage directory, with the vault's own copy of the change log as the only record of what is still referenced. Deciding this inside the protocol is a design question of its own (who decides, on what signal, and with what protection against a relay that deletes what is still referenced), and it is deliberately not answered here.

### Blob commands

`sync relay push` and `sync relay pull` carry blobs on their own, so the common path needs no extra command: push uploads a change's blobs before the change, and pull fetches the blobs of the changes it admits. `sync relay pull`'s success JSON now reports what that cost — the object is `{ registryRevision, changes, blobs, checkpoint, checkpointWarning }`, where `blobs` is `{ fetched, skipped }`.

The `sync blobs` group covers the recovery paths. Every command below needs the program-level `--experimental-trusted-sync` gate, and the two that talk to a relay need `VBRAIN_RELAY_TOKEN`:

```bash
# One line per attachment change that carries blob references, in change
# order: "<attachmentId> <n> present, <m> missing". Silent when the log has
# no blob-form attachment changes.
vbrain --experimental-trusted-sync --vault ./vault sync blobs status

# Retry only the missing blobs for changes already admitted.
# Prints: "Fetched <n> blob(s); <m> already present."
vbrain --experimental-trusted-sync --vault ./vault sync blobs fetch https://relay.example

# Drop staged blobs the relay confirms it holds; one it does not hold is kept.
# Prints: "Pruned <n> staged blob(s); kept <m> the relay does not hold."
vbrain --experimental-trusted-sync --vault ./vault sync blobs prune https://relay.example
```

Two things about those numbers are worth stating plainly, because both look like bugs and are not:

- **`status` counts every blob-form attachment change, applied or not.** It does not filter by applied state, so an attachment already written to live storage is still listed, and after a `prune` its chunks are reported as missing. That is accurate: the vault holds the attachment, but the staged chunks needed to *re-apply* the change are gone and would have to be fetched again.
- **`prune` only considers blobs that some change references.** It walks the blob ids named by the change log, not the staging directory — `SyncBlobStore` has no listing method — so a staged blob no change refers to is never pruned. `prune` is not an orphan collector.

The offline transport keeps working without a relay. `sync export` on its own still writes the JSON array of envelopes to stdout, byte for byte as before; with `--bundle <dir>` it writes `<dir>/changes.json` plus `<dir>/blobs/<blobId>` and prints `Exported <e> envelope(s) and <b> blob(s) to <dir>.` with the directory resolved to an absolute path. `sync import` accepts either a JSON file, as before, or such a directory, in which case it prints `Staged <s> attachment blob(s).` and then the usual `Imported <i>; already present <e>.`:

```bash
vbrain --experimental-trusted-sync --vault ./vault sync export --bundle ./bundle
vbrain --experimental-trusted-sync --vault ./other-vault sync import ./bundle
```

A bundle export fails closed rather than shipping half an attachment: if a referenced blob is not staged locally it writes nothing at all and exits non-zero with `<k> of <total> attachment chunks are missing; run sync blobs fetch before exporting a bundle.` A bundle is otherwise a directory of opaque ciphertext with exactly the same exposure as the JSON export: it is not a backup, and it cannot bootstrap a vault that lacks the original key-derivation metadata.

## Start and use the relay

Generate a random token with a password manager or cryptographic random generator, then set it on both server and client:

```bash
export VBRAIN_RELAY_TOKEN='<at-least-32-random-bytes>'
vbrain --experimental-trusted-sync sync relay serve ./relay-data --port 8787
```

Create a freshness checkpoint immediately before publishing a known-good state, transfer its printed ID through a trusted channel, and push:

```bash
vbrain --experimental-trusted-sync --vault ./vault sync checkpoint create
vbrain --experimental-trusted-sync --vault ./vault sync relay push https://relay.example
```

An existing device can pull with its already pinned authority and checkpoint chain:

```bash
vbrain --experimental-trusted-sync --vault ./vault sync relay pull https://relay.example
```

The first pull into a restored encrypted vault backup must pin the expected enrollment authority. Pin the expected checkpoint as well to make relay withholding detectable on that first contact:

```bash
vbrain --experimental-trusted-sync --vault ./restored-vault sync relay pull https://relay.example \
  --authority <owner-authority-sha256> \
  --checkpoint <owner-checkpoint-sha256>
```

The restored directory must come from an encrypted vault backup and therefore contain the original key-derivation metadata. The relay is not a key escrow or a standalone backup and cannot bootstrap an empty directory or recover a lost passphrase.

## Recovery drill

`npm run recovery:drill` performs a disposable end-to-end exercise:

1. create an enrolled source vault and take a `vbrain backup` archive of it;
2. add a later change and owner-signed checkpoint;
3. upload only opaque ciphertext to a temporary relay;
4. restore that archive into a new directory, catch up from the relay and verify the pinned checkpoint;
5. assert that the relay files do not contain the test plaintext.

Step 4 restores from the artifact the documented backup procedure produces, not
from a directory copy. A copy cannot be verified before it is trusted, and it
carries whatever half-written state the source directory happened to hold.

Run this gate before a release and retain the command output as drill evidence. It is an automated engineering drill, not a substitute for an independent security audit or a human-operated disaster-recovery exercise.
