# Phase 7.4 — Full Re-key After a Compromised Passphrase — Design

Date: 2026-09-04
Roadmap item: Phase 7, key wrapping, passphrase change and re-key
Shared contract: `docs/superpowers/specs/2026-09-03-vault-keyring-design.md`
Predecessor: `docs/superpowers/specs/2026-09-04-phase-7-3-passphrase-change-design.md`

## Scope

Phase 7.3 re-wraps the keyset under a new passphrase and re-encrypts nothing.
That is the right answer to a forgotten passphrase and the wrong answer to a
leaked one: the leaked passphrase unwraps the old `keyring.json`, and anybody
holding a copy of that file plus the vault keeps reading every object written
under the keyset it carries.

This phase adds `vbrain rekey`: a new keyset, and every object in the vault
re-encrypted under it.

In scope:

- Rotating the three confidentiality keys — `documents`, `kv`, `syncEnvelope`
  — and re-encrypting every artifact they cover.
- Wrapping the new keyset under a new passphrase by default.
- A stage, verify and swap commit. Every failure before the commit point
  leaves the vault byte-identical; a crash after it leaves a state the next
  run deterministically finishes, so the vault a user ever sees is either
  wholly re-keyed or wholly untouched.
- Dropping keyring slots the current passphrase cannot open, since they wrap
  the superseded keyset.
- Recording the residual identity leak in `SECURITY.md` and `ARCHITECTURE.md`.

Out of scope: rotating `attachmentId` and `syncChange` (see "Pinned keys"),
rotating `audit`, the recovery slot and `vbrain keyring status` (7.5), the
Rust core, and the desktop interface. The Rust core needs no change: it reads
`keyring.json` and the document objects, and a re-keyed vault presents the
same format it already understands.

## What a re-key can and cannot promise

It cannot un-leak the past. An attacker who held the passphrase and a copy of
the vault has already read what that copy contained; no later operation
retracts that.

What it promises is forward: after `vbrain rekey` returns, no byte on disk
opens under the old passphrase or the old keyset. An attacker who keeps a
stale copy, or who later reaches the vault through a backup or a sync backend,
learns nothing new.

Because of that, `vbrain rekey` requires a new passphrase by default. Rotating
the keyset while leaving it wrapped under the leaked passphrase protects a
stale copy of `keyring.json` and nothing else. `--keep-passphrase` exists for
the deliberate case — a keyset rotated because the keyset, not the passphrase,
is suspect — and says so in its help text.

## Rotated keys

| Key | Artifacts re-encrypted |
| --- | --- |
| `documents` | `documents/objects/*.{note,canvas,plugin,pluginstore}.enc`, `documents/history/<id>/<rev>.{note,canvas}.enc`, `documents/index.enc`, `documents/plugin-policy.enc`, `documents/attachments/<id>/manifest.enc`, `documents/attachments/<id>/<n>.chunk.enc`, `documents/sync/applied.enc`, `documents/sync/pending-local.enc`, `documents/sync/apply-receipt.enc` |
| `kv` | `<vault>/*.kv.enc`, `<vault>/grants.enc` |
| `syncEnvelope` | `documents/sync/changes/<id>.change.enc` |

Every one of these envelopes binds its AAD to the artifact's identity — a
document UUID, a revision number, an attachment content address and chunk
index, a logical key-value file name, a sync change ID. **The AAD is
reproduced byte for byte.** A re-key changes the key, never the identity, so
each AAD is re-derived from the same source it was derived from originally,
which in every case is recoverable from the file's own path. Nothing is
renamed and nothing moves.

`documents/sync/changes/<id>.change.enc` deserves a note. Its per-change
subkey is `HMAC(syncEnvelope, context || "\0" || changeId)` and its AAD binds
the same change ID, and that ID comes from `syncChange`, which does not
rotate. So a body re-encrypted under a new `syncEnvelope` keeps its ID, its
filename, its place in the DAG and its parents' references to it.

`audit.log` is not touched: its entries are plaintext and the key only signs
them.

## Pinned keys

`attachmentId`, `syncChange` and `audit` are carried into the new keyset
unchanged.

**`attachmentId`** derives an attachment's content address as
`HMAC(key, context || bytes)`. That address is the directory name under
`documents/attachments/`, the AAD of the manifest and of every chunk, the `id`
inside the manifest body, the `attachmentId` on canvas `file` nodes and on
every canvas history revision, a key in `index.canvasAttachmentRefs`, and an
`objectId` travelling in sync mutations to other devices. Rotating it is not a
re-encryption but an identity migration, and one that diverges from any peer
that has not run it at the same moment.

**`syncChange`** derives a change ID from the canonical change body. A change
body names its parents by ID, so a recomputed ID changes its children's
bodies, which changes their IDs, without a bound. Remote peers holding the old
IDs would never converge. This key is permanent by construction, as
`src/sync/protocol.ts` already documents.

**`audit`** signs a forward hash chain with no key epoch or per-entry key ID
in the format. `verifyAudit` loads one key and applies it to every signed
entry, so rotating it makes every pre-rotation entry fail verification.
Re-signing the chain forward is mechanically possible and destroys the
property the chain exists for, since an attacker with the new key could
re-sign a doctored history just as easily.

### The residual leak, stated plainly

Pinning the two identity keys leaves a confirmation oracle. An attacker who
kept the old keyset can take a candidate file, compute its attachment content
address, and check whether a directory of that name exists — learning that the
vault holds that exact file without decrypting anything. The same holds for a
guessed sync change body.

This is a confirmation oracle over guessed content, not a disclosure of
content. It is accepted for this phase, reported by `vbrain rekey` in its
closing note, and recorded in `SECURITY.md`. Closing it is an identity
migration and gets its own roadmap item.

## Commit protocol

`src/fs-safe.ts` has no directory-level atomic swap, and the only genuinely
atomic operation available is a single-file replace. The protocol is built
around that.

Everything runs inside `withVaultLock`, which is re-entrant, so the helpers
this code calls may take the lock again.

**Stage.** Enumerate every artifact in the table above. Decrypt each under the
old keyset, re-encrypt under the new one with the identical AAD, and write it
to `<vault>/.rekey/new/<relative path>`. The staging directory lives inside
the vault so the later renames stay on one filesystem. The live vault is not
touched. Any failure here — a wrong passphrase, an unreadable object, a full
disk — aborts with the vault byte-identical to before the call.

**Verify.** Open every staged file under the new keyset and confirm it yields
the same plaintext as the original. Then confirm coverage: the staged set must
match the enumerated set exactly, so a file added by a racing writer or missed
by the walk fails the run rather than surviving under a dead key. This too
aborts leaving the vault untouched.

**Commit.** In order:

1. Write `<vault>/.rekey/journal.json` atomically, carrying the new keyring's
   slot ID and the list of relative paths to install.
2. Write the new `keyring.json` atomically — a single-file replace, and the
   point of no return.
3. Rename each staged file over its live counterpart. Each rename is atomic;
   the sequence is not, but it is idempotent.
4. Delete the journal, then the staging directory.
5. `forgetVaultKeys(vaultDir)`.

**Recover.** A run that finds `<vault>/.rekey/journal.json` on entry compares
the journal's slot ID against the slots in `keyring.json`:

- The ID is present — step 2 completed. Finish the installs from step 3
  onward. Every staged file is still there and every rename is idempotent, so
  replaying from the beginning of the list is safe.
- The ID is absent — step 2 never ran. Delete the staging directory and the
  journal. The vault is unchanged.

The window between steps 2 and 3 is the one state where the vault is neither
old nor new: the keyring carries the new keyset while some live files are
still under the old one. It is not silently broken. Recovery is deterministic
and driven by a journal written before the commit, in the spirit of the
resumable design `migrateToKeyring` already uses, and no user data is lost in
any interleaving.

## Slots

The new keyset is written as a single fresh slot at `DEFAULT_SCRYPT_N` with a
new salt and a new UUID, labelled `primary`.

Slots the current passphrase cannot open are **dropped**, not preserved. This
is the deliberate opposite of `changeVaultPassphrase`, which preserves them so
a recovery slot survives. Here they wrap the superseded keyset: keeping one
would leave a slot that opens to keys nothing on disk is encrypted under any
more. Every dropped slot is listed in the report by ID, label and creation
time, so a user who had a recovery slot learns it is gone and can add a new
one once 7.5 ships.

## Command surface

```
vbrain --vault <dir> rekey [--keep-passphrase]
```

Passphrase handling matches `passphrase change`:

- The current passphrase comes from `VBRAIN_PASSPHRASE` or a masked prompt,
  **never from the OS credential store**, so a stale or attacker-primed
  credential cannot authorize a re-key on its own.
- The new passphrase comes from `VBRAIN_NEW_PASSPHRASE` or the existing
  `readNewPassphrase` double-entry prompt, and is subject to
  `MIN_PASSPHRASE_LENGTH`.
- With `--keep-passphrase` the new keyset is wrapped under the current
  passphrase and no new passphrase is read.
- Afterwards `updateRememberedPassphrase` syncs the OS credential store, with
  the same warning paths `passphrase change` already has.

A vault that is not in the keyring format is refused, naming `vbrain migrate`.

## Report

```ts
export interface RekeyReport {
  /** Keys given fresh material. */
  rotated: KeyName[];
  /** Keys carried across unchanged, with the reason for each. */
  pinned: { name: KeyName; reason: string }[];
  /** Re-encrypted artifacts, counted by the key that covers them. */
  reencrypted: { documents: number; kv: number; syncChanges: number; total: number };
  /** Slots dropped because the current passphrase could not open them. */
  droppedSlots: { id: string; label: string; createdAt: string }[];
  /** Whether a new passphrase was set, or the current one reused. */
  passphraseChanged: boolean;
  /** Whether this run finished an interrupted earlier one. */
  resumed: boolean;
}
```

The CLI prints the counts, then the closing note: attachment identities, sync
change IDs and the audit chain are unchanged by design, and an attacker who
kept the old keyset can still confirm a guessed file's presence.

## Modules

- `src/keyring-rekey.ts` — new. `rekeyVault(vaultDir, current, next, options)`
  and the recovery entry point. It owns the artifact walk, the stage/verify/
  swap protocol and the journal. It reuses `wrapKeySet`, `randomKeySet`,
  `readKeyring`, `writeKeyring`, `unwrapSlot`, `forgetVaultKeys` and
  `zeroKeySet` from `src/keyring.ts`, and `encryptDocument`/`decryptDocument`
  from `src/document-crypto.ts`.
- `src/keyring.ts` — unchanged.
- `src/cli.ts` — the `rekey` command, and the removal of the "run `vbrain
  rekey` once it ships" line at the end of `passphrase change`, which becomes
  a plain pointer to the command.
- `src/store.ts`, `src/grants.ts` — no change; the re-key writes their
  envelopes directly rather than through their save paths, because it stages
  to a shadow location before installing.

`keyring-rekey.ts` is the one new file. It stays separate from
`keyring-passphrase.ts` because the two share almost nothing: one re-wraps a
keyset and touches no content, the other rotates a keyset and touches every
object.

## Testing

`node:test`, a new `test/keyring-rekey.test.mjs` added to the `test` script in
`package.json`, following the helpers in `test/keyring-passphrase.test.mjs`
(`seedVault`, `readSlots`, `hashDocuments`, `runCli`).

Library level:

- Every ciphertext changes. `hashDocuments` before and after must share no
  hash for any path, and the path set must be identical — proving full
  coverage and that nothing moved.
- Every plaintext survives. Note bodies, history revisions, canvas documents,
  attachment bytes, key-value entries and grants all read back identical.
- Attachment IDs are unchanged, and `getAttachment` still passes its content
  address re-check.
- Sync change IDs and filenames are unchanged, the bodies still open, and
  resolved heads agree.
- The audit chain still verifies, and a new entry extends the same chain.
- The old passphrase no longer opens the vault; the new one does.
- Slots the current passphrase cannot open are dropped and reported.
- `--keep-passphrase` rotates the keyset under the same passphrase.
- Every refusal — wrong current passphrase, short new passphrase, legacy
  vault, unreadable object — leaves the vault byte-identical, `keyring.json`
  included, and leaves no `.rekey` directory behind.

Crash recovery, using fault injection in the style of
`src/sync/transaction.ts`:

- A crash during staging leaves the vault untouched; the next run cleans the
  stale staging directory and starts over.
- A crash after the journal but before the new keyring leaves the vault
  untouched and openable under the old passphrase; the next run rolls back.
- A crash after the new keyring but partway through the installs leaves a
  vault the next run finishes; afterwards every artifact opens under the new
  passphrase and every plaintext is intact.
- Replaying the install phase twice is a no-op.

CLI level, via `runCli`:

- The happy path, asserting the report lines and that only the new passphrase
  opens the vault afterwards.
- The current passphrase is never taken from the credential store.
- Closed stdin fails loudly rather than exiting 0.
- A legacy vault is refused naming `vbrain migrate`.

## Documentation

- `README.md` — `rekey` in the command block, and a bullet contrasting it with
  `passphrase change`: one re-wraps, one re-encrypts.
- `docs/ARCHITECTURE.md` — the cryptographic model section currently says key
  rotation re-wraps data keys instead of rewriting every object. It gains the
  rotated/pinned split and the confirmation oracle.
- `SECURITY.md` — the residual identity leak, and the fact that a re-key does
  not retract what a leaked passphrase already exposed.
- `docs/ROADMAP.md` — 7.4 checked; a new unchecked item for the attachment
  identity migration that would close the oracle.
- `CHANGELOG.md` — an Unreleased entry.
- `test/keyring-passphrase.test.mjs:452` asserts on the "once it ships"
  wording and is updated with the CLI text.
