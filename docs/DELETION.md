# Deletion: what `remove`, `purge` and retention actually do

Vault Brain invites medical, financial and identity data. "I need this gone"
therefore has to have an answer, and the answer has to be honest about where it
stops. This document is that answer, and it records the decision Phase 10 took
about whether a deletion propagates.

## Three different operations

| Command | What it does | What survives |
|---|---|---|
| `docs remove <ref>` | Archives the current revision, then unlinks the object. | Every revision, under `documents/history/<id>/`, for the life of the vault. |
| `purge note\|canvas\|attachment <ref> --yes` | Removes the object **and every archived revision of it**, without archiving on the way out. | Nothing in this vault's document storage. See the limits below. |
| `retention set --keep-revisions N --keep-days D` | Bounds how much history every object keeps, and applies that bound to the history that already exists. | The newest revisions the policy keeps, and the live object. |

`remove` is the right default for an editing mistake: it is reversible with
`docs restore`. It is the wrong answer for "this should never have been written
down", because the content is still in the vault. `purge` is the second answer,
and it is not reversible from this vault.

An attachment has no history, so `removeAttachment` was already permanent;
`purge attachment` exists so one command covers all three object kinds and
reports them the same way.

Without `--yes`, every `purge` command is a preview: it prints what would be
removed and exits non-zero without touching anything.

## What a purge cannot reach

A purge removes objects from one vault directory. It is not a promise about
every copy of that data in the world, and the following are outside it.

**Backups taken before the purge.** A `vbrain backup` archive is a complete copy
of the vault as it was. Restoring one taken before a purge brings the purged
object back, in full. After purging something that matters, take a fresh backup
and destroy the older archives that carry it — the archives are encrypted, but
they are encrypted copies of the thing you wanted gone.

**This vault's own sync change log.** A synchronized vault records every
mutation as an encrypted change, and a `put` change carries the note body. A
purge does not rewrite that log, and the purge report counts the changes it is
leaving behind rather than letting the number go unsaid. Those changes are
readable with this vault's passphrase.

**A relay the changes were pushed to.** The relay is an append-only,
content-addressed store with no garbage collection; `docs/SYNC-RELAY.md`
records that as a deliberate operator-facing non-goal. Changes carrying the
purged content stay there until an operator removes them from the storage
directory out of band.

**Any device that pulled it.** A device that admitted the change decrypted the
content to apply it. It has had the plaintext. Purging on one device does not
reach the others; the purge has to be run on each of them.

**The bytes on the disk.** A purge unlinks files. It does not overwrite them,
and on a copy-on-write filesystem, an SSD with wear levelling, or a volume with
snapshots or file-history enabled, the old ciphertext may remain in blocks the
filesystem no longer references. Overwriting in place would be theatre on that
hardware. What protects those remnants is that they are ciphertext under a key
the vault holds — which is also why `vbrain rekey` after a passphrase leak is a
different and stronger operation than deleting anything.

## The decision: a purge does not propagate

**A purge is local to the vault it runs in. Vault Brain 1.x ships no deletion
tombstone, and a purge sends nothing to a relay or to another device.** This was
a choice, not an omission, and here is the reasoning.

*The sync log cannot lose a change without losing its own integrity.* Changes
form a causal DAG: each one names its parents, ids are content addresses, and
owner-signed freshness checkpoints pin the history that exists. Removing or
rewriting a change breaks every parent reference to it and invalidates every
checkpoint that covers it, which turns "delete this note" into "this vault's
history no longer verifies". The property that lets a device detect a relay
withholding history is the same property that makes retracting a change
impossible.

*A propagating delete is an instruction to destroy data, carried over an
untrusted transport.* The relay can withhold, delay or replay what it stores. A
tombstone it withholds leaves a device silently holding what you believe is
gone, and there is no acknowledgement channel that would tell you which devices
complied. Shipping a delete instruction that cannot be confirmed would mean
telling users their data is gone everywhere when the protocol cannot know that.

*A device that already has it cannot be made not to have it.* By the time a
tombstone could arrive, the receiving device has decrypted and stored the
content. The instruction is advisory at best against a device that is offline,
compromised, or simply running an older build.

So the honest procedure for "gone everywhere", today, is manual and this
document states it rather than hiding it behind a command that would imply more:

1. Purge the object on **every** device that holds the vault.
2. Ask the relay operator to remove the stored changes, or remove them from the
   relay's storage directory yourself. There is no protocol command for this.
3. Take a fresh backup, and destroy the backups taken before the purge.
4. If the content was sensitive enough that its exposure matters — not just its
   presence — treat it as exposed to every device that ever synchronized it.

Whether a future format version carries an authenticated, owner-signed
tombstone that is *advisory* — "this device deleted this object; you may want
to as well" — is a live question for 2.0, where the change-identity and
checkpoint constructions can be revised together. It is not something 1.x can
add compatibly.

## What is recorded

A purge appends the object's id to the passphrase-authenticated audit chain
(`purge:note:<id>`, `purge:canvas:<id>`, `purge:attachment:<id>`), and a
retention change appends its bounds. The chain records that the deletion
happened and what it applied to. It does not record the content, which is the
point.
