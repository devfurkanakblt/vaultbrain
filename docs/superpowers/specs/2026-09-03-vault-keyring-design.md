# Vault Keyring — Design

Date: 2026-09-03
Roadmap item: Phase 7, key wrapping, passphrase change and re-key

## Scope

`docs/ARCHITECTURE.md` states that a memory-hard KDF derives a *wrapping* key,
that random data keys are wrapped by it, and that rotation re-wraps data keys
instead of rewriting every object. The implementation does none of this. Both
cores derive the content key directly from the passphrase:

- `src/document-crypto.ts` — `scrypt(passphrase, documents/manifest.json salt, N=2^15)`
  produces the key that encrypts every note, canvas, index, plugin package,
  attachment manifest and attachment chunk.
- `src-tauri/src/lib.rs:1412` — the same derivation, with `N` hard-coded to 32768.
- `src/crypto.ts` — `*.kv.enc` and `grants.enc` run a *fresh* scrypt on every
  write, with a per-file salt.
- `src/audit.ts` — a separate `scrypt(passphrase, audit.meta.json salt, N=2^15)`
  keys the audit chain HMAC.

Three consequences follow, and this design removes all three.

**The passphrase cannot be changed.** There is no command, and no wrapping layer
that would make one cheap. Changing it means re-encrypting the whole vault.

**The KDF cost cannot be raised.** `src/document-crypto.ts:52-57` and
`src-tauri/src/lib.rs:1419` both reject a manifest whose `N` differs from the
constant compiled into the build, so raising the work factor would make every
existing vault unopenable. `src/crypto.ts:5` still carries the comment
`MVP default, tune upward for production`.

**The passphrase-derived key is baked into permanent identities.** Attachment
content IDs are `HMAC-SHA256(key, "secondbrain-vault:attachment-id:v1\0" || bytes)`
(`src/documents.ts:2129`, `src-tauri/src/lib.rs:4341`) and sync change IDs are
`HMAC-SHA256(key, "secondbrain-vault:sync-change-id:v1" || NUL || canonicalBody)`
(`src/sync/protocol.ts:183`). Any change of key silently changes both, breaking
attachment references and the sync DAG.

Out of scope: the recovery key, whole-vault export, backup and the desktop
passphrase-change interface. The recovery key is a later slot in the format
defined here and needs no further format work.

## Key hierarchy

```
passphrase ──scrypt(N=2^17, r=8, p=1, per-slot salt)──► KEK
                                                         │ AES-256-GCM
                                                         ▼
                                              ┌──────── keyset ────────┐
                       rotatable │ documents     32B │ every object under documents/
                                 │ kv            32B │ *.kv.enc, grants.enc
                       ──────────┼───────────────────┤
                       permanent │ attachmentId  32B │ attachment content-address HMAC
                                 │ syncChange    32B │ sync change ID and envelope subkey
                                 │ audit         32B │ audit chain HMAC
                                              └────────────────────────┘
```

The keyset stores final keys rather than deriving them from one root. That is a
deliberate choice in service of migration: an existing vault adopts its legacy
key into `documents`, `attachmentId` and `syncChange` verbatim, so every
attachment ID and sync change ID it has already written stays valid and not one
object is re-encrypted. A vault created fresh gets five independent random keys.

Rotation acts on the two rotatable keys only. The permanent keys keep
identities, references, the sync DAG and historical audit verification intact
across a re-key.

## On-disk format

`<vault>/keyring.json`:

```json
{
  "version": 2,
  "slots": [
    {
      "id": "<uuid v4>",
      "type": "passphrase",
      "label": "primary",
      "kdf": { "name": "scrypt", "N": 131072, "r": 8, "p": 1, "salt": "<base64, 16 bytes>" },
      "createdAt": "<ISO 8601>",
      "wrapped": { "iv": "<base64, 12 bytes>", "authTag": "<base64, 16 bytes>", "ciphertext": "<base64>" }
    }
  ]
}
```

The wrapped plaintext is the keyset:

```json
{
  "version": 1,
  "keys": {
    "documents": "<base64, 32 bytes>",
    "kv": "<base64, 32 bytes>",
    "attachmentId": "<base64, 32 bytes>",
    "syncChange": "<base64, 32 bytes>",
    "audit": "<base64, 32 bytes>"
  }
}
```

Every slot wraps the same keyset. Associated data for the wrap is the canonical
JSON of `{ version, id, type, kdf }`, so a slot header cannot be downgraded to a
weaker cost, retyped, or transplanted onto another slot's ciphertext without the
tag check failing.

There is no verifier field. A wrong passphrase fails as a GCM authentication
error. This is a security improvement in itself: today's
`documents/manifest.json` publishes `HMAC(key, "secondbrain-vault:document-key:v1")`,
which hands an offline attacker an unlimited passphrase-guessing oracle at
N=2^15. Migration deletes it.

`documents/manifest.json` is rewritten to `{ "version": 2, "keyring": true }`.
Both cores already reject a manifest whose version is not 1, so an older build
opening a migrated vault fails closed with a clear error rather than
misinterpreting anything.

`audit.meta.json` is left on disk untouched but is no longer used to derive a
key in v2. Nothing reads its salt after migration.

Slot KDF parameters are validated on read with the bounds `src/crypto.ts`
already applies: `N` a power of two in `[2^14, 2^20]`, `r` in `[1, 32]`, `p` in
`[1, 16]`, salt 16 to 64 bytes. A hostile keyring cannot demand a multi-gigabyte
derivation or silently weaken the next one. Node needs `maxmem` above `128*N*r`,
which is 128 MiB at N=2^17; the call sites pass 256 MiB.

Measured on the development machine: N=2^17 costs 345 ms, against 115 ms for
today's N=2^15. `docs/PRODUCT.md` budgets 2 s for cold unlock to a usable shell.

## Key-value envelope v2

`*.kv.enc` and `grants.enc` move to a new envelope that takes its key from the
keyring:

```json
{ "version": 2, "cipher": "aes-256-gcm", "keyId": "kv", "iv": "<b64>", "authTag": "<b64>", "ciphertext": "<b64>" }
```

Associated data is the canonical JSON of `{ version, cipher, keyId, name }`,
where `name` is the logical file identity (`health`, `finance`, `grants`). Two
defects are fixed at once: the KDF no longer runs on every write, and the
ciphertext is now bound to the file it belongs to, so `health.kv.enc` and
`finance.kv.enc` can no longer be swapped undetected.

Envelope versions 0 and 1 stay readable exactly as today, because a v1 vault is
still a supported vault until its owner migrates it.

## Migration

`vbrain migrate` gains the v1 → v2 step, keeps its existing envelope work, and
stays idempotent. Under `withVaultLock`, in this order:

1. Derive the legacy document key `K` from `documents/manifest.json` and the
   legacy audit key `A` from `audit.meta.json`.
2. Build the keyset: `documents = attachmentId = syncChange = K`, `audit = A`,
   `kv` fresh random.
3. Wrap it in a new slot with a fresh 16-byte salt at N=2^17, write
   `keyring.json` atomically.
4. Re-encrypt `*.kv.enc` and `grants.enc` into envelope v2 under the new `kv`
   key. These files are small and few.
5. Replace `documents/manifest.json` with the version tombstone, which is what
   removes the guessing oracle.

Nothing under `documents/objects/` is read or rewritten. A 100,000-note vault
migrates in the time it takes to write a handful of small files.

The reason `documents`, `attachmentId` and `syncChange` all adopt the same `K`
is that the legacy code used `K` directly for all three purposes. Splitting them
at migration time would invalidate every attachment ID and sync change ID
already written.

Adoption is per key and conditional on the legacy material actually existing. A
vault that only ever used the key-value commands has no
`documents/manifest.json`, and a vault that was never written to has no
`audit.meta.json`. Each key is adopted when its source file is present and
generated randomly when it is not, so a key-value-only vault migrates to a
keyring whose `documents`, `attachmentId` and `syncChange` keys are fresh
random. Step 5 is skipped when there is no manifest to replace.

A vault created after this change never adopts anything; `openVaultKeys` creates
a keyring with five independent random keys on first use.

## Session API

`openVaultKeys(vaultDir, passphrase): VaultKeys` resolves the keyring once and
caches the result in-process, keyed by vault path and a salted fingerprint of
the passphrase — the pattern `src/audit.ts:69-88` already uses to avoid paying
the KDF on every audit event. Nothing is persisted.

Call sites keep their current `passphrase: string` signatures and ask
`openVaultKeys` for the key they need. This keeps the change to key resolution
rather than a signature refactor across `documents.ts`, `store.ts`, `grants.ts`,
`audit.ts` and `sync/`. `VaultKeys` zeroizes its buffers on lock, as
`DocumentKeySession` does today.

## Rust core

The Rust core reads the keyring; it never writes one. `open_document_key`
becomes: if `keyring.json` exists, parse it, validate the slot's KDF bounds,
derive the KEK with the crate's scrypt at the slot's parameters, unwrap the
keyset, and take `keys.documents` and `keys.attachmentId`. Otherwise fall back
to the legacy manifest path unchanged. `keys.attachmentId` is required because
`src-tauri/src/lib.rs:4341-4378` computes attachment content IDs itself.

The Rust core touches neither the audit chain nor sync, so it ignores those
three keys. It must refuse a manifest with `version == 2` when `keyring.json` is
absent, rather than treating the vault as legacy.

`N` is read from the slot and bounds-checked. It is never compared against a
compiled-in constant again — that comparison is the bug this design removes.

## Passphrase change

`vbrain passphrase change` prompts for the current passphrase, unwraps the
keyset, prompts twice for the new one, and writes a new slot: fresh salt, the
current default cost of N=2^17, same keyset. The keyring is replaced atomically under the
vault lock. If the OS credential store holds a passphrase for this vault, it is
updated in the same operation; if that update fails, the command says so
explicitly rather than leaving a stale credential silently in place.

A minimum length is enforced. A full strength estimate is separate work and is
not attempted here.

The command's output states plainly that changing the passphrase does not
re-encrypt anything, and that a leaked passphrase needs `vbrain rekey`.

Because a new slot is written with the current default cost, this command is
also the KDF upgrade path: a user on an old vault raises their work factor by
changing their passphrase, without touching a single note.

## Re-key

`vbrain rekey` generates new random `documents` and `kv` keys and re-encrypts
every object under them. The permanent keys are untouched, so attachment IDs,
note references, the sync DAG and audit history all survive.

Crash safety without doubling disk usage: for the duration of the operation the
keyset carries an optional `retiring` map alongside `keys`, holding the outgoing
`documents` and `kv` keys. Readers try the current key and fall back to the
retiring one on authentication failure — the AAD already binds each object's
identity, so a fallback cannot succeed against the wrong object. Objects are
rewritten one at a time, each write followed by a journal entry, the same
pattern `src/sync/transaction.ts` uses. On completion the retiring entry is
dropped. After a crash, `vbrain rekey` resumes from the journal.

A keyset containing `retiring` is written as `version: 2`. Builds from phases
7.1 through 7.3, and the Rust core until it is taught the field, reject an
unknown keyset version and fail closed. This is the correct behaviour: a vault
caught mid-re-key must not be opened by a build that would silently fail to
decrypt the objects still holding old ciphertext. Re-key runs under the vault
lock from the CLI, so the desktop application is not the one holding it open.

This is the one operation here that rewrites the whole vault, and it is the
last phase for that reason.

## Delivery phases

Each phase ships on its own and leaves older vaults readable.

**7.1 — Format and migration (TypeScript).** `keyring.json`, `openVaultKeys`,
every TypeScript read and write path routed through it, kv envelope v2,
`vbrain migrate`, fixtures and tests. Visible outcome: `migrate`.

**7.2 — Rust read parity.** The Rust core opens v2 vaults. Visible outcome: the
desktop application opens a migrated vault. 7.1 and 7.2 together are what make
v2 usable; neither is shippable alone.

**7.3 — `vbrain passphrase change`.** Visible outcome: the passphrase can be
changed, and the KDF cost can be raised.

**7.4 — `vbrain rekey`.** Visible outcome: a leaked passphrase has an answer.

7.3 and 7.4 are independent of each other.

Each phase gets its own implementation plan and its own pull request. This
document is the shared contract they are all written against.

## Testing

Compatibility is the centre of this change. `test/fixtures/documents-v1`,
`documents-attachments-v1`, `documents-canvas-v1`, `kv-envelope-v0` and
`sync-v1` are not regenerated or edited. A new test copies each into a temporary
directory, migrates it, and asserts that:

- every note, canvas, revision and attachment still opens;
- attachment content IDs are byte-identical before and after;
- sync change IDs and the applied cursor are byte-identical before and after;
- `vbrain audit verify` still validates the pre-migration chain;
- migrating twice is a no-op.

A new `test/fixtures/keyring-v2` fixture is added for the format itself.

Tampering tests, all of which must fail closed: a slot header edited to a lower
`N`; `wrapped.ciphertext` corrupted; `N` outside the accepted bounds or not a
power of two; a slot's `wrapped` value copied onto another slot's header; a
`version: 2` document manifest with no keyring present; a kv envelope v2 moved
from one file name to another.

Cross-core: a Rust test opens the checked-in `keyring-v2` fixture and asserts
the same attachment content ID that the Node test computes, so the two cores
cannot drift.

Phase 7.4 adds fault injection: interrupt a re-key at a random object, then
resume and assert the vault is complete and consistent.

Performance: `npm run benchmark:100k` before and after. Unlock is expected to
rise by roughly 0.23 s from the KDF change; key-value writes are expected to
fall, since scrypt no longer runs per write. Both numbers go in the pull
request, per `CONTRIBUTING.md`.

## Documented limitations

These go into `SECURITY.md` alongside the change.

Migration does not strengthen copies that already exist. A backup taken before
migration is still attackable at N=2^15 and still opens with the old passphrase.

Changing the passphrase does not re-encrypt content. An attacker who learned the
old passphrase and holds a copy of the vault reads what that copy contains. Only
`vbrain rekey` protects content written afterwards.

Even after a re-key, `attachmentId` and `syncChange` remain the keys they always
were. Someone who knew the old passphrase can still test whether a specific file
is present in the vault. They cannot read it. Rotating identity keys would
invalidate every reference in the vault and is deliberately not offered.
