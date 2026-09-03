# Phase 7.2 — Rust Read Parity and Keyring-Native Vaults — Design

Date: 2026-09-03
Roadmap item: Phase 7, key wrapping, passphrase change and re-key
Shared contract: `docs/superpowers/specs/2026-09-03-vault-keyring-design.md`

## Scope

Phase 7.1 put every vault data key behind a passphrase-wrapped `keyring.json`
and added `vbrain migrate`. The Rust core cannot open such a vault, so the
desktop application refuses every migrated vault. This phase closes that gap and
makes a newly created vault keyring-native in both cores.

In scope:

- The Rust core reads a keyring, takes `documents` and `attachmentId` from the
  keyset, and stops comparing the KDF cost against a compiled-in constant.
- The Rust core explains, rather than mis-reports, a `version: 2` document
  manifest with no keyring beside it.
- A brand-new vault is created keyring-native by both cores.
- A cross-core fixture test in each direction, so the two implementations of the
  format cannot drift.
- `keyring.json` in `docs/ARCHITECTURE.md`, and the "losing it loses the vault"
  warning in `SECURITY.md`.

Out of scope: `vbrain passphrase change` (7.3), `vbrain rekey` (7.4), the
recovery-key slot, and the desktop passphrase-change interface. The cosmetic
follow-ups carried out of the 7.1 review stay open, except the `.gitignore`
negation for fixture audit logs, which is included because its absence already
caused one silent fixture omission.

## Sequencing decision

7.2 is committed onto the existing `phase-7-vault-keyring` branch rather than a
branch of its own, and phases 7.1 and 7.2 reach `main` in one pull request. The
shared contract asks for a pull request per phase, and this deviates from it on
purpose: the same document also states that neither phase is shippable alone.
Merging 7.1 by itself would ship a `vbrain migrate` command that produces vaults
the desktop build of the same commit cannot open.

## Rust keyring module

`src-tauri/src/keyring.rs` is a new module. `src-tauri/src/lib.rs` is already
6,212 lines, and format code with its own validation, tampering surface and
fixture tests is exactly the kind of unit that belongs behind an interface: it
depends on nothing in `lib.rs` and `lib.rs` uses it through a handful of
functions.

It owns:

- `KeySet` — the six keys in `KEY_NAMES` order, each a `Zeroizing<[u8; 32]>`.
- `KeyringFile`, `KeyringSlot`, `SlotKdf` — the on-disk shapes from the shared
  contract.
- `read(vault_dir) -> Result<Option<KeyringFile>, String>` — `None` when there is
  no `keyring.json`; rejects a symlink first, as every other vault read does.
- `unwrap_keyring(&KeyringFile, passphrase) -> Result<KeySet, String>` — tries
  each slot in order and returns the first that opens, matching
  `unwrapKeyring` in `src/keyring.ts`.
- `random_key_set()`, `wrap_key_set(&KeySet, passphrase, n)`,
  `write(vault_dir, &KeyringFile)` — the creation path for a new vault.

Two properties fix the format across the two cores.

**Associated data must be byte-identical.** `src/keyring.ts:129` builds it with
`JSON.stringify` over `{ context, version, id, type, kdf: { name, N, r, p, salt } }`,
so the field order is fixed and the cost field is the single upper-case letter
`N`. The Rust side serializes a struct whose fields are declared in that same
order, with `#[serde(rename = "N")]`, through `serde_json::to_vec` (compact, no
pretty printing). A test pins the produced bytes against the literal string, and
the equivalent Node test pins the same literal, so a reordering or a rename in
either core fails immediately instead of at a user's vault.

**The KDF bounds and the memory ceiling match.** `N` a power of two in
`[2^14, 2^20]`, `r` in `[1, 32]`, `p` in `[1, 16]`, salt 16 to 64 bytes, keyset
entries exactly 32 bytes. The `scrypt` crate takes `log2(N)` and has no `maxmem`
parameter, so the module additionally rejects any accepted-looking parameter set
whose `128 * N * r` exceeds 256 MiB. That is the same fixed ceiling
`scryptMaxmem` applies in `src/keyring.ts:111`, and for the same reason: a
tampered file must not be able to dictate its own memory budget.

A wrong passphrase surfaces as a GCM authentication failure with the wording
`src/keyring.ts` already uses — "Unable to unlock this vault: wrong passphrase,
or the keyring is damaged." There is no verifier field to check.

`VaultSession` gains `attachment_id_key` beside its existing `key`, which stays
the `documents` key. The attachment content-address HMAC at
`src-tauri/src/lib.rs:4378` switches to `attachment_id_key`. On a legacy vault
that key is an independent copy of the document key, which is what the legacy
format means and what `src/document-crypto.ts` does. Both key buffers are
zeroized when the session drops.

`N` is never compared against a compiled-in constant again. It is read from the
slot, bounds-checked, and used. That comparison at `src-tauri/src/lib.rs:1419`
is the defect the shared contract set out to remove.

## `open_session` control flow

`src-tauri/src/lib.rs:1414-1447` is replaced by three branches, in this order.

**1. `keyring.json` exists.** Unwrap it, take `documents` and `attachmentId`,
and ignore `kv`, `syncChange`, `syncEnvelope` and `audit` — the Rust core
touches neither the key-value store, nor sync, nor the audit chain. The document
manifest is not read at all in this branch: a migrated vault carries the version
tombstone and a vault created by this phase carries the same tombstone, and
neither holds anything the keyring branch needs.

**2. No keyring, `documents/manifest.json` exists.** The version is read before
anything else, from a deserialization that does not require the legacy fields.
A manifest declaring version 2 means the keyring was lost, and the error says
so, in the same words `src/document-crypto.ts` uses: "This vault was upgraded to
a keyring, but keyring.json is missing or unreadable." Today serde fails on the
absent `kdf` field first and the user is told "missing field kdf", which is safe
but explains nothing. Version 1 keeps today's path unchanged, including the
`N == 32768` check and the verifier comparison, because a legacy vault is still
a supported vault.

**3. No keyring and no legacy material at all.** A keyring is created: six
independent random keys, wrapped in one `passphrase` slot with a fresh 16-byte
salt at `N = 2^17`, written atomically.

Branch 3 carries two decisions that the shared contract does not state.

**A created vault also writes the version tombstone.** `documents/manifest.json`
becomes `{ "version": 2, "keyring": true }`, exactly as migration leaves it.
Without it, a build from before 7.1 opening a keyring-native vault finds no
manifest, concludes the vault is an empty legacy vault, writes its own manifest,
and stores notes under a key nobody else will look for. Older builds fail closed
only on a manifest whose version is not 1, so the tombstone is what makes them
refuse. It also makes a created vault and a migrated vault byte-shaped the same,
which means one set of read paths covers both.

**"No manifest" is not "empty vault", so the format detection is ported.**
`detectVaultFormat` in `src/keyring.ts:282` treats `documents/manifest.json`,
`audit.meta.json`, `grants.enc`, `schema.json` and any `*.kv.enc` as legacy
markers. A vault used only through the key-value commands has no document
manifest but does have `audit.meta.json` and `*.kv.enc`. Writing a keyring
beside those would put a random `audit` key in front of an `audit.log` whose
entries were chained under the key derived from `audit.meta.json`, and
`vbrain audit verify` would stop validating a chain that is in fact intact. So
the Rust core creates a keyring only when no legacy marker is present, and
otherwise keeps its current legacy behaviour and leaves the upgrade to
`vbrain migrate`.

## Keyring-native new vaults in TypeScript

`src/keyring.ts` gains `openOrCreateVaultKeys(vaultDir, passphrase)`:

- a keyring present — open it, as `openVaultKeys` does, cache included;
- a legacy marker present — return `null`, so every existing legacy branch
  behaves exactly as it does today;
- neither — take `withVaultLock` (already reentrant per process, so a caller
  that already holds it is safe), re-check under the lock, then write
  `keyring.json` and the document-manifest tombstone atomically at mode `0600`
  and return the keyset.

`openVaultKeys` keeps its current contract and never creates anything. Only the
write entry points move to the creating variant — `openDocumentKey`, the
key-value write path in `src/store.ts`, the grants write path in
`src/grants.ts`, and `appendAudit` in `src/audit.ts`. A read of an empty vault
must not bring a vault into existence, and a read of a legacy vault must not
change its format.

`vbrain keychain-status` needs no change and starts reporting `keyring` for
newly created vaults, which is the visible signal that this phase landed.

`scripts/benchmark.mjs` builds its corpus on a fresh directory, so from this
phase on it exercises the keyring path. Unlock is expected to rise by roughly
0.23 s from `N = 2^15` to `N = 2^17`, against the 2 s budget in
`docs/PRODUCT.md` and a 2,000 ms gate; key-value writes are expected to fall,
because scrypt no longer runs on every write. Both numbers go in the pull
request, as `CONTRIBUTING.md` requires.

## Cross-core testing

The format now has two implementations, so it is pinned from both sides.

**Rust reads what Node wrote.** A Rust test opens the checked-in
`test/fixtures/keyring-v2` fixture, unwraps the keyset with the fixture
passphrase, decrypts the note object, and asserts the attachment content ID it
computes equals the fixture's attachment directory name. One test covers the
slot AAD, the KDF parameters, the keyset parse, the document key and the
`attachmentId` key at once.

**Node reads what Rust wrote.** A new `test/fixtures/keyring-v2-rust/` fixture
is produced by the Rust core — an `#[ignore]`d generator test, run by a
documented command, with its row in `test/fixtures/README.md`. A Node test
unwraps all six keys from it and decrypts the document the Rust core wrote. This
is the only evidence that a vault created by the desktop application opens in the
CLI, and it is checked in so it keeps being evidence.

**The AAD literal** is asserted in both cores against the same expected string.

**Fail-closed tests in Rust**, each of which must produce an error rather than a
key: a slot header edited to a lower `N`; a corrupted `wrapped.ciphertext`; an
`N` outside the bounds or not a power of two; a slot whose `wrapped` value was
copied onto another slot's header; a `version: 2` manifest with no keyring
present, which must produce the explanatory message and not the serde one.

**Node tests** for the creation rules: a fresh vault comes out keyring-native
with a version tombstone; a legacy document vault is opened without gaining a
keyring; a key-value-only legacy vault is written to without gaining a keyring,
and its audit chain still verifies.

Every fixture under `test/fixtures/` that already exists is neither regenerated
nor edited.

## Documentation

`docs/ARCHITECTURE.md` gains `keyring.json` in the vault layout and the key
hierarchy it now really implements — the document has claimed wrapped data keys
since Phase 0, and this is the phase that makes the claim true in both cores.

`SECURITY.md` gains two sentences: losing `keyring.json` loses the vault, since
no key material exists anywhere else, so a backup must include it; and a vault
created before migration is not strengthened by a copy taken afterwards.

`docs/ROADMAP.md` ticks "Rust core opens a keyring vault". `CHANGELOG.md`
records the phase. `.gitignore` gains `!test/fixtures/**/audit.log`, so the next
fixture with an audit log is not silently excluded by the blanket `*.log` rule
the way `keyring-v2`'s was.

## Risks

The one irreversible risk in this phase is a Rust-created keyring that the
TypeScript core cannot open, because the user's notes would then exist under a
key only one core can find. The checked-in Rust-written fixture is the control
for exactly that, and it fails in CI rather than on a vault.

The second risk is a keyring written beside legacy material, which would orphan
the audit chain. The ported format detection is the control, and a Node test
asserts a key-value-only vault keeps verifying after a write.
