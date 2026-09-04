# Phase 7.3 — Passphrase Change and the KDF Cost Upgrade Path — Design

Date: 2026-09-04
Roadmap item: Phase 7, key wrapping, passphrase change and re-key
Shared contract: `docs/superpowers/specs/2026-09-03-vault-keyring-design.md`

## Scope

Phases 7.1 and 7.2 put every vault data key inside a passphrase-wrapped
`keyring.json` and taught both cores to read one. Nothing yet changes the
passphrase that wraps it, and nothing raises the KDF cost of a vault created
before `DEFAULT_SCRYPT_N` rose to 2^17.

In scope:

- `vbrain passphrase change`: re-wrap the existing keyset under a new
  passphrase at the current default cost.
- The same command as the KDF cost upgrade path, since every slot it writes
  carries `DEFAULT_SCRYPT_N` and a fresh salt.
- Updating the OS credential store when it holds a passphrase for the vault.
- The `SECURITY.md` limitation: changing the passphrase re-encrypts nothing.

Out of scope: `vbrain rekey` (7.4), the recovery-key slot, a passphrase
strength estimate beyond a length floor, and the desktop passphrase-change
interface. The Rust core needs no change: since 7.2 it reads `N` from the slot
and never compares it against a compiled-in constant.

## Command surface

One command, no cost flag:

```
vbrain --vault <dir> passphrase change
```

`passphrase` is a commander parent command with `change` beneath it, leaving
room for later siblings without re-shaping the surface.

Raising the KDF cost is not a separate command. Every slot this command writes
uses `DEFAULT_SCRYPT_N`, so a user on an old vault raises their work factor by
changing their passphrase — re-entering the same passphrase is a legitimate use
of the command. It is nonetheless refused by default when the new passphrase is
byte-identical to the current one, because that case is far more often a
mistake than a deliberate cost upgrade; the message names
`--allow-same-passphrase` as the way to say it was deliberate.

## Flow

Everything below runs inside `withVaultLock(vaultDir, ...)`.

1. `detectVaultFormat(vaultDir)`. Anything but `keyring` is refused: a `legacy`
   or `empty` vault is told to run `vbrain migrate` first. This command never
   migrates a vault as a side effect — two irreversible operations do not
   belong in one invocation, and `migrate` has its own output and its own
   "older desktop builds cannot open this" warning to deliver.
2. Read the current passphrase by the existing path: `VBRAIN_PASSPHRASE`, then
   the OS credential store for this vault, then a masked prompt.
3. `readKeyring(vaultDir)` and unwrap the keyset. A wrong passphrase surfaces
   as a GCM authentication failure and is reported as one sentence.
4. Read the new passphrase from `VBRAIN_NEW_PASSPHRASE`, or prompt twice and
   require the two entries to match.
5. Validate: at least 12 characters, and different from the current one unless
   `--allow-same-passphrase` is given.
6. Re-wrap. See "Slot rewrite" below.
7. `writeKeyring` — a single atomic write of the whole file.
8. Verify: re-read `keyring.json` from disk, unwrap it with the new passphrase,
   and assert the keyset is byte-identical to the one just unwrapped. A vault
   whose keyring does not open under the passphrase the user was just given is
   an unrecoverable vault, so this check runs before the command claims success.
9. `forgetVaultKeys(vaultDir)` — the in-process keyset cache is keyed by the
   passphrase and by the first slot's salt, and both have just changed.
10. Update the OS credential store if it holds a passphrase for this vault.

Steps 1 to 9 leave the vault correct on their own. Step 10 is the only one that
touches state outside the vault, and it is deliberately last.

## Slot rewrite

Every slot the current passphrase opens is re-wrapped under the new passphrase
with a fresh 16-byte salt at `DEFAULT_SCRYPT_N`. A slot it cannot open is
carried across untouched.

Today a keyring holds exactly one slot, so this is indistinguishable from
replacing the slot list outright. It differs the moment the format carries a
slot this passphrase is not supposed to open — the recovery-key slot the shared
contract reserves — and at that point silently discarding it would destroy the
only fallback the user has. The forward-compatible rule costs one loop.

Slot identity is not preserved: `wrapKeySet` mints a new `id` and `createdAt`.
Nothing references a slot by ID, and a new ID correctly reflects that this is
new key-wrapping material rather than an edit of the old.

The keyset itself is unchanged, byte for byte. No object under `documents/`,
no attachment, no sync change and no audit entry is read or rewritten. The cost
of the command is two scrypt derivations and one small file write, whatever the
size of the vault.

## Module boundary

New file `src/keyring-passphrase.ts`, one export:

```ts
export interface PassphraseChangeReport {
  slotsRewritten: number;
  slotsPreserved: number;
  previousN: number;
  newN: number;
}

export function changeVaultPassphrase(
  vaultDir: string,
  currentPassphrase: string,
  newPassphrase: string,
  options?: { allowSamePassphrase?: boolean },
): PassphraseChangeReport;
```

The function takes both passphrases as arguments and returns a report. It does
not prompt, does not print, and does not touch the credential store: prompting,
printing and the keychain live in `src/cli.ts`. This is the boundary
`keyring-migrate.ts` already draws, and it is what lets the tests drive the real
operation without a terminal.

`previousN` is read from the first slot the current passphrase opens, and is
reported so the CLI can tell the user their work factor rose.

`src/keyring.ts` is not modified. `wrapKeySet`, `unwrapSlot`, `readKeyring`,
`writeKeyring`, `zeroKeySet` and `forgetVaultKeys` already provide everything
this phase needs.

## Errors and crash safety

The keyring file is the single source of truth and is written atomically, so a
crash leaves either the old keyring or the new one — both openable, neither
half-written. There is no intermediate state in which two passphrases work.

Refusals that happen before step 7 leave `keyring.json` untouched: a legacy
vault, a wrong current passphrase, a mismatched confirmation, a short new
passphrase, an unchanged passphrase without the flag.

If step 10 fails — no credential store, or a store that rejects the write — the
command still succeeds, because the vault genuinely did change, and says so in
plain terms: the passphrase changed, the remembered credential is now stale,
run `vbrain unlock --remember` to store the new one. Failing the command here
would be worse, because it would report failure for an operation that
completed.

The closing output of the command states that changing the passphrase does not
re-encrypt anything, and that a leaked passphrase needs `vbrain rekey`.

## Non-interactive use

The current passphrase resolves through `getPassphrase`, unchanged. The new one
comes from `VBRAIN_NEW_PASSPHRASE` when that is set, and from two masked
prompts otherwise. This mirrors `VBRAIN_PASSPHRASE` exactly, so scripted use and
the end-to-end tests drive the real CLI rather than only the library function.

The prompting path reuses `readSecret` and enforces the match between the two
entries before any KDF work happens.

## Testing

New `test/keyring-passphrase.test.mjs`, added to the file list of the `test`
script:

- After a change, the old passphrase no longer opens the vault and the new one
  does.
- The keyset is byte-identical across the change: a note written before the
  change reads back after it, an attachment keeps its content address, and
  `vbrain audit verify` still validates the chain.
- Cost upgrade: a keyring hand-built at `N = 2**14` (the lowest accepted bound,
  so the test stays fast) comes out at `DEFAULT_SCRYPT_N`, with a different
  salt, and the report says so.
- A slot the current passphrase cannot open is preserved unchanged, and the
  report counts it.
- Refusals leave the file byte-identical on disk: legacy vault, wrong current
  passphrase, new passphrase under 12 characters, new passphrase equal to the
  current one without the flag.
- `--allow-same-passphrase` re-wraps at the new cost and the vault still opens.
- After a change, `openVaultKeys` with the old passphrase fails rather than
  returning a cached keyset.
- CLI end to end: `VBRAIN_PASSPHRASE` plus `VBRAIN_NEW_PASSPHRASE` through the
  built `dist/cli.js`, asserting the exit code, the output and the vault.
- Keychain: with a stubbed backend (`setKeychainBackend`) holding the old
  passphrase, the change updates it; with a backend whose write throws, the
  command still succeeds and warns.

No fixture is added or regenerated: this phase changes no on-disk format.

Performance is not a gate here. The command does two scrypt derivations and one
small write; there is no vault-size-dependent work to measure.

## Documentation

- `docs/ROADMAP.md`: tick "Passphrase change, including the KDF cost upgrade
  path".
- `README.md`: the command, among the vault lifecycle commands.
- `SECURITY.md`: changing the passphrase re-encrypts nothing, so a copy of the
  vault taken while the old passphrase was current stays readable to whoever
  knows it; `vbrain rekey` (7.4) is the answer to a leak. Also: a vault created
  before 2^17 keeps its old cost until the passphrase is changed once.
- `docs/ARCHITECTURE.md`: one line, that a passphrase change re-wraps the
  keyset and rewrites no object.
