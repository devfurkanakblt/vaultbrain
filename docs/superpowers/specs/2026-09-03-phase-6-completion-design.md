# Phase 6 Completion — Design

Date: 2026-09-03  
Roadmap items: Phase 6 — epoch-based content-key rotation; desktop multi-device
integration; external security audit; stable 1.0 format

## Scope

Phase 6 shipped the encrypted change protocol, owner-signed device enrollment
and revocation, owner-signed freshness checkpoints, an opaque relay and a
recovery drill. Four items remained open. This design closes the two that are
code-completable in this repository, defines the honest boundary of the third,
and states plainly what the fourth cannot be.

| Item | This design delivers |
| --- | --- |
| Epoch content-key rotation | Complete implementation |
| Stable 1.0 format | Complete: frozen spec, version surface, conformance vectors |
| Desktop multi-device | Read-only sync status in the Rust core and desktop UI |
| External security audit | An auditor-ready package; the audit itself is third-party work |

Two constraints apply throughout. Older vaults must stay readable: every format
change is additive and versioned, and no existing artifact is rewritten in
place. And the sync protocol keeps exactly one authoritative implementation.

## 1. Epoch content-key rotation

### Problem

Every sync change is sealed with `session.key` — the document master key
derived directly from the passphrase by scrypt (`sync.ts`, `SyncChangeLog.key`).
Device revocation therefore removes a device's _authority to write_ but not its
_ability to read_: `SECURITY-AUDIT-2026-09-02.md` finding 163 asked for epoch
rotation precisely because a revoked device retains the master key and keeps
decrypting everything the relay accumulates afterwards.

`SyncDeviceRegistryBody.epoch` and `SyncDeviceCertificate.epoch` already exist
and are already enforced — `sync.ts:839` refuses to sign a change when a
device's certificate epoch differs from the registry epoch — but nothing ever
advances the epoch and no content key is bound to it. The skeleton is in place;
the meaning is missing.

### Key hierarchy

```
masterKey = scrypt(passphrase, manifest.salt)
  ├── identity/authority.key.enc          Ed25519 owner authority   (unchanged)
  ├── identity/<device>.key.enc           Ed25519 device signing    (unchanged)
  ├── identity/<device>.x25519.key.enc    X25519 device agreement   (new)
  └── identity/epochs/<n>.key.enc         random 32-byte epoch key, n >= 2 (new)
        └── changeKey = HMAC(epochKey, "...sync-change-key:v2" || NUL || changeId)
```

Epoch 1 has no entry under `identity/epochs/`: it is the historical epoch and
its changes are sealed with the master key, as they are today.

The epoch content key is `crypto.randomBytes(32)` — deliberately **not**
derived from the passphrase. A derived key would be reproducible by anyone
holding the passphrase, which is exactly the party rotation must exclude.

Each epoch key is stored locally encrypted under the master key so the device
that already holds it can reopen historical epochs after a restart, and so a
full encrypted-vault backup still restores everything. It reaches _other_
devices only in wrapped form.

### Distribution

`SyncDeviceCertificate` version 2 adds `keyAgreementKey`: a canonical base64
X25519 public key. Enrollment generates an X25519 pair alongside the existing
Ed25519 pair; the private half is stored in `identity/` under the master key
and, like every other private identity key, is absent from sync exports.

`SyncDeviceRegistryBody` version 2 adds `epochKeys`: for the current epoch, one
wrapped copy per active device.

```
ephemeral = X25519 keypair (fresh per wrap)
shared    = X25519(ephemeral.private, device.keyAgreementKey)
wrapKey   = HKDF-SHA256(shared, salt = zero-length, info = "...sync-epoch-wrap:v1" || epoch || deviceId)
wrapped   = AES-256-GCM(wrapKey, epochKey), aad = "...sync-epoch-wrap:v1" || epoch || deviceId
```

Binding epoch number and device ID into both the HKDF info and the AEAD AAD
means a wrap cannot be replayed onto a different device or a different epoch.
The wraps live inside the owner-signed registry body, so they are covered by
the authority signature and travel over the existing `sync devices export` /
`sync devices import` channel with no new transport.

A device opens the current epoch by finding its own wrap, deriving the shared
secret with its X25519 private key, and caching the result to
`identity/epochs/<n>.key.enc`.

### Envelope and change format

One rule governs which key seals a change: **epoch 1 is the master-key epoch;
every epoch from 2 upward uses a random wrapped epoch key.** Epoch 1 predates
this design and exists in vaults already on disk, so it keeps its existing
sealing and gets no random key and no wraps.

`EncryptedSyncChange` version 2 therefore adds `epoch: number` with a minimum
of 2, and is sealed with that epoch's content key. Version 1 envelopes carry no
epoch field, are sealed with the master key, and belong to epoch 1.

Reading accepts both. Writing follows the registry's current epoch: a vault
still at epoch 1 writes version 1 envelopes exactly as it does today, and a
vault at epoch 2 or higher writes version 2. Since rotation is triggered only
by revocation, a vault that has never revoked a device never changes its
on-disk change format at all — no rewrite, no migration step.

`changeId` remains `HMAC(key, context || NUL || canonicalBody)`, with the epoch
key substituted for the master key in version 2, so IDs stay unguessable to a
relay and remain stable within an epoch.

### Rotation trigger

Rotation is automatic on revocation and has no separate manual command. That is
a deliberate narrowing: rotation exists to make revocation mean something, and
a manual `rotate` verb is additive if a need for periodic rotation appears
later.

`SyncDeviceManager.revoke()` becomes a single signed registry revision that:

1. marks the device revoked at the observed sequence cutoff (unchanged);
2. increments `epoch`;
3. generates a fresh random epoch key;
4. issues a new version-2 certificate at the new epoch for every remaining
   active device, reusing their existing Ed25519 and X25519 public keys;
5. wraps the new epoch key to every remaining active device only;
6. persists the new epoch key locally under the master key;
7. signs and saves the registry, incrementing `revision`.

The revoked device receives no wrap. The existing epoch equality check at
`sync.ts:839` independently stops it from authoring changes even if it somehow
obtained the key. Registry validation gains matching rules: at epoch 1
`epochKeys` is absent, at epoch 2 and above it must cover exactly the active
devices and no others, every active certificate's epoch must equal the registry
epoch, and a revoked certificate must sit at an epoch strictly below it.

Revocation is refused when it would leave zero active devices, since that would
produce an epoch key wrapped to nobody and a vault whose sync log can no longer
be extended.

### Recovery

Unchanged in shape. An encrypted vault backup contains `identity/`, including
every cached epoch key, so first-device recovery from a backup plus relay
catch-up still works. The rule that a device clone must never carry another
device's `identity/` directory now covers the X25519 private keys as well.

### What rotation does not do

Rotation is forward-only, and the documentation will say so in these words. A
device revoked at epoch _n_ keeps its copies of the epoch keys for 1..._n_ and
can still decrypt every change written before the rotation. What rotation
removes is its access to everything written afterwards — the ciphertext that
keeps accumulating on the relay. A revoked device that also holds the
passphrase and a copy of the encrypted vault still recovers historical
plaintext; the passphrase remains the security boundary, exactly as the README
already claims for the rest of the system.

### Tests

Extend `test/sync.test.mjs`:

- a revoked device cannot unwrap the post-revocation epoch key, while a
  remaining device can;
- version 1 and version 2 envelopes coexist in one log and both verify;
- a wrap replayed onto a different device ID or epoch fails its AAD check;
- a registry whose `epochKeys` omit an active device, cover a revoked one, or
  disagree with certificate epochs is rejected;
- revoking the last active device is refused;
- rotation preserves the causal DAG: heads, parents and conflict resolution are
  unchanged across an epoch boundary;
- a checkpoint created before rotation still verifies afterwards.

## 2. Stable 1.0 format

### Problem

Version fields are scattered — `ENVELOPE_VERSION` in `crypto.ts`,
`DocumentManifest.version` and `DocumentPayload.version` in
`document-crypto.ts`, `SyncChangeBody.version` in `sync.ts` — and roughly a
dozen AAD domain-separation strings sit as literals across three files. Nothing
states "this build speaks format 1.0", and an AAD string changed by accident
would silently make existing vaults unopenable with no test to catch it.

`package.json` says `0.2.0` while `README.md:353` says `1.0.0`. Format version
and product version are different things and will be separated explicitly.

### Deliverables

**`src/format-version.ts`** (new) exports a frozen `VAULT_FORMAT_VERSION =
"1.0"`, a `FORMAT_COMPATIBILITY` record naming every on-disk artifact with the
versions this build reads and writes, and every AAD constant, re-exported by
`crypto.ts`, `document-crypto.ts` and `sync.ts` rather than redeclared. Moving
the AAD strings to one inventory is the point: they become reviewable in one
place and frozen by the conformance vectors below.

**`docs/FORMAT-1.0.md`** (new) is the normative specification: each on-disk
file, its path, its JSON shape, its version field, its AAD string, canonical
JSON rules, canonical base64 rules, the KDF parameter bounds, and the key
hierarchy including epochs. It is the single reference for an auditor or a
third-party implementation.

**`test/fixtures/format-1.0/` and `test/format-conformance.test.mjs`** (new)
freeze the format in executable form. Fixtures are generated once with a fixed
passphrase and committed: a version-0 legacy envelope, a version-1 envelope, a
document manifest, a version-1 sync change, a version-2 epoch sync change, a
version-1 registry, a version-2 registry with epoch wraps, and a checkpoint.
The test opens each and asserts the exact expected plaintext. Any accidental
change to a version field, an AAD string, or the canonical encoding breaks a
test instead of breaking a user's vault.

**Compatibility policy**, stated in `docs/FORMAT-1.0.md`: within 1.x only
additive optional fields are permitted. Bumping an artifact version, changing
an AAD string, removing a field, or altering canonical encoding requires 2.0
and a migration path. Reading support for older versions is never dropped
inside a major version.

**`sbrain format`** prints the version matrix and the format version, so bug
reports and audit correspondence can state precisely what a vault was written
by.

### Tests

`format-conformance.test.mjs` as described, plus an assertion that
`FORMAT_COMPATIBILITY` lists every AAD constant actually used — a guard against
a future constant being added outside the frozen inventory.

## 3. Desktop multi-device — read-only sync status

### Problem and constraint

`src-tauri/src/lib.rs` is a 6531-line independent reimplementation of the vault
with its own `aes-gcm`, `scrypt` and `ed25519-dalek` dependencies, and it does
not read `documents/sync` at all. Porting the sync protocol to Rust would
create a second implementation of a security protocol — the largest single
audit-surface increase available to this project, and the most likely source of
a silent divergence between two implementations of the same format.

So the desktop gains visibility, not authority. The protocol keeps one
authoritative implementation.

### Design

New Tauri commands, all read-only, all `async`, following the existing
capability-scoped command pattern:

- `sync_status` returns registry presence, authority fingerprint, current
  epoch, registry revision, per-device summaries (id, name, serial, epoch,
  active or revoked-after-sequence), checkpoint sequence and creation time, the
  total change count, and the count not yet applied.
- `sync_verify_registry` verifies the owner authority signature over the
  registry body with `ed25519-dalek` and reports the result.

Rust reads the encrypted registry and checkpoint with the existing document-key
machinery, parses the canonical JSON, and verifies signatures. It performs no
DAG validation, opens no change envelopes, and unwraps no epoch keys — the
change store is counted by filename, never decrypted. Version-2 registries and
certificates parse; unknown future versions surface as "a newer format this
build cannot display" rather than an error.

A `SyncStatus` panel in `desktop/src` shows device list, active epoch,
checkpoint freshness and unapplied-change count. Every mutating operation —
enroll, revoke, import, apply, relay push and pull — renders the exact `sbrain`
command to run, with a short note that sync mutation is CLI-only in this
release. The panel appears only when a registry exists, and states the
experimental boundary that the CLI's `--experimental-trusted-sync` gate states.

### Tests

`cargo test` unit tests for registry and checkpoint parsing, signature
verification, a tampered-signature rejection, and forward-compatible handling
of a version-2 registry and an unknown version. A `vitest` test for the panel
covering the no-registry, healthy, revoked-device and stale-checkpoint states.

## 4. External security audit — readiness package

The audit is third-party work and this design does not claim to perform it. It
produces what an auditor needs to start.

**`docs/AUDIT-SCOPE.md`** (new) records in-scope components with line counts,
trust boundaries, the threat model, and out-of-scope areas. It states the
accepted known risks plainly: the passphrase is the only real boundary; the
grant layer narrows what an agent receives but is not a boundary against a
model; `SBRAIN_AGENT` is a chosen name, not a credential; epoch rotation is
forward-only. It links the findings already closed by
`SECURITY-AUDIT-2026-09-02.md` and `SECURITY-REMEDIATION-2026-09-03.md`, and
lists the concrete questions the auditor is asked to answer.

The two-implementation problem is named as a first-class scope item: the
TypeScript core and the Rust core read the same format through different code,
and `docs/FORMAT-1.0.md` plus the conformance vectors are offered as the
material for checking them against each other.

The document also carries reproducible build and verification steps, and points
at the conformance fixtures as auditor test material.

**`SECURITY.md`** is updated so the 1.0 gate is unambiguous: until an
independent review is complete, releases are not presented as suitable for real
medical, financial or identity data.

**`docs/ROADMAP.md` and `README.md`** are updated to reflect exactly what is
done and what is not. Epoch rotation and the stable 1.0 format become checked.
The desktop item is recorded as read-only status shipped with mutation still
CLI-only. The external audit stays unchecked with
a note that the readiness package exists. Nothing that did not happen is marked
as having happened.

## Ordering and risk

Epoch rotation lands first because the format freeze must describe the final
shape of the registry and envelope, not an intermediate one. The 1.0 format
work follows and freezes both. Desktop read-only status comes third, since it
parses the frozen registry format. The audit package is last because it
documents the finished state.

The principal risk is that rotation touches the code path every sync change
flows through. It is contained by keeping version 1 reading intact and
unmodified, by making version 2 additive, and by the conformance vectors, which
fail loudly if the version-1 path shifts at all.
