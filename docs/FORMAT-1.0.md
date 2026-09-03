# Vault Brain on-disk format — version 1.0

This is the normative specification of the on-disk format written and read by
this repository. It is written for an external auditor or a third-party
implementer: every value below is copied verbatim from the source files named
next to it, not recalled or paraphrased. Where the text says "exactly", the
adjacent code reference is the source of truth if this document and the code
ever disagree.

## 1. Status and scope

**Format 1.0 is frozen.**

```ts
// src/format-version.ts
export const VAULT_FORMAT_VERSION = "1.0";
```

This is the **on-disk format version** — the shape of every encrypted file a
vault writes, the AEAD domain-separation strings that authenticate them, and
the key-derivation bounds a reader must accept. It is a different number from
the **product version** in `package.json` (currently `0.2.0`). The product is
pre-1.0 because the external security audit gate for a 1.0 product release has
not been met (see `docs/SECURITY-AUDIT-2026-09-02.md` and
`docs/SECURITY-REMEDIATION-2026-09-03.md`). The format can be frozen at 1.0
independently of that: freezing it is what makes an external audit of the
format possible in the first place, and what lets this document promise a
compatibility policy at all.

Everything this document describes is implemented in:

- `src/format-version.ts` — the version constant, the artifact/version matrix,
  every fixed AEAD domain-separation string.
- `src/crypto.ts` — the top-level vault envelope (`*.kv.enc`).
- `src/document-crypto.ts` — the document vault's key-derivation manifest and
  the per-object encrypted payload shape.
- `src/sync.ts` — the sync change envelope, device certificates and registry,
  the freshness checkpoint, the applied-state file, and the canonical JSON /
  canonical base64 rules.
- `src/sync-epoch.ts` — the epoch key hierarchy and the per-device wrap
  construction.

## 2. Compatibility policy

This is a commitment about what future 1.x changes to this codebase are
allowed to do to files already on disk, stated exactly as it appears in
`src/format-version.ts`:

> Compatibility policy: within 1.x only additive optional fields are allowed.
> Bumping an artifact version, changing an AAD string, removing a field, or
> altering a canonical encoding requires format 2.0 and a migration path.

Concretely:

- **Allowed within 1.x**: adding a new optional field to an existing artifact
  shape, adding a new artifact entirely, adding a new AAD string for a new
  artifact.
- **Requires a 2.0 format bump and a migration path**: bumping any single
  artifact's version number, changing the literal value of any AAD string,
  removing or renaming an existing field, or changing how canonical JSON or
  canonical base64 is computed.
- **Reading support for an older version is never dropped inside a major
  version.** Every entry in the artifact/version matrix (Section 5) lists a
  `reads` array that this build accepts; a 1.x release only ever grows that
  array, never shrinks it. `writes` — the version(s) newly produced — may be a
  strict subset of `reads`, which is how a version is retired from _new_
  writes without breaking _old_ readers (see the `encryptedEnvelope` entry,
  which still reads version `0` but only ever writes version `1`).

There is no manual, periodic, or automatic rotation schedule for anything in
this document. The one place content keys change — sync epoch rotation — is
described in Section 6 and happens only as the direct consequence of revoking
a device.

## 3. Encodings

These rules are shared across every artifact in Section 5 unless a subsection
says otherwise.

**Canonical JSON** is RFC 8785-compatible for the JSON subset this codebase
accepts (null, boolean, finite number, string, array, plain object — see
`validateJson` in `src/sync.ts`): object keys are sorted by UTF-16 code unit
and the output carries no insignificant whitespace. The implementation is
`canonicalJsonUnchecked` in `src/sync.ts`:

```ts
// src/sync.ts
function canonicalJsonUnchecked(value: SyncJson): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJsonUnchecked).join(",")}]`;
  const entries = Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJsonUnchecked(value[key])}`);
  return `{${entries.join(",")}}`;
}
```

`canonicalSyncJson` (the exported wrapper) is what every sync artifact is
serialized through before it is hashed, signed, or encrypted — the change ID,
the checkpoint ID, every Ed25519 signature payload, and every sync
ciphertext's plaintext are all canonical JSON of this exact shape.

**Canonical base64** means the encoded string round-trips byte-for-byte:

```ts
// src/format-version.ts — canonicalBase64
if (decoded.toString("base64") !== value) {
  throw new Error(`Encrypted payload has non-canonical ${label}.`);
}
```

i.e. `Buffer.from(v, "base64").toString("base64") === v`. This rejects
non-canonical padding (`"QQ"` for what should be `"QQ=="`) as well as a
malformed alphabet. This exact check governs every base64 field in the
sync/document layer (`src/sync.ts`, `src/sync-epoch.ts`) via the shared
`canonicalBase64` helper. The top-level vault envelope (`*.kv.enc`,
`src/crypto.ts`) validates its own base64 fields (`salt`, `iv`, `authTag`,
`ciphertext`) with a separate, looser check — alphabet and length bounds only,
via `base64Bytes` in `src/crypto.ts` — and does **not** additionally require
canonical padding on those fields.

Length bounds enforced through `canonicalBase64(value, expectedBytes, label)`
calls across `src/sync.ts` and `src/sync-epoch.ts`:

- **Public keys** (Ed25519 or X25519 SPKI DER): base64, **44** decoded bytes.
  Both key types share this length — code that must distinguish them checks
  `asymmetricKeyType`, not length (see `agreementPublicKeyFromBase64` in
  `src/sync-epoch.ts`).
- **Private keys** (Ed25519 or X25519 PKCS#8 DER): base64, **48** decoded
  bytes.
- **Signatures** (Ed25519): base64, **64** decoded bytes.

**Timestamps** are ISO 8601 strings that must round-trip exactly through
`new Date(t).toISOString()`:

```ts
// src/sync.ts — canonicalTimestamp
const timestamp = typeof value === "string" ? Date.parse(value) : Number.NaN;
if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
  throw new Error(`${label} must be a canonical ISO timestamp.`);
}
```

Any timestamp string that does not survive this exact round trip (wrong
precision, a non-UTC offset, etc.) is rejected, not normalized.

## 4. Key derivation

Two independent scrypt call sites exist, with different accepted ranges. Both
use `crypto.scryptSync` with a 32-byte output (`KEY_LEN` / `KEY_LENGTH`) and
`maxmem: 128 * 1024 * 1024`.

**Top-level vault envelope** (`src/crypto.ts`, guards every `*.kv.enc` file).
This build writes `N = 2^16` (`SCRYPT_N`), `r = 8` (`SCRYPT_R`), `p = 1`
(`SCRYPT_P`), and accepts a wider range on read — this is the range a
conformant reader must accept from a file it opens, enforced by
`validateParameters`:

```ts
// src/crypto.ts — validateParameters
if (!Number.isSafeInteger(N) || N < 2 ** 14 || N > 2 ** 20 || (N & (N - 1)) !== 0) {
  throw new Error("Encrypted envelope declares an unacceptable scrypt cost.");
}
if (!Number.isSafeInteger(r) || r < 1 || r > 32)
  throw new Error("Encrypted envelope declares an unacceptable scrypt block size.");
if (!Number.isSafeInteger(p) || p < 1 || p > 16)
  throw new Error("Encrypted envelope declares an unacceptable scrypt parallelism.");
base64Bytes(candidate.salt, 16, 64, "salt");
```

So: `N` a power of two with `2^14 <= N <= 2^20`; `r` a safe integer in
`1..32`; `p` a safe integer in `1..16`; `salt` 16 to 64 decoded bytes. The
pre-versioning (legacy, envelope version `0`) format has no recorded
parameters on disk at all — its parameters were compiled into the binary as
`LEGACY_PARAMETERS` (`N = 2^15`, `r = 8`, `p = 1`), which is exactly why the
format is versioned now: any future change to what "legacy" means would be
undetectable from the file itself.

The envelope header — `version`, `cipher`, and the `kdf` object (`name`, `N`,
`r`, `p`, `salt`) — is itself the AEAD associated data for the ciphertext:

```ts
// src/crypto.ts — headerAad
function headerAad(version: number, kdf: ScryptParameters): Buffer {
  return Buffer.from(
    JSON.stringify({ version, cipher: ALGO, kdf: { name: kdf.name, N: kdf.N, r: kdf.r, p: kdf.p, salt: kdf.salt } }),
    "utf8",
  );
}
```

So a header cannot be rewritten — to claim a different (weaker) `N`/`r`/`p`,
or a different declared cipher or version — without the GCM authentication tag
check failing on decrypt. `ALGO` is `"aes-256-gcm"`.

**Document vault manifest** (`src/document-crypto.ts`, `documents/manifest.json`).
This is a narrower, closed set rather than a range: a manifest's `kdf.N` must
be exactly `2^15` or `2^16` (`SUPPORTED_SCRYPT_N = new Set([2 ** 15, 2 ** 16])`);
new manifests are always written with `N = 2^16`. `r` and `p` are not
recorded in this manifest, and `derive()` in `src/document-crypto.ts` does not
pass them to `crypto.scryptSync` explicitly — they take Node's built-in
`scrypt` defaults (`r = 8`, `p = 1`). This KDF derives the document-vault
master key from the passphrase and is verified by an HMAC check (`verifier`),
not by an AEAD header. On open, `openDocumentKey` first rejects any `kdf.N`
outside `{2^15, 2^16}` outright (`SUPPORTED_SCRYPT_N`); an `N` inside that set
but different from the one the vault was actually created with instead
surfaces indirectly, as an HMAC verifier mismatch.

## 5. Artifact catalogue

One subsection per entry in `FORMAT_COMPATIBILITY` (`src/format-version.ts`),
in the order that constant declares them. `reads` is every version this build
accepts; `writes` is every version this build newly produces (Section 2).

### `encryptedEnvelope` — `*.kv.enc`

`reads: [0, 1]`, `writes: [1]`. Defined in `src/crypto.ts`.

Version 1 (`EncryptedPayload`):

```ts
interface EncryptedPayload {
  version: number; // 1
  cipher: "aes-256-gcm";
  kdf: { name: "scrypt"; N: number; r: number; p: number; salt: string };
  iv: string; // base64, 12 bytes
  authTag: string; // base64, 16 bytes
  ciphertext: string; // base64
}
```

Version 0, the pre-versioning legacy shape (`LegacyEncryptedPayload`) — no
`version`, `cipher`, or `kdf` fields, and no AAD at all on decrypt:

```ts
interface LegacyEncryptedPayload {
  salt: string;
  iv: string;
  authTag: string;
  ciphertext: string;
}
```

AAD: the header itself, as `headerAad(version, kdf)` above (not a fixed
string — this is the one artifact whose AAD is structural rather than a
constant). Legacy (version 0) payloads carry no AAD.

### `documentManifest` — `documents/manifest.json`

`reads: [1]`, `writes: [1]`. Defined in `src/document-crypto.ts`. Not AEAD
data — a plaintext JSON file that records the KDF parameters and an HMAC
verifier used to confirm a passphrase before deriving the document-vault
master key:

```ts
interface DocumentManifest {
  version: 1;
  kdf: { name: "scrypt"; N: number; salt: string };
  verifier: string; // lowercase hex, 64 chars (HMAC-SHA256)
}
```

"AAD" here is really the HMAC message, not AEAD associated data:
`verifier = HMAC-SHA256(key, AAD.documentKeyCheck)` where
`AAD.documentKeyCheck = "secondbrain-vault:document-key:v1"` (`src/format-version.ts`).

### `documentPayload` — `documents/objects/*.enc`

`reads: [1]`, `writes: [1]`. Defined in `src/document-crypto.ts`; this is the
generic AES-256-GCM envelope shared by every encrypted object the document
vault stores, wherever it actually lives on disk:

```ts
interface DocumentPayload {
  version: 1;
  iv: string; // base64, 12 bytes
  authTag: string; // base64, 16 bytes
  ciphertext: string; // base64
}
```

The literal path glob in `FORMAT_COMPATIBILITY` (`documents/objects/*.enc`)
is representative, not exhaustive: this same envelope shape, produced by the
same `encryptDocument`/`encryptDocumentBytes` functions, also backs
`documents/attachments/<id>/manifest.enc` and attachment chunk files, and the
sync artifacts in the remaining subsections below (each of which nests one
`DocumentPayload` inside its own outer wrapper). For the id-keyed object
kinds — notes, canvases, plugins, plugin storage, and attachments — what
differs per object kind is only the AAD string passed to `encryptDocument`,
built from a per-kind prefix plus the object's own id (and, for note/canvas
history, a revision number):

| Object kind             | AAD constant / builder (`src/format-version.ts`) | AAD value                                             |
| ----------------------- | ------------------------------------------------ | ----------------------------------------------------- |
| Note                    | `noteAad(id)`                                    | `secondbrain-vault:note:v1:<id>`                      |
| Note history revision   | `noteHistoryAad(id, revision)`                   | `secondbrain-vault:note-history:v1:<id>:<revision>`   |
| Canvas                  | `canvasAad(id)`                                  | `secondbrain-vault:canvas:v1:<id>`                    |
| Canvas history revision | `canvasHistoryAad(id, revision)`                 | `secondbrain-vault:canvas-history:v1:<id>:<revision>` |
| Plugin package          | `pluginAad(id)`                                  | `secondbrain-vault:plugin:v1:<id>`                    |
| Plugin storage          | `pluginStoreAad(id)`                             | `secondbrain-vault:plugin-store:v1:<id>`              |
| Attachment manifest     | `attachmentManifestAad(id)`                      | `secondbrain-vault:attachment-manifest:v1:<id>`       |
| Attachment chunk        | `attachmentChunkAad(id, index)`                  | `secondbrain-vault:attachment-chunk:v1:<id>:<index>`  |

Two further single-purpose files also use this `DocumentPayload` shape under
a fixed (non-id-keyed) AAD, but live outside `documents/objects/` and are not
separate entries in `FORMAT_COMPATIBILITY`: the document index
(`AAD.documentIndex = "secondbrain-vault:document-index:v1"`) and the plugin
security policy (`AAD.pluginPolicy = "secondbrain-vault:plugin-policy:v1"`),
both in `src/documents.ts`. They are out of scope for this specification's
version guarantees.

### `syncChangeEnvelope` — `documents/sync/changes/*.change.enc`

`reads: [1, 2]`, `writes: [1, 2]`. Defined in `src/sync.ts`:

```ts
interface EncryptedSyncChange {
  version: 1 | 2;
  id: string; // hex, 64 chars (HMAC-SHA256 of the canonical change body)
  epoch?: number; // version 2 only; always >= 2
  payload: DocumentPayload;
}
```

A version 1 envelope must not declare `epoch`; a version 2 envelope must
declare `epoch >= 2` (`validateEnvelope` in `src/sync.ts`). Epoch 1 changes
are always version 1 envelopes and are always sealed under the vault's master
key; epoch 2-and-above changes are always version 2 envelopes sealed under
that epoch's content key (Section 6).

AAD (`payload`, i.e. the inner `DocumentPayload`): `syncChangeAad(id)` =
`${AAD.syncChangePrefix}${id}`, i.e. `secondbrain-vault:sync-change:v1:<id>`.
**This AAD string is identical for version 1 and version 2 envelopes** — the
envelope/epoch distinction is not carried in the AAD at all. It is carried in
two other places instead:

- The **encryption key** for `payload` (`changeEncryptionKey` in
  `src/sync.ts`) is `HMAC-SHA256(contentKey, AAD.syncChangeKey || "\0" || id)`
  for epoch 1, or `HMAC-SHA256(contentKey, AAD.syncChangeKeyV2 || "\0" || id)`
  for epoch 2 and above — `AAD.syncChangeKey = "secondbrain-vault:sync-change-key:v1"`,
  `AAD.syncChangeKeyV2 = "secondbrain-vault:sync-change-key:v2"`.
- The change **`id`** itself (`changeId` in `src/sync.ts`) is
  `HMAC-SHA256(contentKey, AAD.syncChangeId || "\0" || (epoch===1 ? "" : epoch+"\0") || canonicalSyncJson(body))`,
  where `AAD.syncChangeId = "secondbrain-vault:sync-change-id:v1"` — so epoch
  1 and epoch-N bodies that are otherwise byte-identical still hash to
  different ids once `epoch !== 1`.

The plaintext inside `payload` is `canonicalSyncJson(SyncChangeBody)`:

```ts
interface SyncChangeBody {
  version: 1 | 2;
  deviceId: string; // lowercase UUID
  sequence: number; // safe integer >= 1
  previousDeviceChange: string | null; // change id, or null iff sequence === 1
  parents: string[]; // sorted, unique change ids, at most 256
  createdAt: string; // canonical ISO 8601
  mutation: {
    objectType: "note" | "canvas" | "attachment" | "plugin" | "vault";
    objectId: string;
    operation: "put" | "delete";
    baseRevision: number | null;
    revision: number;
    value: SyncJson; // null iff operation === "delete"
  };
  authorization?: { certificateSerial: number; signature: string }; // version 2 only
}
```

A version 2 body's `authorization.signature` is an Ed25519 signature (not an
AEAD AAD) over `canonicalSyncJson` of `{ version, deviceId, sequence,
previousDeviceChange, parents, createdAt, mutation, authorization:
{ certificateSerial } }` — i.e. the whole body with `authorization` reduced
to just `certificateSerial` (the signature itself is excluded from what it
signs) — see `changeAuthorizationPayload` in `src/sync.ts`. A version 1 body
must not carry `authorization` at all. The whole body is capped at 8 MiB
(`MAX_CHANGE_BYTES`) of canonical-JSON UTF-8.

### `syncDeviceCertificate` and `syncDeviceRegistry` — `documents/sync/devices.enc`

Both `reads: [1, 2]`, `writes: [1, 2]`. These are two nested shapes stored in
the same file, defined in `src/sync.ts`. The outer encrypted wrapper is a
constant `version: 1` regardless of the inner body's version:

```ts
interface EncryptedSyncDeviceRegistry {
  version: 1;
  payload: DocumentPayload; // AAD: AAD.syncDeviceRegistry = "secondbrain-vault:sync-device-registry:v1"
}
```

`payload`'s plaintext is `canonicalSyncJson(SignedSyncDeviceRegistry)`:

```ts
interface SignedSyncDeviceRegistry {
  body: SyncDeviceRegistryBody;
  signature: string; // Ed25519, base64, 64 bytes, over canonicalSyncJson(body)
}

interface SyncDeviceRegistryBody {
  version: 1 | 2; // this is the "syncDeviceRegistry" artifact's [1,2] version
  revision: number;
  epoch: number;
  authorityPublicKey: string; // base64 Ed25519 SPKI DER, 44 bytes
  updatedAt: string;
  legacyChangeIds: string[]; // sorted, unique
  devices: SyncDeviceRecord[]; // sorted by certificate.deviceId
  epochKeys?: EpochKeyWrap[]; // present iff epoch >= 2 (Section 6)
}

interface SyncDeviceRecord {
  certificate: SyncDeviceCertificate; // the "syncDeviceCertificate" artifact
  certificateSignature: string; // Ed25519, base64, 64 bytes, over canonicalSyncJson(certificate)
  revokedAt?: string;
  revokedAfterSequence?: number;
}

interface SyncDeviceCertificate {
  version: 1 | 2;
  serial: number;
  deviceId: string; // lowercase UUID
  name: string; // 1-80 chars, one line
  publicKey: string; // base64 Ed25519 SPKI DER, 44 bytes
  keyAgreementKey?: string; // base64 X25519 SPKI DER, 44 bytes — version 2 only
  enrolledAt: string;
  epoch: number;
}
```

The device certificate itself carries no AAD string — its authenticity is the
Ed25519 `certificateSignature` from the registry's authority key, computed
over `canonicalSyncJson(certificate)`. Only the outer file-level envelope has
an AAD, `AAD.syncDeviceRegistry` above. A version 1 registry/certificate must
not carry `keyAgreementKey` or `epochKeys`; those are added, additively,
starting at version 2 (Section 2's "additive optional fields" rule applied to
this exact pair of fields).

### `syncEnrollmentRequest` — `(transferred)`

`reads: [1, 2]`, `writes: [1, 2]`. Defined in `src/sync.ts`. This artifact is
never written to the vault directory — it is handed off out-of-band (file or
stdout) between the requesting device and the owner:

```ts
interface SyncEnrollmentRequest {
  version: 1 | 2;
  deviceId: string;
  name: string;
  publicKey: string; // base64 Ed25519 SPKI DER, 44 bytes
  keyAgreementKey?: string; // base64 X25519 SPKI DER, 44 bytes — version 2 only
  requestedAt: string;
  nonce: string; // base64, 32 bytes
  proof: string; // base64 Ed25519 signature, 64 bytes
}
```

No AAD applies — it is never AEAD-encrypted. Its authenticity is `proof`, an
Ed25519 signature by the requesting device's own (not-yet-certified) key over
`canonicalSyncJson` of the request with `proof` itself omitted (see
`enrollmentRequestPayload` in `src/sync.ts`).

### `syncFreshnessCheckpoint` — `documents/sync/checkpoint.enc`

`reads: [1]`, `writes: [1]`. Defined in `src/sync.ts`:

```ts
interface EncryptedSyncFreshnessCheckpoint {
  version: 1;
  payload: DocumentPayload; // AAD: AAD.syncFreshnessCheckpoint = "secondbrain-vault:sync-freshness-checkpoint:v1"
}
```

`payload`'s plaintext is `canonicalSyncJson(SignedSyncFreshnessCheckpoint)`:

```ts
interface SignedSyncFreshnessCheckpoint {
  id: string; // sha256 hex of canonicalSyncJson({ body, signature })
  body: SyncFreshnessCheckpointBody;
  signature: string; // Ed25519, base64, 64 bytes, over canonicalSyncJson(body)
}

interface SyncFreshnessCheckpointBody {
  version: 1;
  sequence: number;
  authorityFingerprint: string; // sha256 hex of the registry's authorityPublicKey bytes
  registryRevision: number;
  epoch: number;
  changeCount: number;
  heads: string[]; // sorted, unique change ids, at most 256
  createdAt: string;
  previousCheckpoint: string | null; // checkpoint id, or null iff sequence === 1
}
```

### `syncAppliedState` — `documents/sync/applied.enc`

`reads: [1]`, `writes: [1]`. Defined in `src/sync.ts`. This is local,
per-device bookkeeping — the cursor of which change last touched each local
object — never signed, and not part of the synchronized log itself. Unlike
the registry and checkpoint artifacts above, this file carries **no outer
wrapper**: the top-level JSON on disk at `documents/sync/applied.enc` _is_ a
`DocumentPayload` directly (`saveAppliedState`/`readAppliedState` in
`src/sync.ts` read and write a bare `DocumentPayload`, not a
`{ version, payload }` envelope):

```ts
// documents/sync/applied.enc top-level shape: DocumentPayload
// { version: 1; iv: string; authTag: string; ciphertext: string }
// AAD: AAD.syncApplied = "secondbrain-vault:sync-applied:v1"

interface SyncAppliedState {
  version: 1;
  objects: Record<string, { changeId: string; revision: number; operation: "put" | "delete" }>;
}
```

The `DocumentPayload`'s plaintext is plain `JSON.stringify(state)` — not
`canonicalSyncJson` — since this file is never signed or hashed by content,
only decrypted and read back on the same device that wrote it.

## 6. Key hierarchy and epochs

Three kinds of key exist:

- **The vault (master) key.** Derived from the passphrase via the document
  vault manifest's scrypt parameters (Section 4). It never leaves the device
  and is used both to decrypt regular documents and to decrypt every identity
  private key file below.
- **Identity keys**, one set per enrolled device, each stored at rest as a
  `DocumentPayload` encrypted under the vault key with its own AAD, all under
  `documents/sync/identity/`:
  - Authority Ed25519 private key (owned only by the enrolling/owner device):
    `authority.key.enc`, AAD `AAD.syncAuthorityKey` =
    `secondbrain-vault:sync-authority-key:v1`.
  - Per-device Ed25519 signing private key: `<deviceId>.key.enc`, AAD
    `syncDeviceKeyAad(deviceId)` = `${AAD.syncDeviceKeyPrefix}${deviceId}` =
    `secondbrain-vault:sync-device-key:v1:<deviceId>`.
  - Per-device X25519 key-agreement private key: `<deviceId>.x25519.key.enc`,
    AAD `syncAgreementKeyAad(deviceId)` = `${AAD.syncAgreementKeyPrefix}${deviceId}`
    = `secondbrain-vault:sync-agreement-key:v1:<deviceId>`.
- **Epoch content keys**, one per sync epoch numbered from 1.

### The epoch rule

**Epoch 1 is the legacy master-key epoch.** There is no stored epoch-1 key
file, no wraps, and every epoch-1 change is a version 1 change envelope
sealed directly under the vault master key (`epochResolver` in `src/sync.ts`
returns the vault key itself when `epoch === 1`).

**Epoch 2 and above use a random 32-byte content key**
(`EPOCH_KEY_BYTES = 32`, `src/sync-epoch.ts`). This key is:

1. Generated with `crypto.randomBytes(EPOCH_KEY_BYTES)` at the moment a
   device is revoked (see below — there is no other trigger).
2. Cached at rest on each device that holds it, encrypted under that device's
   own vault master key, at `documents/sync/identity/epochs/<n>.key.enc`,
   with AAD `syncEpochKeyAad(epoch)` = `${AAD.syncEpochKeyPrefix}${epoch}` =
   `secondbrain-vault:sync-epoch-key:v1:<n>` (`readEpochKey`/`saveEpochKey` in
   `src/sync-epoch.ts`). This is a local cache, not how the key is
   distributed between devices.
3. Distributed between devices as one `EpochKeyWrap` per active device, listed
   in the owner-signed registry's `epochKeys` array (Section 5), sealed to
   that device's X25519 key-agreement public key.

**Rotation happens only on device revocation.** `SyncDeviceManager.revoke` in
`src/sync.ts` is the single call site that changes the epoch:
`registry.body.epoch + 1`. There is no manual, periodic, or automatic rotation
of an epoch's content key for any other reason — an epoch's key is generated
exactly once, at the revocation that creates that epoch, and never re-wrapped
or replaced afterwards short of a further revocation minting the next epoch.
Revoking the last active device is refused outright (nobody left to wrap the
new key to). Every device that remains active is reissued a certificate at
the new epoch and re-wrapped; the revoked device receives no wrap and is
pinned at its old (pre-revocation) certificate epoch.

### The wrap construction

Exactly as implemented in `src/sync-epoch.ts` (`wrapEpochKey`/`unwrapEpochKey`
via the shared `wrapContext`/`wrapKey`):

```ts
interface EpochKeyWrap {
  deviceId: string;
  ephemeralPublicKey: string; // base64 X25519 SPKI DER, fresh for every wrap
  iv: string; // base64, 12 bytes
  authTag: string; // base64, 16 bytes
  ciphertext: string; // base64, 32 bytes (AES-GCM ciphertext length equals the 32-byte EPOCH_KEY_BYTES plaintext; the tag is separate, in authTag)
}
```

1. Generate a fresh ephemeral X25519 key pair (`generateAgreementKeyPair`).
2. ECDH between the ephemeral private key and the target device's X25519
   key-agreement public key (`crypto.diffieHellman`).
3. `HKDF-SHA256` over that shared secret with a **zero-length salt**
   (`Buffer.alloc(0)`), output length 32 bytes, and `info` equal to the exact
   string:

   ```ts
   // src/sync-epoch.ts — wrapContext
   `${AAD.syncEpochWrap}:${epoch}:${deviceId}`;
   ```

   i.e. `secondbrain-vault:sync-epoch-wrap:v1:<epoch>:<deviceId>`
   (`AAD.syncEpochWrap = "secondbrain-vault:sync-epoch-wrap:v1"` in
   `src/format-version.ts`).

4. AES-256-GCM-encrypt the 32-byte epoch content key with the HKDF output as
   key, and the **same string** — `wrapContext(epoch, deviceId)`, identical
   bytes — as the AEAD associated data (not merely the same value computed
   independently; it is one function producing both the HKDF `info` and the
   AEAD AAD).

Both the epoch number and the device ID are bound into that one string, so a
wrap cannot be replayed onto a different device or presented as belonging to
a different epoch — changing either invalidates both the KDF context and the
authentication tag. Unwrapping (`unwrapEpochKey`) reverses exactly this: ECDH
with the device's own X25519 private key and the wrap's `ephemeralPublicKey`,
the same HKDF call, then GCM decryption checked against the same AAD.

## 7. Conformance

A third-party implementation is conformant with format 1.0 when it can open
the fixture vaults below with the shared fixture passphrase
`fixture-only-passphrase` and recover the same plaintext this codebase
recovers from them. These are committed, real vaults — not synthetic
descriptions of the format — under `test/fixtures/`:

- **`test/fixtures/sync-epoch-v2/`** — a vault that has actually been through
  one real revocation-triggered rotation. It holds one version 1 (epoch 1,
  vault-key-sealed) and one version 2 (epoch 2, wrapped-content-key-sealed)
  change envelope, a version 2 device registry with one active device (whose
  `epochKeys` entry is the only wrap present) and one revoked device pinned
  at its pre-rotation certificate epoch, and exactly one cached epoch key
  file (`documents/sync/identity/epochs/2.key.enc` — nothing cached for the
  revoked device's inaccessible epoch).
- **`test/fixtures/kv-envelope-v0/`** — a pre-versioning (`encryptedEnvelope`
  version 0) `*.kv.enc` file: no `version`, `cipher`, or `kdf` fields, no AAD.

`test/format-conformance.test.mjs` is the executable form of this document: it
asserts `VAULT_FORMAT_VERSION === "1.0"`, that every `AAD` value is unique and
carries the `secondbrain-vault:` prefix, that `FORMAT_COMPATIBILITY` reads
every version it writes, and that both fixture vaults above open to the
expected plaintext and shape. Any change that breaks that test has broken
this specification and requires either a fix or, if the change is
intentional, the format 2.0 migration path described in Section 2.
