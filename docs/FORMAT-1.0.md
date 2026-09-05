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
- `src/keyring.ts` — the vault keyring: the wrapped keyset every other key
  comes from, its slot format and its scrypt bounds.
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

**Two carve-outs, stated rather than assumed.** `documentManifest` version 2 is
in this format at 1.0, even though the policy above reserves artifact version
bumps for 2.0. It is not a second generation of the manifest: a version 2
manifest is a *tombstone* — the two fields `{"version": 2, "keyring": true}`
and nothing else — carrying no KDF, no salt and no verifier. It exists so that a
build predating the keyring refuses a keyring vault instead of mistaking it
for an empty legacy one and writing notes under a key of its own. The rule the
2.0 requirement protects — that a 1.x change must never make an existing vault
silently misread — is what the tombstone enforces rather than breaks: an older
build fails closed on it, a version 1 manifest is still read exactly as before,
and `vbrain migrate` is the migration path between them. A future artifact
version that carried real data under a bumped number would still be a 2.0
event.

The second is `vaultKeyset` version 2, and it holds for the same reason. It is
not a second generation of the keyset but a *transient* one: it exists only
between the first and last object a `vbrain rekey` rewrites, and the operation
drops it again on completion. Every build that predates it — including the Rust
core until it is taught the field — rejects an unrecognized keyset version and
refuses the vault, which is exactly the required behaviour: a vault caught
mid-re-key must not be opened by a reader that would report success and then
fail to decrypt every object the interrupted run had not reached. `vbrain rekey
--resume` is the migration path out of it.

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

A vault written by this build derives **one** key from the passphrase: the
keyring slot key, which unwraps the keyset every other key is read from
(Section 5, `vaultKeyring`). The two call sites below are what a reader must
still accept, because a vault created before the keyring existed derives its
keys directly and is never rewritten by being opened.

So there are three scrypt call sites in total, with different accepted ranges.
All use `crypto.scryptSync` with a 32-byte output (`KEY_LEN` / `KEY_LENGTH`).
The keyring uses `maxmem: 256 * 1024 * 1024`; the two legacy sites use
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

**Keyring slot** (`src/keyring.ts`, `keyring.json`). The current path, and the
only one a new vault takes. This build writes `N = 2^17` (`DEFAULT_SCRYPT_N`),
`r = 8`, `p = 1`, and accepts, per slot, the same range as the key-value
envelope: `N` a power of two with `2^14 <= N <= 2^20`, `r` in `1..32`, `p` in
`1..16`, `salt` 16 to 64 decoded bytes (`validateKdf`). Unlike the two sites
below, the parameters are per-vault data rather than a constant compiled into
the build, which is what lets `vbrain passphrase change` raise the cost of an
existing vault. The memory ceiling is deliberately *not* derived from the
declared parameters — `N = 2^20` with `r = 32` is individually in range and
jointly implies a multi-gigabyte allocation, so a fixed ceiling makes an
out-of-policy cost fail fast instead of letting the file dictate its own
budget.

**Document vault manifest** (`src/document-crypto.ts`, `documents/manifest.json`).
The legacy path: read for a vault created before the keyring, never taken by a
vault that has one.
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

### `vaultKeyring` — `keyring.json`

`reads: [2]`, `writes: [2]`. Defined in `src/keyring.ts`. The root of the key
hierarchy and the first file a reader opens: a plaintext JSON envelope holding
one or more slots, each an AES-256-GCM wrap of the same keyset under a key
scrypt-derived from one passphrase.

```ts
interface KeyringFile {
  version: 2;              // KEYRING_VERSION
  slots: KeyringSlot[];
}

interface KeyringSlot {
  id: string;              // 36 chars matching /^[0-9a-f-]{36}$/
  type: "passphrase";      // the only type this build accepts
  label: string;           // <= 64 chars; "primary" for the slot a vault is created with
  kdf: { name: "scrypt"; N: number; r: number; p: number; salt: string };
  createdAt: string;       // any Date.parse-able timestamp
  wrapped: { iv: string; authTag: string; ciphertext: string };
}
```

`iv` is exactly 12 decoded bytes, `authTag` exactly 16, and `ciphertext` 16 to
4096 (`validateSlot`). The KDF bounds are in Section 4.

The associated data binds each slot's identity and declared cost to its
ciphertext, so a header cannot be weakened and one slot's ciphertext cannot be
moved under another slot's identity without the tag check failing:

```ts
// src/keyring.ts — slotAad
Buffer.from(JSON.stringify({
  context: AAD.keyringSlot,   // "secondbrain-vault:keyring-slot:v1"
  version: KEYRING_VERSION,   // 2
  id: slot.id,
  type: slot.type,
  kdf: { name, N, r, p, salt },
}), "utf8")
```

The plaintext inside the wrap is the keyset, and the order of `KEY_NAMES` is
part of the format:

```ts
{ version: 1, keys: { documents, kv, attachmentId, syncChange, syncEnvelope, audit } }
```

Each value is 32 decoded bytes. `version` here is the *keyset* version
(`KEYSET_VERSION`), nested inside the wrap and independent of the file's
`version`. Because these keys are random and wrapped rather than derived,
changing the passphrase re-wraps one slot and rewrites nothing else — which is
what keeps attachment content ids and sync change ids, both keyed HMACs and
both permanent identities, byte-identical across a passphrase change.

While a re-key is in flight the keyset carries the outgoing rotatable keys
alongside the new ones and is written as version 2
(`RETIRING_KEYSET_VERSION`):

```ts
{
  version: 2,
  keys: { documents, kv, attachmentId, syncChange, syncEnvelope, audit },
  retiring: { documents, kv, syncEnvelope },
}
```

A keyset may also carry `legacyChangeIdentity`, an optional 32-byte key at
either version. It holds the `documents` key a completed re-key replaced, and
it exists for one purpose: recomputing the ids of sync changes an older build
derived from that key, so a re-key can move their bodies to the new envelope
key without renaming them. It decrypts nothing, and it grants nobody anything
an owner of the superseded passphrase did not already hold. It is absent on a
vault that has never been re-keyed.

`retiring` holds exactly `ROTATABLE_KEY_NAMES` — the three keys `vbrain rekey`
replaces — and nothing else. `attachmentId`, `syncChange` and `audit` never
appear there because they are never rotated: every content address, change id
and audit link already in the vault is computed under them. A reader tries the
key in force and falls back to the retiring one only on an authentication
failure, which is safe because each object's AAD already binds its identity, so
a fallback cannot succeed against the wrong object. When the last object has
been rewritten the field is dropped and the keyset returns to version 1. A
version 1 keyset carrying a `retiring` field is refused rather than ignored.

A vault created before the keyring has no `keyring.json` at all; see
`documentManifest` below and Section 4.

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

`reads: [1, 2]`, `writes: [1, 2]`. Defined in `src/document-crypto.ts`, with
version 2 written by `src/keyring.ts`. Not AEAD data.

Version 1 is a plaintext JSON file recording the KDF parameters and an HMAC
verifier used to confirm a passphrase before deriving the document-vault
master key:

```ts
interface DocumentManifest {
  version: 1;
  kdf: { name: "scrypt"; N: number; salt: string };
  verifier: string; // lowercase hex, 64 chars (HMAC-SHA256)
}
```

Version 2 is the keyring tombstone, and is byte-identical whether the vault
was created keyring-native or upgraded by `vbrain migrate`
(`manifestTombstone()` is its single definition):

```json
{
  "version": 2,
  "keyring": true
}
```

It carries no key material. A keyring vault never consults it to unlock —
`openDocumentKey` returns from the keyring before reading it — and the one
time it is read is to turn a missing or unreadable `keyring.json` into "this
vault was upgraded to a keyring, but keyring.json is missing or unreadable"
rather than a confusing manifest error. Its real audience is a build from
before the keyring, which refuses any manifest whose version is not 1 and so
fails closed instead of treating a keyring vault as an empty legacy one. See
the carve-out in Section 2.

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

**Attachment `<id>` derivation.** Unlike note/canvas/plugin ids, which the
caller supplies, an attachment's `id` is content-addressed: computed from the
attachment's plaintext bytes, keyed by the vault's dedicated attachment-id
key, using a dedicated AAD constant distinct from `attachmentManifestAad`/
`attachmentChunkAad` above:

```ts
// src/format-version.ts
attachmentId: "secondbrain-vault:attachment-id:v1\0",
```

Note the trailing NUL (`\0`) — it is part of the constant, not a formatting
artifact of this document. The id is an HMAC-SHA256, keyed by the
attachment-id key, over that constant followed by the raw attachment bytes,
in this exact order (`putAttachment` in `src/documents.ts`):

```ts
// src/documents.ts:2188-2192
const id = crypto
  .createHmac("sha256", this.session.attachmentIdKey)
  .update(AAD.attachmentId, "utf8")
  .update(data)
  .digest("hex");
```

i.e. `id = HMAC-SHA256(attachmentIdKey, AAD.attachmentId || data)`,
hex-encoded.

**The key is not the document key.** `attachmentIdKey` is a separate,
never-rotated entry in the vault keyring (`attachmentId` in `KEY_NAMES`,
`src/keyring.ts`), surfaced as `session.attachmentIdKey` by
`src/document-crypto.ts`. It equals the document key *only* on legacy
manifest vaults, where every subkey comes from the same derivation; on
keyring vaults the two are independent. An implementation that keys this
HMAC with the document key therefore agrees on legacy vaults and computes
different ids for the same bytes on every keyring vault — a divergence that
would appear only on newer vaults and only for attachments. Both
implementations in this repository key it correctly: the Rust core computes
`attachment_id(session.attachment_id_key, data)` (`src-tauri/src/lib.rs`).
Because this construction is keyed (not a bare content hash), two vaults with
different attachment-id keys assign different ids to identical bytes, and an
attacker without that key cannot forge or predict an id. This is also
how attachment deduplication works: re-adding bytes that hash to an id whose
manifest already exists on disk is a no-op (`putAttachment` checks
`fs.existsSync` on that id's manifest path before writing anything).

The exact same HMAC is recomputed on every read as an integrity check,
independent of the AES-GCM authentication already performed on each chunk and
the manifest (`getAttachment` in `src/documents.ts`):

```ts
// src/documents.ts:2231-2236
const actualId = crypto
  .createHmac("sha256", this.session.attachmentIdKey)
  .update(AAD.attachmentId, "utf8")
  .update(data)
  .digest("hex");
if (data.length !== info.size || actualId !== id) throw new Error("Attachment integrity check failed.");
```

A third-party implementation that derives attachment ids by a different
construction (a bare `SHA-256(data)`, a different AAD string, arguments in a
different order, a missing trailing NUL, or the document key in place of the
attachment-id key) will compute different ids for
the same bytes and produce a vault this build cannot open, and this build's
attachments will fail this same check in the other direction.

Two further single-purpose files also use this `DocumentPayload` shape under
a fixed (non-id-keyed) AAD, but live outside `documents/objects/` and are not
separate entries in `FORMAT_COMPATIBILITY`: the document index
(`AAD.documentIndex = "secondbrain-vault:document-index:v1"`) and the plugin
security policy (`AAD.pluginPolicy = "secondbrain-vault:plugin-policy:v1"`),
both in `src/documents.ts`. They are out of scope for this specification's
version guarantees.

### `syncChangeEnvelope` — `documents/sync/changes/*.change.enc`

`reads: [1, 2, 3]`, `writes: [1, 2, 3]`. Defined in `src/sync.ts`. This
entry covers two nested version numbers that are **not** the same number:
the envelope's own `version`, which is still only `1` or `2` and selects the
epoch sealing rule below, and the `version` of the `SyncChangeBody` sealed
inside it, which is where `3` appears.

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
  version: 1 | 2 | 3; // 1 = unsigned legacy; 2 and 3 = device-authorized
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
  authorization?: { certificateSerial: number; signature: string }; // versions 2 and 3
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

A **version 3** body is validated, signed and verified exactly as a version 2
body is: `authorization` is required, and the `version` inside the signed
bytes is the body's own, so relabelling a body between 2 and 3 invalidates its
signature. The body version is covered a second time by the change `id`, an
HMAC over the whole canonical body under a key the relay does not hold, so a
transport cannot flip it undetected either way. Version 3 names the
generation of the format in which an attachment change carries a *blob
manifest* instead of base64 bytes.

> **Compatibility.** `changeAuthorizationPayload` once pinned a literal
> `version: 2` for every authorized body, which left a 2/3 relabelling
> signature-valid and rested that guarantee on the change `id` alone. Version 2
> signatures are unaffected by the correction -- their payload already carried a
> 2 -- but any version 3 body signed under the old rule no longer verifies.
> Version 3 was never released, so the only artefact affected was this
> repository's own fixture.

> **How a writer chooses a version.** An enrolled device stamps `3` on an
> attachment change carrying a blob manifest and `2` on every other
> authorized change; a vault with no device registry stamps `1` either way,
> because version 3 requires `authorization` and an un-enrolled vault cannot
> produce one (`changeBodyVersion`, `src/sync.ts`). Validation enforces the
> pairing in both directions: a version 3 body must carry a blob manifest,
> and a version 2 body may not. *Reading* still branches on shape —
> `parseAttachmentSnapshot` takes the blob branch whenever
> `size`/`chunks`/`blobs` are present and the inline branch whenever `data`
> is — so a version 1 body carrying a manifest is read as one. A third-party
> implementation must read all three versions and may write any of them.

#### Attachment snapshots: inline bytes and blob manifests

An attachment change's `mutation.value` has two accepted shapes
(`parseAttachmentSnapshot`, `src/sync.ts`):

```ts
// Legacy: read at every version, written by none. The writer always
// produces the manifest form below, whatever the attachment size.
interface InlineAttachmentSyncSnapshot {
  filename: string;
  mime: string;
  data: string; // canonical base64 of the whole plaintext
}

// The blob manifest form. The bytes are not in the change.
interface BlobAttachmentSyncSnapshot {
  filename: string;
  mime: string;
  size: number;    // safe integer, 1 <= size <= 250 MiB (MAX_ATTACHMENT_SIZE)
  chunks: number;  // safe integer >= 1
  blobs: string[]; // one blob id per chunk, in chunk order
}
```

The rules, all enforced before any byte is transferred:

- Exactly one of `data` or the `size`/`chunks`/`blobs` trio. A snapshot
  carrying both forms, or neither, is refused. The pairing with the body
  version is deliberately asymmetric: a version 2 body carrying `blobs` is
  refused, while a version 1 body carrying `blobs` is read as a blob
  manifest, because an un-enrolled vault has no version 3 available to it.
- `blobs` holds at most **256** entries (`MAX_ATTACHMENT_BLOBS`, matching the
  `parents` cap). This bound is checked first, so hostile input cannot force
  an unbounded scan. 250 MiB at 1 MiB per chunk is 250 entries, so the cap is
  not reachable by a legal attachment.
- Every blob id is exactly 64 lowercase hexadecimal characters.
- `chunks === blobs.length === Math.ceil(size / ATTACHMENT_CHUNK_SIZE)`, with
  `ATTACHMENT_CHUNK_SIZE` = 1 MiB. `size` is at least 1 because an empty
  attachment is refused at `prepareAttachmentPut`, so `chunks` is at least 1.

**Blob sealing key.** A blob is sealed under a key derived from the permanent
`syncChange` key, `HMAC-SHA256(syncChange, "secondbrain-vault:sync-blob-key:v1")`,
not under the rotatable `documents` key. A blob id is the SHA-256 of the sealed
bytes and the nonce is random, so a blob can never be reproduced under its own
id: the staged bytes are the only copy that satisfies the manifest inside the
version 3 change body that names them. Deriving from a key `vbrain rekey` never
rotates is what keeps that manifest valid for the life of the vault. A reader
also accepts the `documents` key, which is what a blob staged before this
derivation existed was sealed under.

**Blob identity.** A blob is one plaintext 1 MiB chunk sealed as a
`DocumentPayload` under the vault's document key with AAD
`attachmentChunkAad(attachmentId, index)` — the same key, the same AAD
builder and the same chunk size the on-disk chunk file uses. No new AAD
string was introduced. It is a *fresh* seal, not a copy of
`documents/attachments/<id>/<index>.chunk.enc`: AEAD nonces are random per
seal, so the two ciphertexts differ even though they carry the same chunk.

The blob id is the lowercase hex `SHA-256` of the exact sealed bytes
transferred — the JSON-encoded `DocumentPayload`, unkeyed:

```ts
blobId = crypto.createHash("sha256").update(sealedChunkJsonBytes).digest("hex");
```

It is deliberately **not** keyed, unlike `syncChangeId`. Because nonces are
random, two devices sealing the same chunk produce different ciphertext; a
keyed id would make those different bytes claim one id and collide in an
immutable content-addressed store — a correctness failure, not a storage
inefficiency. Hashing the ciphertext instead keeps the transport opaque (the
input is AEAD output), lets a relay verify an upload while holding no key,
and deduplicates identical uploads. The cost accepted in exchange is that two
devices that each add the same file produce two distinct blob sets.

**Plaintext integrity does not rest on the blob id.** After reassembly the
receiving device recomputes `HMAC-SHA256(attachmentIdKey, AAD.attachmentId ||
data)` and refuses anything that is not the change's `mutation.objectId`,
exactly as an ordinary local read does; and because each chunk's AAD binds
the attachment id and the chunk index, a reordered or cross-attachment chunk
fails to open at all. A transport that serves corrupted, substituted or
mismatched blobs therefore produces an attachment that is refused rather than
one that is trusted.

**Staging.** Sealed blobs awaiting transfer live at
`documents/sync/blobs/<blobId>`, one file per blob, 2 MiB maximum
(`SyncBlobStore`, `src/sync-blobs.ts`). This is a transfer staging area, not
a durable vault artifact — the durable copy of an attachment is always
`documents/attachments/<id>/` — which is why it has no `FORMAT_COMPATIBILITY`
entry of its own. The store re-verifies `SHA-256(body) === id` on every write.

**Fail-closed apply.** Applying an attachment change whose blobs have not all
arrived refuses with `"<n> of <m> attachment chunks are missing."` *before*
any apply receipt is written, so a partial attachment never reaches live
storage and no receipt is left to be rolled forward on the next unlock.

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
- **`test/fixtures/sync-attachment-blobs-v3/`** — a two-directory vault pair
  pinning the blob manifest form. `source/` is an owner-enrolled vault whose
  attachment change is a version 3 body carrying `size`, `chunks` and four
  blob ids instead of base64 bytes, with the four sealed chunks staged under
  `documents/sync/blobs/`; `target/` is the same vault copied before the
  attachment existed, so it shares the key material and the registry and can
  admit the change the way a second device would. `manifest.json` records the
  blob ids and the plaintext SHA-256 the reassembly must reproduce.
- **`test/fixtures/kv-envelope-v0/`** — a pre-versioning (`encryptedEnvelope`
  version 0) `*.kv.enc` file: no `version`, `cipher`, or `kdf` fields, no AAD.

`test/format-conformance.test.mjs` is the executable form of this document: it
asserts `VAULT_FORMAT_VERSION === "1.0"`, that every `AAD` value is unique and
carries the `secondbrain-vault:` prefix, that `FORMAT_COMPATIBILITY` reads
every version it writes, and that every fixture vault above opens to the
expected plaintext and shape. Any change that breaks that test has broken
this specification and requires either a fix or, if the change is
intentional, the format 2.0 migration path described in Section 2.
