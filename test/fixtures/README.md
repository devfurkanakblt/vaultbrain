# Format fixtures

Checked-in vaults written by earlier releases. Vault Brain is the product name,
but these fixtures retain immutable pre-rename storage and cryptographic
identifiers so tests prove upgrades do not orphan existing data.

**Passphrase for every fixture here: `fixture-only-passphrase`.**

They contain dummy data only. Never point a fixture at a real vault.

| Directory | Format | What it pins |
|---|---|---|
| `kv-envelope-v0/` | key-value envelope, pre-versioning | Unversioned `{salt,iv,authTag,ciphertext}` files still decrypt, and `vbrain migrate` upgrades them in place |
| `documents-v1/` | document vault manifest v1, index v2 | An encrypted note vault written by the current format still opens, searches and resolves links |
| `documents-attachments-v1/` | document vault with chunk-encrypted attachments | Content-addressed attachments written by the TypeScript core still open in the Rust desktop core |
| `documents-canvas-v1/` | document vault with encrypted canvas objects | Canvas objects, identities, references and AAD written by the TypeScript core stay readable |
| `sync-epoch-v2/` | sync registry v2, change envelopes v1 and v2 | A rotated vault still opens: epoch 1 changes stay vault-key sealed, epoch 2 changes need the wrapped content key, and the revoked device holds no wrap |
| `sync-attachment-blobs-v3/` | sync change body v3, attachment blob manifest | An attachment change that carries `size`/`chunks`/`blobs[]` instead of base64 bytes still opens; `source/` stages the two sealed chunks, `target/` is the same vault before the attachment and reassembles it from them. `manifest.json` records the blob ids and the plaintext SHA-256 |

Regenerate deliberately (see `scripts/make-fixtures.mjs`) — overwriting a
fixture throws away the evidence it was there to provide. To cover a new
format version, add a new directory instead of editing an old one.

`keyring-vector.json` is written by `scripts/make-keyring-vector.mjs` and
refuses to overwrite itself without `--force`. Its passphrase is
`vector-only-passphrase`, not the shared fixture passphrase, because it is a
format vector rather than a vault.

`keyring-legacy-vector.json` is written by
`scripts/make-keyring-legacy-vector.mjs` and pins the other shape a version 1
keyset can take: one carrying `legacyChangeIdentity`, the `documents` key a
completed re-key replaced. Both cores must unwrap it to the same keys and
re-serialize it to the same bytes. The Rust core used to parse this shape
successfully and then drop the field on the next re-wrap, which is what the
vector exists to prevent recurring.
