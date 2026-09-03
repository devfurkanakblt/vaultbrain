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
| `keyring-v2/` | vault keyring v2, keyset v1, key-value envelope v2 | A migrated vault opens through its wrapped keyset, its key-value files use the keyed envelope, and its adopted audit chain still verifies |
| `keyring-vector.json` | keyring slot v2, keyset v1, deterministic | Both cores unwrap one fixed slot to the same six keys and serialize that keyset to the same plaintext bytes, so the Rust and TypeScript implementations of the format cannot drift |

Regenerate deliberately (see `scripts/make-fixtures.mjs`) — overwriting a
fixture throws away the evidence it was there to provide. To cover a new
format version, add a new directory instead of editing an old one.

`keyring-vector.json` is written by `scripts/make-keyring-vector.mjs` and
refuses to overwrite itself without `--force`. Its passphrase is
`vector-only-passphrase`, not the shared fixture passphrase, because it is a
format vector rather than a vault.
