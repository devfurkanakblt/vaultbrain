# Format fixtures

Checked-in synthetic vaults for format-contract and compatibility tests. Tests
open them to prove that storage behavior remains intentional across changes.

**Passphrase for every fixture here: `fixture-only-passphrase`.**

They contain dummy data only. Never point a fixture at a real vault.

| Directory | Format | What it pins |
|---|---|---|
| `kv-envelope-v0/` | key-value envelope, pre-versioning | Unversioned `{salt,iv,authTag,ciphertext}` files still decrypt, and `vbrain migrate` upgrades them in place |
| `documents-v1/` | document vault manifest v1, index v2 | An encrypted note vault written by the current format still opens, searches and resolves links |
| `documents-attachments-v1/` | document vault with chunk-encrypted attachments | Content-addressed attachments written by the TypeScript core still open in the Rust desktop core |
| `documents-canvas-v1/` | document vault with encrypted canvas objects | Canvas objects, identities, references and AAD written by the TypeScript core stay readable |

Regenerate deliberately (see `scripts/make-fixtures.mjs`). After publication,
preserve released-format fixtures and add a new directory for each new format.
