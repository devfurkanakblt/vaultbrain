# Format fixtures

Checked-in vaults written by earlier releases. Tests open them to prove that a
change to the storage format did not silently orphan existing data.

**Passphrase for every fixture here: `fixture-only-passphrase`.**

They contain dummy data only. Never point a fixture at a real vault.

| Directory | Format | What it pins |
|---|---|---|
| `kv-envelope-v0/` | key-value envelope, pre-versioning | Unversioned `{salt,iv,authTag,ciphertext}` files still decrypt, and `sbrain migrate` upgrades them in place |
| `documents-v1/` | document vault manifest v1, index v2 | An encrypted note vault written by the current format still opens, searches and resolves links |

Regenerate deliberately (see `scripts/make-fixtures.mjs`) — overwriting a
fixture throws away the evidence it was there to provide. To cover a new
format version, add a new directory instead of editing an old one.
