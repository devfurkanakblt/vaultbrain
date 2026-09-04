# Vault Brain Security Policy

Vault Brain stores encrypted notes, canvases, attachments, plugin packages and
derived indexes locally, and exposes deliberately narrow CLI, desktop, plugin
and MCP surfaces. Security reports are welcome and should be handled privately.

## Supported versions

Vault Brain is pre-1.0. Security fixes are made on the default branch and the
latest published release only; older releases do not receive backports.

| Version        | Supported             |
| -------------- | --------------------- |
| Latest release | Yes                   |
| Default branch | Yes, for verification |
| Older releases | No                    |

The project has not completed an independent security review. Until the review
gate in [`docs/PRODUCT.md`](docs/PRODUCT.md) is complete, releases must not be
presented as suitable for real medical, financial or identity data.

## Reporting a vulnerability

Do not open a public issue, discussion or pull request for a suspected
vulnerability. Submit a private report through the repository's
[GitHub Security Advisories](https://github.com/devfurkanakblt/vaultbrain/security/advisories/new).

Include as much of the following as possible:

## Windows release signing

Stable `v1.*` release tags fail closed unless the repository has both
`WINDOWS_CERTIFICATE` (a base64-encoded Authenticode PFX) and
`WINDOWS_CERTIFICATE_PASSWORD` secrets. The release workflow signs every MSI
and NSIS executable with SHA-256, obtains an RFC 3161 timestamp, verifies the
signature, and only then produces checksums, SBOM and provenance. Pre-1.0
artifacts without these secrets must be described as unsigned test builds.

## What the grant layer does and does not claim

Please do not test against another person's data or systems, perform denial of
service, publish exploit details before coordination, or attach passphrases,
decrypted vault contents, credential-store exports or real personal data.

## Security model

Vault Brain's primary boundary is encryption at rest. A memory-hard KDF derives
key material from the passphrase; authenticated encryption binds ciphertext to
its format and logical identity. The desktop webview does not receive the vault
master key or unrestricted filesystem access. Crash-safe writes, encrypted
history and authenticated sync records protect integrity and recovery.

Reports are especially valuable when they demonstrate any of the following
without already possessing the required secret or capability:

- plaintext note, attachment, index, workspace or plugin data remaining on disk
  after lock;
- passphrase or derived-key exposure across the webview/privileged-core boundary;
- path traversal, symlink escape or writes outside the selected vault;
- ciphertext accepted under the wrong object type, ID, revision or sync context;
- grant/redaction bypass that reveals more content than the evaluated policy;
- a plugin reaching an undeclared host or Rust capability, escaping the worker
  boundary, or bypassing signature/revocation policy;
- audit-chain, sync-chain, replay, fork-detection or crash-recovery failure that
  permits silent tampering or data loss;
- session operations succeeding after lock or key zeroization.

## Important limitations

Encryption at rest does not protect plaintext after an authorized operation
decrypts it. An unlocked process, terminal output, clipboard, export destination
or calling AI model may hold that plaintext.

- `vbrain get` is the direct, no-model path. MCP content operations necessarily
  place the returned or submitted content in the calling model's context.
- Grants and redaction minimize exposure; they are not model authentication.
  `VBRAIN_AGENT` is selected by whoever starts the MCP server and is not a
  credential.
- `VBRAIN_PASSPHRASE` is useful for automation but may be visible to processes
  running as the same OS user. The OS credential store is preferable for
  interactive use, but it also cannot defend against code already running as
  that user.
- Plugin signatures provide package integrity and signer continuity, not proof
  of a publisher's real-world identity. A granted capability may be used fully
  by the plugin that receives it.
- Vault encryption does not defend against a compromised operating system,
  keylogger, malicious code running as the user, screen capture, destructive
  filesystem access or loss of all backups.
- Upgrading a vault to the keyring format does not strengthen copies that
  already exist. A backup taken before `vbrain migrate` keeps the older
  key-derivation cost and still opens with the passphrase it was written under.
- Changing the passphrase does not re-encrypt content. It replaces the wrapping
  around the vault's keys, nothing more. Anyone who already knew the old
  passphrase and holds a copy of the vault reads what that copy contains, before
  and after. `vbrain rekey` will be the answer to a leaked passphrase once it
  ships; it has not shipped yet.

  A vault created before the default key-derivation cost rose keeps its old cost
  until its passphrase is changed once. `vbrain passphrase change` writes every
  slot at the current default, so one run raises the work factor without touching
  a single note.
- Every vault, newly created or migrated, keeps its data keys only inside
  `keyring.json`: it wraps the keys that decrypt everything, and the correct
  passphrase alone cannot recover a vault whose keyring is lost or corrupted.
  A backup that omits `keyring.json` is not a backup. Migration additionally
  removes the legacy manifest's key-check material, so a migrated vault has no
  fallback path at all once its keyring is gone.
- Key names and descriptions exported to `schema.json`, plus explicitly
  plaintext recovery metadata documented in the architecture, must be treated
  as non-secret metadata.

A report about one of these documented limitations is still useful if it shows
that Vault Brain behaves more broadly than documented or crosses an additional
boundary.

## Disclosure process

Maintainers will acknowledge a complete report, reproduce it privately, assess
severity and affected versions, and prepare a fix with a regression test.
Disclosure and release timing will be coordinated with the reporter. Credit is
given when requested, unless the reporter prefers to remain anonymous.

Security fixes must not silently break existing encrypted vaults. When a format
or protocol change is necessary, the fix must include versioning, compatibility
or an explicit migration and recovery path.
