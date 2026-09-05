# Security Policy

## Supported versions

The on-disk format is frozen at 1.0 — see [`docs/FORMAT-1.0.md`](docs/FORMAT-1.0.md).
The product itself remains pre-1.0. Security fixes are applied to the latest
release only.

Until the independent review described in
[`docs/AUDIT-SCOPE.md`](docs/AUDIT-SCOPE.md) is complete, releases are not
presented as suitable for real medical, financial, or identity data.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
security-advisory flow for this repository and include reproduction steps,
affected versions, impact, and any suggested mitigation.

See "Supported versions" above for the current release-readiness gate.

## Windows release signing

Stable `v1.*` release tags fail closed unless the repository has both
`WINDOWS_CERTIFICATE` (a base64-encoded Authenticode PFX) and
`WINDOWS_CERTIFICATE_PASSWORD` secrets. The release workflow signs every MSI
and NSIS executable with SHA-256, obtains an RFC 3161 timestamp, verifies the
signature, and only then produces checksums, SBOM and provenance. Pre-1.0
artifacts without these secrets must be described as unsigned test builds.

## What the grant layer does and does not claim

Per-agent grants and redaction narrow how much an agent is handed. They are not
a boundary against a model:

- A redacted value still enters the calling model's context as a redacted value.
- The MCP agent name is a label the process is started with (`vbrain mcp --agent
  <name>`), not a credential; anything able to start the MCP server can pass any
  name and inherit that name's grants.
- The security boundary is the passphrase and the encrypted files. `vbrain get`
  (Mode 1) remains the only path that involves no model at all.

Report a grant that can be bypassed *without* the passphrase — for example a
scope that leaks a value it should mask — through the flow above.

## Keyring and recovery limits

- Without a recovery kit, a vault keeps its only wrapped data-key copies in
  `keyring.json`; the correct primary passphrase alone cannot reconstruct a
  lost or corrupted keyring. `vbrain keyring recovery create` writes an
  independently usable wrapped copy outside the vault. Store its 256-bit code
  separately: possession of both kit and code is equivalent to vault access.
- Removing a recovery slot does not erase offline kit copies. A suspected kit
  disclosure requires removing the slot, re-keying the content and creating a
  new kit. Permanent attachment-ID, sync-change-ID and audit keys deliberately
  survive re-key, so an old kit still exposes those stable identities and can
  open ciphertext backups made before the re-key.

- Changing the passphrase does not re-encrypt content. It replaces the wrapping
  around the vault's keys, nothing more. Anyone who already knew the old
  passphrase and holds a copy of the vault reads what that copy contains, before
  and after. `vbrain rekey` is the answer to a leaked passphrase: it replaces
  the keys and re-encrypts every object under them.
- A re-key does not retract what a leaked passphrase already exposed. An
  attacker who held the passphrase and a copy of the vault has already read
  what that copy contained. `vbrain rekey` is forward-looking: afterwards no
  byte on disk opens under the old passphrase or the old keys.
- A re-key keeps exactly one keyring slot: the one wrapping the passphrase it
  was given. Every other slot is dropped, deliberately — a slot this passphrase
  cannot open is wrapped around the keyset the re-key supersedes, so preserving
  it would keep the leaked passphrase's keys reachable. A vault carrying a
  recovery slot or a second person's slot loses it, and the run reports each
  one it dropped. Re-add them after the re-key.
- A re-key pins the two keys that derive identities, `attachmentId` and
  `syncChange`. Someone who kept the old keyset can therefore still confirm
  that a guessed file or a guessed sync change is present, from directory
  names alone, without decrypting anything. They cannot read its contents.

## Disclosure

Maintainers will acknowledge a complete report, reproduce it privately, prepare
a fix and regression test, then coordinate disclosure with the reporter. Secrets,
decrypted vault contents, passphrases, or real personal data must never be attached
to a report.
