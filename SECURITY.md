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

## Release and updater signing

The zero-cost release channel does not use an Authenticode certificate or an
Apple Developer ID. Windows SmartScreen and macOS Gatekeeper can therefore warn
on a first install even when the downloaded bytes match the published checksum.
Those operating-system publisher warnings must not be described as bypassed.

The in-app updater has a separate, mandatory Tauri signature. Its public key and
fixed HTTPS GitHub Releases feed are embedded at build time; the webview cannot
replace either one or supply an installer path. A release build fails closed
when the public key or private signing secret is missing. Keep an offline backup
of the updater private key: losing it can make a manual reinstall necessary for
existing installations.
The vault recovery kit is unrelated to this release key and cannot restore it.

Updates are never checked, downloaded, or installed automatically. Before a
verified package is installed, the desktop app saves pending note and canvas
edits and locks the vault. Any save, download, signature, or install failure
stops the operation without disabling ordinary offline use. The updater has no
automatic rollback; release acceptance therefore includes a real two-version
installation drill on every supported platform.

## What the grant layer does and does not claim

Per-agent grants and redaction narrow how much an agent is handed. They are not
a boundary against a model:

- A redacted value still enters the calling model's context as a redacted value.
- The MCP agent name is a label the process is started with (`vbrain mcp --agent
  <name>`), not a credential; anything able to start the MCP server can pass any
  name and inherit that name's grants.
- The security boundary is the passphrase and the encrypted files. `vbrain get`
  (Mode 1) remains the only path that involves no model at all.

Report a grant that can be bypassed _without_ the passphrase — for example a
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
- A re-key installs a fresh primary slot and, when supplied with its matching
  kit and code, a rewritten recovery slot. Other slots are dropped and reported.
  A recovery slot requires the matching kit and code before mutation begins.
  If the kit rewrite succeeds but the vault commit fails, the rewritten kit no
  longer matches the vault; the command reports how to replace it using the
  still-working current passphrase.
- A re-key pins the two keys that derive identities, `attachmentId` and
  `syncChange`. Someone who kept the old keyset can therefore still confirm
  that a guessed file or a guessed sync change is present, from directory
  names alone, without decrypting anything. They cannot read its contents.

## Accepted re-key limitations

- Re-key audit entries share an operation ID and the unchanged audit signing
  key: `pending` precedes mutation and `allowed` follows successful completion.
  Safely refused operations can end in `denied`. A crash or an uncertain
  post-commit failure can leave `pending` without a terminal entry. Re-running
  `vbrain rekey` to settle a journal is passphrase-free and cannot sign another
  event. Audit-write failures are errors, not a successful audit guarantee.
- Recovery verification tries a kit's current keys first and its retiring keys
  only after authentication fails. Malformed payloads remain errors. This
  supports kits that actually carry both generations, not an arbitrary stale
  kit. Audit verification never falls back because its key is not rotated.

- Recovery uses the staging journal's slot ID to distinguish commit from rollback.
  An actor with vault write access can alter it and steer that decision. The
  journal is not an authenticated instruction source against a hostile writer.
- Staged-path containment is lexical; completeness checks do not establish that
  every staged path is free of symlinks. Keep the vault and staging directory
  inaccessible to other writers during re-key.
- `allowSamePassphrase` and `--keep-passphrase` can leave the same passphrase in
  force while reporting `passphraseChanged` differently. This flag is a report
  of the selected mode, not proof that a compromised passphrase was revoked.
- When multiple slots open under the supplied passphrase, re-key uses the first
  keyset; it does not compare every opened keyset for equality. Corrupt or
  inconsistent slots must not be treated as an independently verified backup.

## Disclosure process

Maintainers will acknowledge a complete report, reproduce it privately, prepare
a fix and regression test, then coordinate disclosure with the reporter. Secrets,
decrypted vault contents, passphrases, or real personal data must never be attached
to a report.
