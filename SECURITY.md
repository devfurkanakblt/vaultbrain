# Security Policy

## Supported versions

The project is pre-1.0. Security fixes are applied to the latest release only.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
security-advisory flow for this repository and include reproduction steps,
affected versions, impact, and any suggested mitigation.

Until the external review gate in `docs/PRODUCT.md` is complete, releases must
not be presented as suitable for real medical, financial, or identity data.

## What the grant layer does and does not claim

Per-agent grants and redaction narrow how much an agent is handed. They are not
a boundary against a model:

- A redacted value still enters the calling model's context as a redacted value.
- `SBRAIN_AGENT` is a name the agent chooses, not a credential; anything able to
  start the MCP server can pick any name and inherit that name's grants.
- The security boundary is the passphrase and the encrypted files. `sbrain get`
  (Mode 1) remains the only path that involves no model at all.

Report a grant that can be bypassed *without* the passphrase — for example a
scope that leaks a value it should mask — through the flow above.

## Disclosure

Maintainers will acknowledge a complete report, reproduce it privately, prepare
a fix and regression test, then coordinate disclosure with the reporter. Secrets,
decrypted vault contents, passphrases, or real personal data must never be attached
to a report.
