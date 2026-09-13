# Re-key acceptance and Phase 7.7 transition matrix

This document maps the implemented re-key and recovery transitions to evidence
that must be reviewed. A source test title or passing unit test proves the
covered branch; it does not prove every transition in this matrix.

## Phase 7.7 transition matrix

| Transition | Expected behavior | Source/test evidence | Acceptance status |
| --- | --- | --- | --- |
| Complete ordinary re-key | New data keys encrypt every classified object; pinned identities remain stable | `test/rekey-vault.test.mjs` re-key and retention cases | IMPLEMENTED; manual acceptance NOT RUN |
| Re-key with `--keep-passphrase` | Data keys rotate while the current passphrase remains in force | `test/rekey-vault.test.mjs` keep-passphrase cases | IMPLEMENTED; manual acceptance NOT RUN |
| Re-key with a new passphrase | New keyset opens only with the new passphrase; remembered credential is updated or reported | `src/cli.ts` `rekey` command and re-key tests | IMPLEMENTED; manual acceptance NOT RUN |
| `documents/retention.enc` present | Retention artifact is classified and preserved through the walk | `test/rekey-vault.test.mjs` retention coverage | IMPLEMENTED; manual acceptance NOT RUN |
| Rust reads legacy identity | `legacyChangeIdentity` survives Rust parse and re-wrap | keyring legacy vector and Rust keyring tests | IMPLEMENTED; independent review NOT RUN |
| Re-key audit pending/allowed/denied | Authenticated audit events describe the outcome without secrets | `test/rekey-vault.test.mjs` audit cases | IMPLEMENTED; independent review NOT RUN |
| Interrupted re-key, journal recoverable | Rerunning `vbrain rekey` settles the journal, then a second deliberate invocation rotates | `src/cli.ts` recovery path; `rekey-transitions.test.mjs`: `every normal re-key file install interruption is recoverable and replay is idempotent` | IMPLEMENTED; manual acceptance NOT RUN |
| Interrupted re-key, malformed journal | Fail closed; preserve staging for manual evidence and report cleanup path | CLI malformed-journal handling | IMPLEMENTED; manual acceptance NOT RUN |
| Journal write boundary | A failure before the journal lands leaves the original vault untouched | `rekey-transitions.test.mjs`: `a journal write interruption leaves the original vault untouched` | TEST DEFINED; NOT RUN |
| Keyring replacement boundary | A failure at keyring replacement leaves a journal that recovery rolls back | `rekey-transitions.test.mjs`: `a journal write or keyring replacement interruption rolls back without claiming success` | TEST DEFINED; NOT RUN |
| Recovery kit during transition | Retiring and current keys are tried for artifact verification | `test/keyring-recovery.test.mjs` epoch-2 recovery coverage | IMPLEMENTED; independent review NOT RUN |
| Unsupported keyset | Refuse with the documented recovery path; do not guess or downgrade | TypeScript keyset tests and Rust fail-closed handling | IMPLEMENTED; manual acceptance NOT RUN |
| Identity rotation with backup | Verify encrypted backup first, rotate attachment/sync identities, start a new owner epoch | `vbrain rekey --rotate-identities --backup <file>` implementation/tests; `rekey-transitions.test.mjs`: `every identity-rotation file install interruption is recoverable and leaves a fresh owner` | IMPLEMENTED; manual acceptance NOT RUN |
| Identity rotation with missing/unverified backup | Refuse before the point of no return | `src/cli.ts` backup requirement and verification | IMPLEMENTED; negative manual acceptance NOT RUN |

The new regression file intentionally injects an interruption at each individual
staged-file install, for both ordinary and identity-rotation journals. Its
coverage is still a test definition until the repository test command is run;
the result remains `NOT RUN` in this closure session.

The following transitions are unmapped by the current evidence and must not be
called successful: cross-core operation on every artifact during a live
mid-re-key state; a real operator recovery from a damaged keyring; recovery-kit
restore on both current and retiring keys across all artifact families; and the
desktop UI's behavior while a re-key journal is present. Their status is
`NOT RUN` until an independent reviewer records concrete evidence.

## Operator acceptance

Run against a disposable copy. The command settles an interrupted journal
without asking for a passphrase; run it again to begin a new rotation:

```bash
vbrain --vault ./vault rekey
vbrain --vault ./vault rekey --keep-passphrase
vbrain --vault ./vault rekey --rotate-identities --backup ./verified-backup.zip
```

Use `VBRAIN_PASSPHRASE`, `VBRAIN_NEW_PASSPHRASE`, and
`VBRAIN_RECOVERY_CODE` only in a controlled process environment when automation
requires them. Never place secrets in argv, shell history, logs, or this record.

| Manual check | Result | Evidence |
| --- | --- | --- |
| Ordinary re-key opens with the selected new passphrase | NOT RUN |  |
| Retention, sync IDs, attachment IDs and audit chain remain readable | NOT RUN |  |
| Journal settlement followed by deliberate second invocation | NOT RUN |  |
| Malformed journal fails closed without touching live vault data | NOT RUN |  |
| Verified backup gates identity rotation | NOT RUN |  |
| Old peer must re-enroll after identity rotation | NOT RUN |  |
