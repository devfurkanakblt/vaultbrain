# Phase 7.5 Survivable Keyrings Design

## Goal

Prevent a forgotten primary passphrase or a damaged `keyring.json` from being
the permanent loss of a vault, make slot metadata visible, and record keyring
mutations in the existing authenticated audit chain.

## Recovery model

The keyring format stays at version 2 and recovery remains an ordinary
`type: "passphrase"` slot labelled `recovery`. This preserves compatibility
with both existing cores. Its passphrase is a checksummed, versioned 256-bit
random code. An external version-1 recovery kit contains only the complete
wrapped slot and creation timestamp; the code is shown once and is never
persisted by Vault Brain.

Kit creation requires the current primary passphrase and writes the kit outside
the vault before appending the slot to `keyring.json`. Restore opens the kit,
checks available encrypted index, KV, grants, sync and audit material with the
recovered keyset, backs up an existing keyring, and installs a new primary slot
beside the recovery slot. Wrong code, kit or ciphertext fails before replacement.

Removing a live recovery slot does not revoke an offline kit. Content keys must
be re-keyed before a replacement kit is created when the old kit may be exposed.

## Status and audit

`vbrain keyring status [--json]` is intentionally passwordless because every
reported field is already plaintext in `keyring.json`. It omits salts and all
wrapped fields and classifies each scrypt cost relative to the current default.

Key-material changes use `actor=cli-keyring`, `file=keyring`, a random operation
ID in `key`, and the existing signed `outcome` field. A pending record is written
before mutation and an allowed or denied record follows. No secret, external
path, ciphertext or object identity is recorded. The schema therefore remains
verifiable by older audit readers.

## Rekey boundary

Phase 7.5 exports a recovery adapter for Phase 7.4. A re-key with a recovery
slot must receive the matching kit and code. The adapter authenticates the kit
against the live slot and atomically rewrites it with the new keyset while
preserving slot ID, creation time and KDF cost. The Phase 7.4 coordinator calls
this at its temporary-v2 and final-v1 keyset transitions.

