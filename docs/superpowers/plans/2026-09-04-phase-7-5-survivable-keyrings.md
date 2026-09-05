# Phase 7.5 Survivable Keyrings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add inspectable, recoverable and audited keyring lifecycle operations.

**Architecture:** Keep recovery as a compatible passphrase slot, copy it to an
external kit, verify recovered keys against encrypted vault material, and use
the permanent audit key for paired keyring-operation events. Phase 7.4 consumes
the focused recovery-rekey adapter rather than duplicating kit rules.

**Tech Stack:** TypeScript, Node.js crypto/fs, Commander, Node test runner, Rust.

**Spec:** `docs/superpowers/specs/2026-09-04-phase-7-5-survivable-keyrings-design.md`

## Global Constraints

- Recovery code is 32 random bytes and is never persisted.
- Recovery kit must be outside the selected vault and must not overwrite an existing file.
- Keyring and keyset versions remain unchanged.
- Old audit entries and both cores remain compatible.
- All production changes follow failing-test-first development.

---

### Task 1: Recovery and status primitives

- [ ] Add failing tests for code validation, slot parity, redacted status and wrong-vault restore.
- [ ] Implement focused status, kit parsing, ciphertext verification and recovery lifecycle modules.
- [ ] Run the keyring recovery tests and commit the green slice.

### Task 2: CLI and cross-core compatibility

- [ ] Add failing CLI tests for passwordless JSON status and keychain-independent recovery commands.
- [ ] Add the nested `keyring status` and `keyring recovery` Commander commands.
- [ ] Prove Rust opens a recovery-labelled passphrase slot and run both core suites.

### Task 3: Key-material audit

- [ ] Add failing tests for paired, secret-free migration, passphrase and recovery events.
- [ ] Add explicit-key audit append support and operation helpers.
- [ ] Integrate events at each mutation boundary and verify the historical chain.

### Task 4: Phase 7.4 integration

- [ ] Verify the merged 7.4 public types and fault boundaries.
- [ ] Pass recovery kit/code through `RekeyOptions` and journal state.
- [ ] Rewrite the kit before v2 installation and final v1 installation, with fault-injection coverage.
- [ ] Add the paired `rekey` audit event and run resume/idempotency tests.

### Task 5: Documentation and release gates

- [ ] Update README, security limits, architecture, roadmap and changelog.
- [ ] Run TypeScript, desktop and Rust quality gates plus package and 100k benchmark checks.
- [ ] Update graphify output after the final source merge.
