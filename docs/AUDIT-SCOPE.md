# External security audit — scope

This document defines what an independent security engagement is being asked
to review, and states plainly what this project already knows is weak,
unfinished, or out of scope. It is written for the auditor, not as marketing.

## 1. Purpose

Vault Brain is pre-1.0 software. Per `SECURITY.md` and `docs/PRODUCT.md`, the
project does not present itself as suitable for real medical, financial, or
identity data until an independent review of the design and implementation
below is complete. This document is the scope package for that review — the
gate it exists to satisfy is exactly that presentation decision, and nothing
else. Passing this review does not make the software "secure" in any absolute
sense; it is the condition under which the project would be willing to say
so is being considered.

## 2. In scope, with sizes

Line counts below were measured directly against this branch with
`wc -l src/*.ts` and `wc -l src-tauri/src/lib.rs`; they are not estimates.

TypeScript core (`src/*.ts`, 11,351 lines total across the directory).
The modules most load-bearing for the security properties this review is
about:

| File | Lines | Role |
|---|---:|---|
| `src/crypto.ts` | 178 | Top-level vault envelope (`*.kv.enc`): key derivation, AEAD seal/open. |
| `src/document-crypto.ts` | 124 | Document-vault key-derivation manifest and per-object encrypted payload shape. |
| `src/sync.ts` | 2,565 | Change envelopes, device certificates/registry, freshness checkpoints, canonical JSON/base64, apply logic. |
| `src/sync-epoch.ts` | 187 | Epoch key hierarchy and per-device X25519 wrap construction. |
| `src/sync-relay.ts` | 418 | Relay HTTP client/server: opaque storage, bearer auth, containment checks. |
| `src/grants.ts` | 424 | Per-agent grant policy and redaction. |
| `src/plugin-signatures.ts` | 131 | Plugin manifest/package signature verification. |

Rust desktop core: `src-tauri/src/lib.rs`, 7,036 lines. A second, independent
implementation of vault unlock, document read/write, and (as of this branch)
read-only sync status (`sync_status`, `sync_verify_registry`) against the same
on-disk format as the TypeScript core.

The relay: `src/sync-relay.ts` (client and server share this file) plus
`docs/SYNC-RELAY.md` for the deployment/operations side.

## 3. Trust boundaries

- **The passphrase and the encrypted files on disk are the trust boundary.**
  Everything else is defense placed around that boundary, not a replacement
  for it.
- **The relay is untrusted.** It receives and serves only opaque ciphertext —
  encrypted change envelopes, encrypted device registries, encrypted
  freshness checkpoints — under a bearer token. It has no vault key and
  cannot read object types, device IDs, timestamps, or content. It is
  nonetheless a live availability adversary: it can delete, delay, or
  withhold data it holds.
- **Enrolled devices are trusted.** Enrollment is owner-signed; once a device
  holds the vault's content keys it is trusted with the plaintext those keys
  decrypt, subject to the forward-only rotation behavior in §5.
- **Plugins run sandboxed under declared, signed capabilities**
  (`src/plugin-signatures.ts`); they are not granted ambient vault access.
- **Agents reach the vault only through MCP tools**, not direct filesystem
  access; the per-agent grant layer (`src/grants.ts`) narrows what a given
  agent identity is handed, subject to the limits in §5.

## 4. Threat model

The review should evaluate the design and code against these adversaries:

1. **A malicious or compromised relay operator** — sees only ciphertext and
   metadata bounded by `docs/SYNC-RELAY.md`; can withhold, delay, delete, or
   selectively serve stale history.
2. **A revoked device that retains the passphrase or its prior key material**
   — should lose the ability to produce changes the registry accepts, and to
   decrypt content sealed under keys issued after its revocation; should
   *not* be assumed to lose access to anything sealed before it (see §5).
3. **A stolen vault at rest** (encrypted files with no passphrase) — should
   yield nothing beyond ciphertext and structural metadata already documented
   as visible (file existence, sizes, counts).
4. **A hostile or malformed plugin package** — signature and capability
   checks in `src/plugin-signatures.ts` should reject it before it runs with
   any capability it wasn't granted.
5. **A hostile or misconfigured agent** talking to the MCP server — the grant
   layer should narrow what it can retrieve, understanding (see §5) that it
   is not a boundary against the model itself.
6. **A hostile envelope or registry supplied as input** — a malformed or
   adversarially constructed sync change, device certificate, or device
   registry fed to either implementation (TypeScript or Rust) should fail
   closed rather than being accepted, and should not cause disproportionate
   resource consumption before validation.

## 5. Accepted known risks

Stated without softening, because a scope document that hides its own known
weaknesses is worse than no scope document:

- **The passphrase is the only real security boundary.** Anyone who holds it
  recovers everything the vault protects. There is no second factor and no
  boundary that survives passphrase compromise.
- **The grant layer is not a boundary against a model.** Per-agent grants and
  redaction narrow what an agent is *handed*, but a redacted value still
  enters the calling model's context as a redacted value; the grant layer
  cannot stop the model from having seen it.
- **`SBRAIN_AGENT` is a name the agent chooses, not a credential.** Anything
  able to start the MCP server can pick any agent name and inherit that
  name's grants.
- **Epoch rotation is forward-only.** Revoking a device advances the epoch
  and issues a fresh random content key wrapped only to remaining active
  devices — but a revoked device keeps every epoch key it already held, and
  can still decrypt everything sealed before its revocation. What it loses
  is everything sealed afterward. This is by design, not an oversight, but
  it means revocation is not equivalent to retroactively erasing a departed
  device's access to history.
- **Only the Windows credential-store path is exercised by tests.** `sbrain
  unlock --remember` can hand the passphrase to macOS Keychain or libsecret
  on Linux, but this project's test suite runs on and validates only the
  Windows DPAPI path.
- **Attachments larger than 6,242,304 bytes cannot sync at all.** A
  synchronized attachment travels as a snapshot inside a single change
  envelope, and an envelope is capped at 8 MiB (`MAX_CHANGE_BYTES`,
  `src/sync.ts`); after base64 expansion and envelope overhead that leaves
  `MAX_SYNC_ATTACHMENT_BYTES` = 6,242,304 raw bytes. Larger files are
  accepted into the vault and then refused by the sync layer with an explicit
  "until blob transport is available" error. This is a product gap rather
  than a vulnerability, but it bounds the review: there is no chunked or
  resumable blob path to look at, and any reasoning about relay storage or
  denial-of-service limits may assume every stored object is at most 8 MiB.

- **A known gap in the format catalogue.** `documents/index.enc`
  (`AAD.documentIndex`) and `documents/plugin-policy.enc`
  (`AAD.pluginPolicy`) use the same `DocumentPayload` envelope shape as
  artifacts under `documents/objects/`, but neither is a separate entry in
  `FORMAT_COMPATIBILITY` (`src/format-version.ts`). They are therefore
  outside the format's versioned read/write compatibility guarantees
  described in `docs/FORMAT-1.0.md` — that document already flags this at
  the point it describes `DocumentPayload`. An auditor should treat these two
  files as present on disk, encrypted with the project's real AEAD
  construction, but *not* covered by the format's stated 1.x compatibility
  policy, and should examine them as a gap in the map rather than assume the
  gap means they are unused or low-value.

## 6. The two-implementation problem

This is the single largest audit surface in the project and should be treated
as a first-class scope item, not a footnote. The TypeScript core (`src/`) and
the Rust desktop core (`src-tauri/src/lib.rs`, 7,036 lines) are two
independently written implementations that read and write the same on-disk
format, including two independently written canonical-JSON serializers used
for the signature verification that authenticates device certificates and
sync changes. Nothing enforces agreement between them beyond the shared
specification and shared fixtures; a divergence between the two is a format
bug that would not necessarily show up in either implementation's own tests
in isolation.

The material for checking the two against each other:

- `docs/FORMAT-1.0.md` — the normative specification both implementations
  are supposed to satisfy, including the canonical JSON / canonical base64
  rules.
- `test/fixtures/` — committed conformance vaults, including
  `test/fixtures/sync-epoch-v2/` for the rotated epoch-sealed format this
  branch added. These exist specifically so both implementations can be run
  against the same on-disk bytes and checked for agreement.
- `node --test test/format-conformance.test.mjs` exercises the TypeScript
  side against the fixtures; `cargo test --manifest-path src-tauri/Cargo.toml
  --lib` exercises the Rust side. Neither currently runs the other
  implementation's output through the other implementation — an auditor
  cross-checking the two directly, rather than relying on both merely
  agreeing with the same written specification, is exactly the value this
  engagement would add.

## 7. Already-closed findings

`docs/SECURITY-AUDIT-2026-09-02.md` and
`docs/SECURITY-REMEDIATION-2026-09-03.md` record an earlier internal review
and its remediation status. Finding SEC-05 ("Faz 6 sync, düşman relay ve
cihaz ele geçirilmesine hazır değil") called, among other things, for
"epoch tabanlı key rotation" (epoch-based key rotation) as a remediation
item. `docs/SECURITY-REMEDIATION-2026-09-03.md` recorded that item as not yet
implemented at the time it was written ("Epoch tabanlı content-key rotation
... henüz uygulanmadı").

This branch closes that specific item: epoch-based content-key rotation is
implemented (`src/sync-epoch.ts`, `bf4d3a9 feat(sync): rotate the epoch
content key when a device is revoked`), specified in `docs/FORMAT-1.0.md`,
and covered by committed conformance fixtures
(`test/fixtures/sync-epoch-v2/`). It closes only that item. The other SEC-05
remediation items already marked done in the 2026-09-03 remediation record
(owner-signed enrollment, per-device change signatures, authority pinning,
freshness checkpoints, the opaque relay) predate this branch and are not
claimed as new work here.

## 8. Questions for the auditor

Concrete and intended to be answerable from the code and fixtures, not
rhetorical:

1. Does epoch rotation actually exclude a revoked device that retains the
   passphrase? Wrapped epoch keys travel inside a registry that is itself
   encrypted under the vault's master key — walk the path from "device is
   revoked" to "device cannot derive the new epoch's content key" and
   confirm there is no route back in through the master-key-encrypted
   registry.
2. Is the change-ID HMAC construction (`AAD.syncChangeId`,
   `src/sync.ts`) sound as a relay-opaque identifier across an epoch
   boundary — does anything about epoch rotation let an adversary correlate,
   forge, or collide change IDs across epochs?
3. Can a hostile registry or envelope (malformed device certificate,
   adversarially large or deeply nested change DAG, corrupted epoch wrap
   list) cause unbounded work in either implementation before validation
   rejects it?
4. Do the TypeScript and Rust implementations agree on every conformance
   fixture in `test/fixtures/`, including `sync-epoch-v2/`? Where they
   diverge, is the divergence a bug in one implementation or an
   underspecification in `docs/FORMAT-1.0.md`?
5. Is there any path by which the grant layer (`src/grants.ts`) can be made
   to leak an unredacted value to an agent without the agent (or whoever
   controls its `SBRAIN_AGENT` name) already holding the passphrase?

## 9. Engagement shape and deliverables

Stated so a quote can be written against something specific rather than
against "review our crypto".

**Shape.** A source-available design and implementation review by one or two
engineers with applied-cryptography depth who can read both Rust and
TypeScript. This is not a penetration test: there is no hosted service to
attack — the relay is software the operator runs themselves — and it is not a
compliance audit against any framework.

**Suggested allocation.** A division of effort to argue with, not a fixed bid.
It is weighted by where this project believes its own risk actually sits:

| Area | Weight |
|---|---:|
| §6 two-implementation divergence, including differential execution over `test/fixtures/` | ~40% |
| Sync protocol: envelopes, registry, revocation cutoffs, epoch rotation (§8 Q1, Q2) | ~30% |
| Hostile-input handling and resource bounds in both implementations (§8 Q3) | ~15% |
| Vault envelope and key derivation: `src/crypto.ts`, `src/document-crypto.ts` | ~10% |
| Grant layer and plugin signature verification (§8 Q5) | ~5% |

**Deliverables.**

1. Findings with severity, affected file and line, and a reproduction — a
   claim that cannot be reproduced against this repository is not usable.
2. A differential test harness that runs both implementations over the same
   fixture bytes and reports disagreement, delivered as code that can be
   committed and run in CI. This is the deliverable with the longest life:
   §6 is a permanent property of the architecture, not a one-time finding.
3. Direct answers to the five questions in §8, including "no, and here is
   why the question was malformed" where that is the honest answer.
4. An explicit statement of what was *not* examined, so the project does not
   later claim coverage the engagement never gave it.

**What passing means.** The gate is the presentation decision in §1 and
nothing wider: whether this project may stop saying it is unsuitable for real
medical, financial, or identity data. A review that finds serious issues and
sees them fixed satisfies that gate; a review that finds nothing because it
looked at little does not.

**Working materials.** The repository, its committed fixtures, the format
specification, and the commands in §11. No NDA-restricted material is
withheld from the reviewer, and the project asks for the right to publish the
findings once fixes have shipped.

## 10. Out of scope

- **iOS and Android clients.** Out of scope for the product, not merely
  unbuilt. Per `docs/ROADMAP.md` mobile clients are no longer planned: a phone
  client would make a hosted relay and a third-party app store part of the
  product, and would put the passphrase — per §5 the only real security
  boundary — on a device the owner does not fully control. Sync is
  desktop-to-desktop. There is no mobile code to review and none is coming.
- **The plugin ecosystem's third-party packages.** `src/plugin-signatures.ts`
  and the plugin sandbox are in scope; any specific third-party plugin's own
  logic is not.
- **The relay's hosting environment.** TLS termination, network placement,
  and host OS hardening for a self-hosted relay deployment are the
  self-hoster's responsibility per `docs/SYNC-RELAY.md`, not this codebase's.
- **Desktop-driven sync mutation.** The desktop app in this branch exposes
  only read-only sync status (`sync_status`, `sync_verify_registry`); it has
  no enrollment, revocation, import, apply, or relay push/pull surface to
  review, because none exists yet. Worth knowing while reading §6: the Rust
  core links `ed25519-dalek` for verification only — no `SigningKey` use — and
  carries no X25519 dependency at all, so building desktop-side mutation
  would mean a second independent *signing* and key-wrapping implementation
  and would roughly double the §6 surface. A reviewer opinion on whether
  that is wise, or whether desktop mutation should delegate to the
  TypeScript core, is explicitly welcome.

## 11. Reproducing the build and running the evidence

```bash
npm ci
npm run quality
npm run quality:rust
npm run benchmark
npm run recovery:drill
node --test test/format-conformance.test.mjs
```

`npm run quality` runs lint, format check, typecheck, the Node test suite
(including `test/sync.test.mjs`, `test/sync-epoch.test.mjs`,
`test/sync-relay.test.mjs`, `test/cli.test.mjs`, and
`test/format-conformance.test.mjs`), the desktop Vitest suite, and the
desktop build. `npm run quality:rust` runs `cargo clippy -D warnings` and the
Rust test suite over `src-tauri/src/lib.rs`. `npm run recovery:drill` exercises
the encrypted-backup-plus-relay-catch-up recovery path end to end.
