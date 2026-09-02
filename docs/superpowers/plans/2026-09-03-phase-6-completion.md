# Phase 6 Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the four open Phase 6 items — epoch-based content-key rotation, a frozen 1.0 on-disk format, read-only desktop sync status, and an auditor-ready package — without breaking any vault already on disk.

**Architecture:** Rotation introduces a random per-epoch content key wrapped to each active device's X25519 key, carried inside the already owner-signed encrypted device registry, and advanced automatically when a device is revoked. Epoch 1 stays the master-key epoch so existing vaults need no migration. The format freeze pulls every version field and AAD domain string into one inventory module and locks them with committed conformance fixtures. The desktop gains read-only sync status in the Rust core; sync mutation stays CLI-only so the protocol keeps one authoritative implementation.

**Tech Stack:** TypeScript (Node 20+, `node:crypto`, ESM, `node --test`), Rust (Tauri 2, `aes-gcm`, `scrypt`, `ed25519-dalek`, `cargo test`), React 19 + Vitest for the desktop UI.

**Spec:** `docs/superpowers/specs/2026-09-03-phase-6-completion-design.md`

## Global Constraints

- **Node engine floor:** `>=20`. `crypto.hkdfSync`, `crypto.diffieHellman` and X25519 key generation are all available there.
- **Older vaults must stay readable.** Every format change is additive and versioned. No task rewrites an existing on-disk artifact in place.
- **Epoch 1 is the master-key epoch.** It has no random key, no wraps, and no entry under `identity/epochs/`. Epochs 2 and above use a random wrapped key. This single rule decides which key seals a change.
- **Sync change envelope versions:** `EncryptedSyncChange.version` is `1` (no `epoch` field, master-key sealed) or `2` (`epoch: number` with minimum 2, epoch-key sealed).
- **Certificate and registry versions:** `SyncDeviceCertificate.version` and `SyncDeviceRegistryBody.version` are `1` or `2`. Version 2 certificates carry `keyAgreementKey`; version 2 registry bodies carry `epochKeys`.
- **Key encodings, unchanged from the existing code:** Ed25519 and X25519 public keys are base64 SPKI DER of exactly 44 decoded bytes. Private keys are base64 PKCS#8 DER of exactly 48 decoded bytes. Signatures are base64 of exactly 64 decoded bytes.
- **Canonical JSON** is the existing RFC 8785-compatible `canonicalSyncJson`. Canonical base64 means `Buffer.from(v, "base64").toString("base64") === v`.
- **Rotation is triggered only by revocation.** No manual rotate command is added.
- **Rotation is forward-only** and must be documented in those words: a revoked device keeps every epoch key it already held and can still read pre-revocation changes.
- **Honesty rule for docs:** nothing that did not happen may be marked as having happened. The external audit and mobile clients stay unchecked on the roadmap.
- **Quality gate:** `npm run quality` (lint, format:check, typecheck, test, desktop:test, desktop:build) must pass before the final commit of each part. Rust tasks additionally run `npm run quality:rust`.
- **Tests import compiled output** from `../dist/`, so every test run is `npm run build && node --test <file>`.

## Ordering note (refines the spec)

The spec ordered rotation before the format freeze so the frozen spec would describe the final shape. That still holds for the *documentation and fixtures* (Tasks 11 and 12), which come after rotation. But the shared constants module is a prerequisite for rotation rather than a consequence of it — rotation needs a home for its new AAD strings and a shared canonical-base64 validator, and duplicating either would defeat the purpose. So `src/format-version.ts` is created first, in Task 1, and rotation adds its constants to it as it goes.

## File Structure

**Created:**

- `src/format-version.ts` — frozen format version, the artifact/version compatibility record, every AAD domain string, and the canonical base64 validator. One responsibility: the format's identity surface.
- `src/sync-epoch.ts` — X25519 epoch-key wrapping primitives and the on-disk epoch key store. Kept out of `sync.ts` because `sync.ts` is already 2323 lines and this is a self-contained cryptographic unit with its own tests.
- `docs/FORMAT-1.0.md` — the normative on-disk format specification.
- `docs/AUDIT-SCOPE.md` — the auditor-facing scope, threat model and accepted-risk record.
- `test/format-conformance.test.mjs` — asserts the frozen version/AAD surface and opens the committed epoch fixtures.
- `test/fixtures/sync-epoch-v2/**` — a committed post-rotation vault, following the existing fixture convention.
- `test/cli.test.mjs` — the project's first CLI process test, covering `sbrain format`.
- `desktop/src/SyncStatus.tsx` — read-only sync status panel.
- `desktop/src/SyncStatus.test.tsx` — panel tests.

**Modified:**

- `src/sync.ts` — certificate/registry v2 types and validation, envelope v2, enrollment X25519 pairs, rotation inside `revoke()`, epoch-aware seal/open.
- `src/crypto.ts`, `src/document-crypto.ts`, `src/documents.ts` — import their AAD constants from `format-version.ts` instead of declaring them.
- `src/cli.ts` — `sbrain format`, epoch column in `sync devices list`, rotation note in `sync devices revoke`.
- `scripts/make-fixtures.mjs` — adds the post-rotation fixture and its row in the generated `test/fixtures/README.md` table.
- `src-tauri/src/lib.rs` — `sync_status` and `sync_verify_registry` read-only commands.
- `src-tauri/capabilities/main.json` — allow the two new commands.
- `desktop/src/App.tsx`, `desktop/src/bridge.ts`, `desktop/src/types.ts` — wire the panel in.
- `test/sync.test.mjs` — rotation tests.
- `README.md`, `docs/ROADMAP.md`, `docs/ARCHITECTURE.md`, `SECURITY.md`, `package.json` — documentation and version truth.

---

## Part A — Shared format surface

### Task 1: Format version and AAD inventory module

**Files:**

- Create: `src/format-version.ts`
- Modify: `src/document-crypto.ts:11`, `src/documents.ts:319-365`, `src/sync.ts:32-39`
- Test: `test/format-conformance.test.mjs` (created here with the inventory test only; fixtures arrive in Task 12)

**Interfaces:**

- Consumes: nothing.
- Produces: `VAULT_FORMAT_VERSION: "1.0"`, `FORMAT_COMPATIBILITY: FormatCompatibility`, `AAD: Readonly<Record<string, string>>`, `canonicalBase64(value: unknown, expectedBytes: number | undefined, label: string): string`, and the per-artifact AAD builder functions `noteAad(id)`, `noteHistoryAad(id, revision)`, `canvasAad(id)`, `canvasHistoryAad(id, revision)`, `pluginAad(id)`, `pluginStoreAad(id)`, `attachmentManifestAad(id)`, `attachmentChunkAad(id, index)`, `syncChangeAad(id)`, `syncDeviceKeyAad(deviceId)`.

- [ ] **Step 1: Write the failing inventory test**

Create `test/format-conformance.test.mjs`:

```js
import assert from "node:assert/strict";
import test from "node:test";

import { AAD, FORMAT_COMPATIBILITY, VAULT_FORMAT_VERSION, canonicalBase64 } from "../dist/format-version.js";

test("the format version surface is frozen and complete", () => {
  assert.equal(VAULT_FORMAT_VERSION, "1.0");

  // Every AAD string is domain-separated under one prefix and is unique.
  const values = Object.values(AAD);
  assert.ok(values.length >= 20, "the inventory must cover every domain string in the codebase");
  for (const value of values) {
    assert.match(value, /^secondbrain-vault:/u, `AAD ${value} must carry the project prefix`);
  }
  assert.equal(new Set(values).size, values.length, "AAD strings must be unique");

  // The compatibility record names every artifact and the versions this build handles.
  for (const [artifact, entry] of Object.entries(FORMAT_COMPATIBILITY)) {
    assert.ok(entry.reads.length > 0, `${artifact} must declare readable versions`);
    assert.ok(entry.writes.length > 0, `${artifact} must declare written versions`);
    for (const written of entry.writes) {
      assert.ok(entry.reads.includes(written), `${artifact} must read every version it writes`);
    }
  }
  assert.deepEqual(FORMAT_COMPATIBILITY.encryptedEnvelope.reads, [0, 1]);
  assert.deepEqual(FORMAT_COMPATIBILITY.encryptedEnvelope.writes, [1]);
});

test("canonical base64 rejects non-canonical and wrong-length encodings", () => {
  const key = Buffer.alloc(44, 7).toString("base64");
  assert.equal(canonicalBase64(key, 44, "test key"), key);
  assert.throws(() => canonicalBase64(key, 32, "test key"), /invalid test key length/u);
  assert.throws(() => canonicalBase64("not base64!", undefined, "test key"), /malformed test key/u);
  // "QQ==" is canonical; "QQ" is the same bytes without padding and must be refused.
  assert.equal(canonicalBase64("QQ==", 1, "test key"), "QQ==");
  assert.throws(() => canonicalBase64("QQ", 1, "test key"), /malformed test key/u);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm run build && node --test test/format-conformance.test.mjs`
Expected: FAIL — build error, `dist/format-version.js` does not exist.

- [ ] **Step 3: Create the module**

Create `src/format-version.ts`:

```ts
/**
 * The single inventory of everything that identifies this vault's on-disk
 * format: the frozen format version, which artifact versions this build reads
 * and writes, and every AEAD domain-separation string.
 *
 * These strings are load-bearing. Changing one does not fail loudly — it makes
 * previously written vaults undecryptable. They live here so they are
 * reviewable in one place and are frozen by test/format-conformance.test.mjs.
 *
 * Compatibility policy: within 1.x only additive optional fields are allowed.
 * Bumping an artifact version, changing an AAD string, removing a field, or
 * altering a canonical encoding requires format 2.0 and a migration path.
 */

/** Frozen on-disk format version. Not the product version in package.json. */
export const VAULT_FORMAT_VERSION = "1.0";

export interface FormatArtifact {
  /** Where the artifact lives, relative to the vault directory. */
  readonly path: string;
  /** Versions this build can open. */
  readonly reads: readonly number[];
  /** Versions this build produces. Always a subset of `reads`. */
  readonly writes: readonly number[];
}

export type FormatCompatibility = Readonly<Record<string, FormatArtifact>>;

export const FORMAT_COMPATIBILITY: FormatCompatibility = {
  encryptedEnvelope: { path: "*.kv.enc", reads: [0, 1], writes: [1] },
  documentManifest: { path: "documents/manifest.json", reads: [1], writes: [1] },
  documentPayload: { path: "documents/objects/*.enc", reads: [1], writes: [1] },
  syncChangeEnvelope: { path: "documents/sync/changes/*.change.enc", reads: [1, 2], writes: [1, 2] },
  syncDeviceCertificate: { path: "documents/sync/devices.enc", reads: [1, 2], writes: [1, 2] },
  syncDeviceRegistry: { path: "documents/sync/devices.enc", reads: [1, 2], writes: [1, 2] },
  syncEnrollmentRequest: { path: "(transferred)", reads: [1, 2], writes: [1, 2] },
  syncFreshnessCheckpoint: { path: "documents/sync/checkpoint.enc", reads: [1], writes: [1] },
  syncAppliedState: { path: "documents/sync/applied.enc", reads: [1], writes: [1] },
} as const;

/**
 * Fixed AEAD domain-separation strings. Suffixed builders below cover the
 * artifacts whose AAD includes an identifier.
 */
export const AAD = {
  documentKeyCheck: "secondbrain-vault:document-key:v1",
  documentIndex: "secondbrain-vault:document-index:v1",
  pluginPolicy: "secondbrain-vault:plugin-policy:v1",
  attachmentId: "secondbrain-vault:attachment-id:v1\0",
  syncChangeId: "secondbrain-vault:sync-change-id:v1",
  syncChangeKey: "secondbrain-vault:sync-change-key:v1",
  syncChangeKeyV2: "secondbrain-vault:sync-change-key:v2",
  syncChangePrefix: "secondbrain-vault:sync-change:v1:",
  syncApplied: "secondbrain-vault:sync-applied:v1",
  syncDeviceRegistry: "secondbrain-vault:sync-device-registry:v1",
  syncFreshnessCheckpoint: "secondbrain-vault:sync-freshness-checkpoint:v1",
  syncAuthorityKey: "secondbrain-vault:sync-authority-key:v1",
  syncDeviceKeyPrefix: "secondbrain-vault:sync-device-key:v1:",
  syncAgreementKeyPrefix: "secondbrain-vault:sync-agreement-key:v1:",
  syncEpochKeyPrefix: "secondbrain-vault:sync-epoch-key:v1:",
  syncEpochWrap: "secondbrain-vault:sync-epoch-wrap:v1",
  notePrefix: "secondbrain-vault:note:v1:",
  noteHistoryPrefix: "secondbrain-vault:note-history:v1:",
  canvasPrefix: "secondbrain-vault:canvas:v1:",
  canvasHistoryPrefix: "secondbrain-vault:canvas-history:v1:",
  pluginPrefix: "secondbrain-vault:plugin:v1:",
  pluginStorePrefix: "secondbrain-vault:plugin-store:v1:",
  attachmentManifestPrefix: "secondbrain-vault:attachment-manifest:v1:",
  attachmentChunkPrefix: "secondbrain-vault:attachment-chunk:v1:",
} as const;

export const noteAad = (id: string): string => `${AAD.notePrefix}${id}`;
export const noteHistoryAad = (id: string, revision: number): string =>
  `${AAD.noteHistoryPrefix}${id}:${revision}`;
export const canvasAad = (id: string): string => `${AAD.canvasPrefix}${id}`;
export const canvasHistoryAad = (id: string, revision: number): string =>
  `${AAD.canvasHistoryPrefix}${id}:${revision}`;
export const pluginAad = (id: string): string => `${AAD.pluginPrefix}${id}`;
export const pluginStoreAad = (id: string): string => `${AAD.pluginStorePrefix}${id}`;
export const attachmentManifestAad = (id: string): string => `${AAD.attachmentManifestPrefix}${id}`;
export const attachmentChunkAad = (id: string, index: number): string =>
  `${AAD.attachmentChunkPrefix}${id}:${index}`;
export const syncChangeAad = (id: string): string => `${AAD.syncChangePrefix}${id}`;
export const syncDeviceKeyAad = (deviceId: string): string => `${AAD.syncDeviceKeyPrefix}${deviceId}`;
export const syncAgreementKeyAad = (deviceId: string): string =>
  `${AAD.syncAgreementKeyPrefix}${deviceId}`;
export const syncEpochKeyAad = (epoch: number): string => `${AAD.syncEpochKeyPrefix}${epoch}`;

/**
 * Strict base64: rejects malformed alphabets, non-canonical padding, and
 * unexpected lengths. Shared so every artifact validates encodings identically.
 */
export function canonicalBase64(value: unknown, expectedBytes: number | undefined, label: string): string {
  if (
    typeof value !== "string" ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)
  ) {
    throw new Error(`Encrypted payload has malformed ${label}.`);
  }
  const decoded = Buffer.from(value, "base64");
  if (expectedBytes !== undefined && decoded.length !== expectedBytes) {
    throw new Error(`Encrypted payload has invalid ${label} length.`);
  }
  if (decoded.toString("base64") !== value) {
    throw new Error(`Encrypted payload has non-canonical ${label}.`);
  }
  return value;
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm run build && node --test test/format-conformance.test.mjs`
Expected: PASS, both tests.

- [ ] **Step 5: Replace the duplicated constants at their call sites**

In `src/document-crypto.ts`, delete the local `KEY_CHECK_CONTEXT` declaration and import it:

```ts
import { AAD } from "./format-version.js";
```

then replace the single use in `verifier()` with `AAD.documentKeyCheck`.

In `src/sync.ts`, delete the eight local AAD constants at lines 32-39 and import their replacements:

```ts
import {
  AAD,
  canonicalBase64,
  syncChangeAad,
  syncDeviceKeyAad,
} from "./format-version.js";
```

Replace uses as follows, leaving all behaviour identical: `CHANGE_ID_CONTEXT` → `AAD.syncChangeId`; `CHANGE_KEY_CONTEXT` → `AAD.syncChangeKey`; `` `${CHANGE_AAD_PREFIX}${id}` `` → `syncChangeAad(id)`; `APPLIED_AAD` → `AAD.syncApplied`; `DEVICE_REGISTRY_AAD` → `AAD.syncDeviceRegistry`; `FRESHNESS_CHECKPOINT_AAD` → `AAD.syncFreshnessCheckpoint`; `AUTHORITY_KEY_AAD` → `AAD.syncAuthorityKey`; `` `${DEVICE_KEY_AAD_PREFIX}${deviceId}` `` → `syncDeviceKeyAad(deviceId)`. Delete the local `canonicalBase64` function in `sync.ts` and use the imported one — its error messages change from "Encrypted sync payload has …" to "Encrypted payload has …", which no test asserts on.

In `src/documents.ts`, delete the local constants and AAD builder functions at lines 319-365 and import the equivalents:

```ts
import {
  AAD,
  attachmentChunkAad,
  attachmentManifestAad,
  canvasAad,
  canvasHistoryAad,
  noteAad,
  noteHistoryAad,
  pluginAad,
  pluginStoreAad,
} from "./format-version.js";
```

Replace the two `secondbrain-vault:attachment-id:v1\0` literals at lines 2025 and 2076 with `AAD.attachmentId`.

- [ ] **Step 6: Verify nothing changed on disk**

Run: `npm run build && node --test test/core.test.mjs test/documents.test.mjs test/canvas.test.mjs test/plugins.test.mjs test/sync.test.mjs`
Expected: PASS. Every AAD string is byte-identical to before, so previously written fixtures still decrypt. If any test fails, an AAD was transcribed wrong — diff the string against git history rather than changing the test.

- [ ] **Step 7: Commit**

```bash
git add src/format-version.ts src/crypto.ts src/document-crypto.ts src/documents.ts src/sync.ts test/format-conformance.test.mjs
git commit -m "refactor: gather format versions and AAD domain strings into one inventory"
```

---

## Part B — Epoch content-key rotation

### Task 2: Epoch key wrapping primitives

**Files:**

- Create: `src/sync-epoch.ts`
- Test: `test/sync-epoch.test.mjs`
- Modify: `package.json:test` (add the new test file to the `test` script)

**Interfaces:**

- Consumes: `AAD`, `canonicalBase64` from `src/format-version.ts` (Task 1).
- Produces:
  - `EPOCH_KEY_BYTES = 32`
  - `interface EpochKeyWrap { deviceId: string; ephemeralPublicKey: string; iv: string; authTag: string; ciphertext: string }`
  - `generateAgreementKeyPair(): crypto.KeyPairKeyObjectResult`
  - `exportAgreementPublicKey(key: crypto.KeyObject): string`
  - `agreementPublicKeyFromBase64(value: unknown, label: string): crypto.KeyObject`
  - `agreementPrivateKeyFromBase64(value: string, label: string): crypto.KeyObject`
  - `wrapEpochKey(epochKey: Buffer, epoch: number, deviceId: string, devicePublicKey: crypto.KeyObject): EpochKeyWrap`
  - `unwrapEpochKey(wrap: EpochKeyWrap, epoch: number, deviceId: string, devicePrivateKey: crypto.KeyObject): Buffer`
  - `validateEpochKeyWrap(value: unknown): EpochKeyWrap`

- [ ] **Step 1: Write the failing test**

Create `test/sync-epoch.test.mjs`:

```js
import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  EPOCH_KEY_BYTES,
  agreementPublicKeyFromBase64,
  exportAgreementPublicKey,
  generateAgreementKeyPair,
  unwrapEpochKey,
  validateEpochKeyWrap,
  wrapEpochKey,
} from "../dist/sync-epoch.js";

const DEVICE_A = "11111111-1111-4111-8111-111111111111";
const DEVICE_B = "22222222-2222-4222-8222-222222222222";

test("an epoch key round-trips to the intended device only", () => {
  const alice = generateAgreementKeyPair();
  const bob = generateAgreementKeyPair();
  const epochKey = crypto.randomBytes(EPOCH_KEY_BYTES);

  const wrap = wrapEpochKey(epochKey, 2, DEVICE_A, alice.publicKey);
  assert.equal(wrap.deviceId, DEVICE_A);
  assert.deepEqual(unwrapEpochKey(wrap, 2, DEVICE_A, alice.privateKey), epochKey);

  // A different device's private key cannot open it.
  assert.throws(() => unwrapEpochKey(wrap, 2, DEVICE_A, bob.privateKey));
});

test("a wrap is bound to its epoch and device and cannot be replayed", () => {
  const alice = generateAgreementKeyPair();
  const epochKey = crypto.randomBytes(EPOCH_KEY_BYTES);
  const wrap = wrapEpochKey(epochKey, 2, DEVICE_A, alice.publicKey);

  // Same ciphertext, claimed for a later epoch: the AAD no longer matches.
  assert.throws(() => unwrapEpochKey(wrap, 3, DEVICE_A, alice.privateKey));
  // Same ciphertext, relabelled for another device: also refused.
  assert.throws(() => unwrapEpochKey({ ...wrap, deviceId: DEVICE_B }, 2, DEVICE_B, alice.privateKey));
});

test("every wrap of the same key uses a fresh ephemeral key and nonce", () => {
  const alice = generateAgreementKeyPair();
  const epochKey = crypto.randomBytes(EPOCH_KEY_BYTES);
  const first = wrapEpochKey(epochKey, 2, DEVICE_A, alice.publicKey);
  const second = wrapEpochKey(epochKey, 2, DEVICE_A, alice.publicKey);
  assert.notEqual(first.ephemeralPublicKey, second.ephemeralPublicKey);
  assert.notEqual(first.iv, second.iv);
  assert.notEqual(first.ciphertext, second.ciphertext);
});

test("agreement keys are X25519 and structurally validated", () => {
  const pair = generateAgreementKeyPair();
  const encoded = exportAgreementPublicKey(pair.publicKey);
  assert.equal(Buffer.from(encoded, "base64").length, 44);
  assert.equal(agreementPublicKeyFromBase64(encoded, "test key").asymmetricKeyType, "x25519");

  // An Ed25519 key is the same 44-byte SPKI length and must still be rejected.
  const signing = crypto.generateKeyPairSync("ed25519");
  const ed = signing.publicKey.export({ format: "der", type: "spki" }).toString("base64");
  assert.throws(() => agreementPublicKeyFromBase64(ed, "test key"), /must be an X25519 public key/u);
});

test("malformed wraps are rejected before any cryptographic work", () => {
  const alice = generateAgreementKeyPair();
  const wrap = wrapEpochKey(crypto.randomBytes(EPOCH_KEY_BYTES), 2, DEVICE_A, alice.publicKey);
  assert.deepEqual(validateEpochKeyWrap(wrap), wrap);
  assert.throws(() => validateEpochKeyWrap({ ...wrap, deviceId: "not-a-uuid" }), /device ID/u);
  assert.throws(() => validateEpochKeyWrap({ ...wrap, iv: "AAAA" }), /nonce/u);
  assert.throws(() => validateEpochKeyWrap({ ...wrap, authTag: "AAAA" }), /authentication tag/u);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm run build && node --test test/sync-epoch.test.mjs`
Expected: FAIL — `dist/sync-epoch.js` does not exist.

- [ ] **Step 3: Implement the module**

Create `src/sync-epoch.ts`:

```ts
import crypto from "node:crypto";
import { AAD, canonicalBase64 } from "./format-version.js";

/** AES-256 content key for one sync epoch. */
export const EPOCH_KEY_BYTES = 32;

const DEVICE_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;

/**
 * One epoch content key sealed to one enrolled device. These live inside the
 * owner-signed device registry, so the authority signature covers them.
 */
export interface EpochKeyWrap {
  deviceId: string;
  /** base64 X25519 SPKI DER, fresh for every wrap. */
  ephemeralPublicKey: string;
  iv: string;
  authTag: string;
  ciphertext: string;
}

export function generateAgreementKeyPair(): crypto.KeyPairKeyObjectResult {
  return crypto.generateKeyPairSync("x25519");
}

export function exportAgreementPublicKey(key: crypto.KeyObject): string {
  return key.export({ format: "der", type: "spki" }).toString("base64");
}

export function agreementPublicKeyFromBase64(value: unknown, label: string): crypto.KeyObject {
  const encoded = canonicalBase64(value, 44, label);
  let key: crypto.KeyObject;
  try {
    key = crypto.createPublicKey({ key: Buffer.from(encoded, "base64"), format: "der", type: "spki" });
  } catch {
    throw new Error(`${label} is not a valid X25519 public key.`);
  }
  // Ed25519 SPKI DER is also 44 bytes, so the length check alone is not enough.
  if (key.asymmetricKeyType !== "x25519") throw new Error(`${label} must be an X25519 public key.`);
  return key;
}

export function agreementPrivateKeyFromBase64(value: string, label: string): crypto.KeyObject {
  const encoded = canonicalBase64(value, 48, label);
  let key: crypto.KeyObject;
  try {
    key = crypto.createPrivateKey({ key: Buffer.from(encoded, "base64"), format: "der", type: "pkcs8" });
  } catch {
    throw new Error(`${label} is not a valid X25519 private key.`);
  }
  if (key.asymmetricKeyType !== "x25519") throw new Error(`${label} must be an X25519 private key.`);
  return key;
}

/**
 * The epoch number and device ID are bound into both the HKDF info and the
 * AEAD associated data, so a wrap cannot be replayed onto another device or
 * presented as belonging to a different epoch.
 */
function wrapContext(epoch: number, deviceId: string): Buffer {
  return Buffer.from(`${AAD.syncEpochWrap}:${epoch}:${deviceId}`, "utf8");
}

function wrapKey(shared: Buffer, epoch: number, deviceId: string): Buffer {
  return Buffer.from(
    crypto.hkdfSync("sha256", shared, Buffer.alloc(0), wrapContext(epoch, deviceId), 32),
  );
}

export function wrapEpochKey(
  epochKey: Buffer,
  epoch: number,
  deviceId: string,
  devicePublicKey: crypto.KeyObject,
): EpochKeyWrap {
  if (epochKey.length !== EPOCH_KEY_BYTES) throw new Error("An epoch content key must be 32 bytes.");
  if (!Number.isSafeInteger(epoch) || epoch < 2) throw new Error("Only epoch 2 and above carry wrapped keys.");
  if (!DEVICE_ID.test(deviceId)) throw new Error("Sync device ID must be a lowercase UUID.");

  const ephemeral = generateAgreementKeyPair();
  const shared = crypto.diffieHellman({ privateKey: ephemeral.privateKey, publicKey: devicePublicKey });
  const key = wrapKey(shared, epoch, deviceId);
  shared.fill(0);
  try {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(wrapContext(epoch, deviceId));
    const ciphertext = Buffer.concat([cipher.update(epochKey), cipher.final()]);
    return {
      deviceId,
      ephemeralPublicKey: exportAgreementPublicKey(ephemeral.publicKey),
      iv: iv.toString("base64"),
      authTag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    };
  } finally {
    key.fill(0);
  }
}

export function unwrapEpochKey(
  wrap: EpochKeyWrap,
  epoch: number,
  deviceId: string,
  devicePrivateKey: crypto.KeyObject,
): Buffer {
  const normalized = validateEpochKeyWrap(wrap);
  if (normalized.deviceId !== deviceId) throw new Error("Epoch key wrap is addressed to a different device.");
  const ephemeral = agreementPublicKeyFromBase64(normalized.ephemeralPublicKey, "Epoch wrap ephemeral key");
  const shared = crypto.diffieHellman({ privateKey: devicePrivateKey, publicKey: ephemeral });
  const key = wrapKey(shared, epoch, deviceId);
  shared.fill(0);
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(normalized.iv, "base64"));
    decipher.setAAD(wrapContext(epoch, deviceId));
    decipher.setAuthTag(Buffer.from(normalized.authTag, "base64"));
    const epochKey = Buffer.concat([
      decipher.update(Buffer.from(normalized.ciphertext, "base64")),
      decipher.final(),
    ]);
    if (epochKey.length !== EPOCH_KEY_BYTES) throw new Error("Unwrapped epoch key has the wrong length.");
    return epochKey;
  } finally {
    key.fill(0);
  }
}

export function validateEpochKeyWrap(value: unknown): EpochKeyWrap {
  const wrap = value as EpochKeyWrap | undefined;
  if (!wrap || typeof wrap !== "object" || Array.isArray(wrap)) {
    throw new Error("An epoch key wrap must be an object.");
  }
  if (typeof wrap.deviceId !== "string" || !DEVICE_ID.test(wrap.deviceId)) {
    throw new Error("Epoch key wrap device ID must be a lowercase UUID.");
  }
  return {
    deviceId: wrap.deviceId,
    ephemeralPublicKey: canonicalBase64(wrap.ephemeralPublicKey, 44, "epoch wrap ephemeral key"),
    iv: canonicalBase64(wrap.iv, 12, "nonce"),
    authTag: canonicalBase64(wrap.authTag, 16, "authentication tag"),
    ciphertext: canonicalBase64(wrap.ciphertext, EPOCH_KEY_BYTES, "epoch key ciphertext"),
  };
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm run build && node --test test/sync-epoch.test.mjs`
Expected: PASS, all five tests.

- [ ] **Step 5: Register the test file**

In `package.json`, add `test/sync-epoch.test.mjs` to the `test` script's file list, immediately after `test/sync.test.mjs`.

- [ ] **Step 6: Commit**

```bash
git add src/sync-epoch.ts test/sync-epoch.test.mjs package.json
git commit -m "feat(sync): add X25519 epoch content-key wrapping"
```

---

### Task 3: Local epoch key store

**Files:**

- Modify: `src/sync-epoch.ts`
- Test: `test/sync-epoch.test.mjs`

**Interfaces:**

- Consumes: `wrapEpochKey`, `unwrapEpochKey`, `EPOCH_KEY_BYTES` (Task 2); `encryptDocument`, `decryptDocument`, `type DocumentPayload` from `src/document-crypto.js`; `writeFileAtomic`, `assertNotSymlink`, `readTextFileLimited` from `src/fs-safe.js`; `resolveInside` from `src/safety.js`; `syncEpochKeyAad` from `src/format-version.js`.
- Produces:
  - `epochKeyDir(rootDir: string): string`
  - `readEpochKey(rootDir: string, vaultKey: Buffer, epoch: number): Buffer | undefined`
  - `saveEpochKey(rootDir: string, vaultKey: Buffer, epoch: number, epochKey: Buffer): void`

The store caches each epoch key encrypted under the master key so a device can reopen historical epochs after a restart, and so an encrypted vault backup restores everything. Epoch 1 is never stored: it is the master-key epoch.

- [ ] **Step 1: Write the failing test**

Append to `test/sync-epoch.test.mjs`:

```js
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { openDocumentKey } from "../dist/document-crypto.js";
import { readEpochKey, saveEpochKey } from "../dist/sync-epoch.js";

test("epoch keys persist under the master key and refuse epoch 1", () => {
  const vaultDir = fs.mkdtempSync(path.join(os.tmpdir(), "secondbrain-epoch-store-"));
  const session = openDocumentKey(vaultDir, "epoch-store-test-passphrase");
  const epochKey = crypto.randomBytes(EPOCH_KEY_BYTES);

  assert.equal(readEpochKey(session.rootDir, session.key, 2), undefined, "an unknown epoch reads as absent");
  saveEpochKey(session.rootDir, session.key, 2, epochKey);
  assert.deepEqual(readEpochKey(session.rootDir, session.key, 2), epochKey);

  // Epoch 1 is the master-key epoch and never has a stored key.
  assert.throws(() => saveEpochKey(session.rootDir, session.key, 1, epochKey), /epoch 2 and above/u);
  assert.throws(() => readEpochKey(session.rootDir, session.key, 1), /epoch 2 and above/u);

  // The stored file is ciphertext, not the raw key.
  const stored = fs.readFileSync(path.join(session.rootDir, "sync", "identity", "epochs", "2.key.enc"), "utf8");
  assert.doesNotMatch(stored, new RegExp(epochKey.toString("base64").slice(0, 16), "u"));
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm run build && node --test test/sync-epoch.test.mjs`
Expected: FAIL — `readEpochKey` is not exported.

- [ ] **Step 3: Implement the store**

Append to `src/sync-epoch.ts`:

```ts
import fs from "node:fs";
import path from "node:path";
import { decryptDocument, encryptDocument, type DocumentPayload } from "./document-crypto.js";
import { assertNotSymlink, readTextFileLimited, writeFileAtomic } from "./fs-safe.js";
import { resolveInside } from "./safety.js";
import { syncEpochKeyAad } from "./format-version.js";

export function epochKeyDir(rootDir: string): string {
  return resolveInside(rootDir, path.join("sync", "identity", "epochs"));
}

function assertStorableEpoch(epoch: number): number {
  if (!Number.isSafeInteger(epoch) || epoch < 2) {
    throw new Error("Only epoch 2 and above have a stored content key; epoch 1 uses the vault key.");
  }
  return epoch;
}

function epochKeyPath(rootDir: string, epoch: number): string {
  return resolveInside(epochKeyDir(rootDir), `${assertStorableEpoch(epoch)}.key.enc`);
}

export function readEpochKey(rootDir: string, vaultKey: Buffer, epoch: number): Buffer | undefined {
  const filePath = epochKeyPath(rootDir, epoch);
  if (!fs.existsSync(filePath)) return undefined;
  assertNotSymlink(filePath);
  const payload = JSON.parse(
    readTextFileLimited(filePath, 64 * 1024, `Sync epoch ${epoch} key`),
  ) as DocumentPayload;
  const key = Buffer.from(decryptDocument(payload, vaultKey, syncEpochKeyAad(epoch)), "base64");
  if (key.length !== EPOCH_KEY_BYTES) throw new Error(`Stored sync epoch ${epoch} key is malformed.`);
  return key;
}

export function saveEpochKey(rootDir: string, vaultKey: Buffer, epoch: number, epochKey: Buffer): void {
  if (epochKey.length !== EPOCH_KEY_BYTES) throw new Error("An epoch content key must be 32 bytes.");
  const filePath = epochKeyPath(rootDir, epoch);
  fs.mkdirSync(epochKeyDir(rootDir), { recursive: true, mode: 0o700 });
  writeFileAtomic(
    filePath,
    JSON.stringify(encryptDocument(epochKey.toString("base64"), vaultKey, syncEpochKeyAad(epoch))),
    { mode: 0o600 },
  );
}
```

Move the new `import` statements to the top of the file alongside the existing ones — the block above lists them together only for readability.

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm run build && node --test test/sync-epoch.test.mjs`
Expected: PASS, all six tests.

- [ ] **Step 5: Commit**

```bash
git add src/sync-epoch.ts test/sync-epoch.test.mjs
git commit -m "feat(sync): persist epoch content keys under the vault key"
```

---

### Task 4: Version 2 certificates and registries

**Files:**

- Modify: `src/sync.ts` (types near lines 104-140; `validateCertificate` near line 610; `validateSignedDeviceRegistry` near line 633)
- Test: `test/sync.test.mjs`

**Interfaces:**

- Consumes: `EpochKeyWrap`, `validateEpochKeyWrap`, `agreementPublicKeyFromBase64` (Task 2).
- Produces: `SyncDeviceCertificate` gains `version: 1 | 2` and optional `keyAgreementKey?: string`; `SyncDeviceRegistryBody` gains `version: 1 | 2` and optional `epochKeys?: EpochKeyWrap[]`.

Validation rules added here, all enforced inside `validateSignedDeviceRegistry` so they are checked on every read, import and save:

1. A version 2 certificate must carry `keyAgreementKey`; a version 1 certificate must not.
2. At registry epoch 1, `epochKeys` must be absent.
3. At registry epoch 2 or above, `epochKeys` must be present, sorted by `deviceId`, contain no duplicates, and cover exactly the set of active (non-revoked) device IDs.
4. At registry epoch 2 or above, every active certificate must be version 2 and sit at the registry epoch; every revoked certificate must sit strictly below it.

- [ ] **Step 1: Write the failing test**

Append to `test/sync.test.mjs`:

```js
test("version 2 registries must wrap the epoch key to exactly the active devices", () => {
  const vaultDir = tempVault("registry-v2");
  const manager = new SyncDeviceManager(vaultDir, PASSPHRASE);
  try {
    const registry = manager.initializeOwner("Owner laptop", DEVICE_A);

    // A fresh vault starts at the master-key epoch with no wrapped keys.
    assert.equal(registry.body.version, 1);
    assert.equal(registry.body.epoch, 1);
    assert.equal(registry.body.epochKeys, undefined);

    // Enrollment still issues a version 2 certificate carrying an agreement key.
    const owner = registry.body.devices[0].certificate;
    assert.equal(owner.version, 2);
    assert.equal(Buffer.from(owner.keyAgreementKey, "base64").length, 44);
  } finally {
    manager.close();
  }
});

test("a registry whose epoch keys disagree with its devices is rejected", () => {
  const vaultDir = tempVault("registry-mismatch");
  const manager = new SyncDeviceManager(vaultDir, PASSPHRASE);
  try {
    manager.initializeOwner("Owner laptop", DEVICE_A);
    const request = new SyncDeviceManager(tempVault("registry-peer"), PASSPHRASE);
    let enrollment;
    try {
      enrollment = request.createEnrollmentRequest("Travel laptop", DEVICE_B);
    } finally {
      request.close();
    }
    manager.enroll(enrollment);
    const rotated = manager.revoke(DEVICE_B, 0);

    // Rotation moved to epoch 2 and wrapped the key to the one remaining device.
    assert.equal(rotated.body.version, 2);
    assert.equal(rotated.body.epoch, 2);
    assert.equal(rotated.body.epochKeys.length, 1);
    assert.equal(rotated.body.epochKeys[0].deviceId, DEVICE_A);

    // Adding a wrap for the revoked device breaks the signature, and even a
    // resigned body would fail the coverage rule.
    const forged = structuredClone(rotated);
    forged.body.epochKeys.push({ ...rotated.body.epochKeys[0], deviceId: DEVICE_B });
    assert.throws(() => manager.importRegistry({ version: 1, payload: forged }), /invalid|signature|epoch/iu);
  } finally {
    manager.close();
  }
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm run build && node --test test/sync.test.mjs`
Expected: FAIL — `owner.version` is `1` and `keyAgreementKey` is `undefined`; `manager.revoke` does not rotate.

- [ ] **Step 3: Extend the types**

In `src/sync.ts`, change the two interfaces:

```ts
export interface SyncDeviceCertificate {
  version: 1 | 2;
  serial: number;
  deviceId: string;
  name: string;
  publicKey: string;
  /** base64 X25519 SPKI DER. Present on version 2 certificates only. */
  keyAgreementKey?: string;
  enrolledAt: string;
  epoch: number;
}

export interface SyncDeviceRegistryBody {
  version: 1 | 2;
  revision: number;
  epoch: number;
  authorityPublicKey: string;
  updatedAt: string;
  legacyChangeIds: string[];
  devices: SyncDeviceRecord[];
  /** Present at epoch 2 and above: one wrap per active device. */
  epochKeys?: EpochKeyWrap[];
}
```

Add the import:

```ts
import {
  agreementPublicKeyFromBase64,
  validateEpochKeyWrap,
  type EpochKeyWrap,
} from "./sync-epoch.js";
```

- [ ] **Step 4: Extend certificate validation**

Replace the body of `validateCertificate` in `src/sync.ts`:

```ts
function validateCertificate(value: unknown): SyncDeviceCertificate {
  const certificate = value as SyncDeviceCertificate | undefined;
  if (
    !certificate ||
    typeof certificate !== "object" ||
    Array.isArray(certificate) ||
    (certificate.version !== 1 && certificate.version !== 2)
  ) {
    throw new Error("Unsupported or invalid sync device certificate.");
  }
  if (typeof certificate.deviceId !== "string" || !DEVICE_ID.test(certificate.deviceId)) {
    throw new Error("Certificate device ID must be a lowercase UUID.");
  }
  const normalized: SyncDeviceCertificate = {
    version: certificate.version,
    serial: integer(certificate.serial, 1, "Device certificate serial"),
    deviceId: certificate.deviceId,
    name: deviceName(certificate.name),
    publicKey: canonicalBase64(certificate.publicKey, 44, "certificate public key"),
    enrolledAt: canonicalTimestamp(certificate.enrolledAt, "Device enrollment time"),
    epoch: integer(certificate.epoch, 1, "Device certificate epoch"),
  };
  if (certificate.version === 2) {
    // Validated as X25519 rather than by length: Ed25519 SPKI is also 44 bytes.
    agreementPublicKeyFromBase64(certificate.keyAgreementKey, "Certificate key agreement key");
    normalized.keyAgreementKey = certificate.keyAgreementKey;
  } else if (certificate.keyAgreementKey !== undefined) {
    throw new Error("A version 1 device certificate cannot carry a key agreement key.");
  }
  return normalized;
}
```

Note the field order in `normalized`: `canonicalSyncJson` sorts object keys before signing, so declaration order does not affect signatures.

- [ ] **Step 5: Extend registry validation**

In `validateSignedDeviceRegistry`, change the version guard from `raw.version !== 1` to `raw.version !== 1 && raw.version !== 2`, set `version: raw.version` in the constructed `body`, and replace the trailing epoch loop with the full rule set:

```ts
  if (raw.version === 2) {
    if (!Array.isArray(raw.epochKeys)) throw new Error("A version 2 device registry must list epoch keys.");
    body.epochKeys = raw.epochKeys.map((wrap) => validateEpochKeyWrap(wrap));
  } else if (raw.epochKeys !== undefined) {
    throw new Error("A version 1 device registry cannot carry epoch keys.");
  }

  const active = devices.filter((record) => !record.revokedAt);
  for (const record of devices) {
    if (record.certificate.epoch > body.epoch) {
      throw new Error("A device certificate cannot target a future registry epoch.");
    }
  }

  if (body.epoch === 1) {
    if (body.epochKeys !== undefined) {
      throw new Error("Epoch 1 is sealed with the vault key and carries no wrapped epoch keys.");
    }
  } else {
    if (body.version !== 2 || !body.epochKeys) {
      throw new Error("A registry at epoch 2 or above must be version 2 and carry epoch keys.");
    }
    for (const record of active) {
      if (record.certificate.version !== 2) {
        throw new Error("An active device at epoch 2 or above needs a version 2 certificate.");
      }
      if (record.certificate.epoch !== body.epoch) {
        throw new Error("An active device certificate must sit at the current registry epoch.");
      }
    }
    for (const record of devices) {
      if (record.revokedAt && record.certificate.epoch >= body.epoch) {
        throw new Error("A revoked device certificate must sit below the current registry epoch.");
      }
    }
    const wrapped = body.epochKeys.map((wrap) => wrap.deviceId);
    const expected = active.map((record) => record.certificate.deviceId).sort();
    if (new Set(wrapped).size !== wrapped.length) {
      throw new Error("Registry epoch keys must not repeat a device.");
    }
    if ([...wrapped].sort().some((id, index) => id !== wrapped[index])) {
      throw new Error("Registry epoch keys must be sorted by device ID.");
    }
    if (wrapped.length !== expected.length || expected.some((id, index) => id !== wrapped[index])) {
      throw new Error("Registry epoch keys must cover exactly the active devices.");
    }
  }
```

Place this block immediately before the `const signature = verifyCanonical(...)` line so the signature is verified over the fully normalized body.

- [ ] **Step 6: Run the tests**

Run: `npm run build && node --test test/sync.test.mjs`
Expected: the first new test still FAILS on `owner.version` (enrollment does not yet issue version 2 certificates — that is Task 5) and the second still FAILS on rotation (Task 6). Every pre-existing test must PASS. If a pre-existing test fails, the validation rules are rejecting a shape that used to be legal — fix the rule, not the test.

- [ ] **Step 7: Commit**

```bash
git add src/sync.ts test/sync.test.mjs
git commit -m "feat(sync): validate version 2 device certificates and epoch key coverage"
```

---

### Task 5: Enrollment issues agreement keys

**Files:**

- Modify: `src/sync.ts` (`initializeOwner` near line 1046, `createEnrollmentRequest` near line 1098, `enroll` near line 1131, `validateEnrollmentRequest` near line 572, `SyncEnrollmentRequest` near line 94)
- Test: `test/sync.test.mjs`

**Interfaces:**

- Consumes: `generateAgreementKeyPair`, `exportAgreementPublicKey`, `agreementPrivateKeyFromBase64` (Task 2); `syncAgreementKeyAad` (Task 1).
- Produces: `SyncEnrollmentRequest` gains `version: 1 | 2` and optional `keyAgreementKey?: string`. A new private helper `agreementKeyPath(rootDir, deviceId): string` resolving `sync/identity/<deviceId>.x25519.key.enc`, and `readAgreementKey(rootDir, vaultKey, deviceId): crypto.KeyObject`.

Every newly enrolled device — including the owner's first device — gets an X25519 pair and a version 2 certificate. The registry stays version 1 at epoch 1, because it has no epoch keys to carry yet; it becomes version 2 on first rotation. A version 1 request from an older build is still accepted and yields a version 1 certificate, which can never become active at epoch 2 or above and so is refused a wrap — that is the correct outcome, and `sync devices list` will show it.

- [ ] **Step 1: Write the failing test**

Append to `test/sync.test.mjs`:

```js
test("enrollment stores an X25519 agreement key that never leaves the device", () => {
  const ownerVault = tempVault("agreement-owner");
  const peerVault = tempVault("agreement-peer");
  const owner = new SyncDeviceManager(ownerVault, PASSPHRASE);
  const peer = new SyncDeviceManager(peerVault, PASSPHRASE);
  try {
    owner.initializeOwner("Owner laptop", DEVICE_A);
    const request = peer.createEnrollmentRequest("Travel laptop", DEVICE_B);

    assert.equal(request.version, 2);
    assert.equal(Buffer.from(request.keyAgreementKey, "base64").length, 44);

    const registry = owner.enroll(request);
    const enrolled = registry.body.devices.find((record) => record.certificate.deviceId === DEVICE_B);
    assert.equal(enrolled.certificate.version, 2);
    assert.equal(enrolled.certificate.keyAgreementKey, request.keyAgreementKey);

    // The private half stays on the requesting device and is stored encrypted.
    const keyFile = path.join(peerVault, "documents", "sync", "identity", `${DEVICE_B}.x25519.key.enc`);
    assert.ok(fs.existsSync(keyFile), "the agreement private key is written locally");
    assert.doesNotMatch(fs.readFileSync(keyFile, "utf8"), /-----BEGIN/u, "it is stored as ciphertext");

    // It is absent from everything the owner ever sends.
    assert.doesNotMatch(JSON.stringify(owner.exportRegistry()), new RegExp(DEVICE_B, "u"));
  } finally {
    owner.close();
    peer.close();
  }
});
```

The final assertion holds because the exported registry is a single encrypted payload, so no device ID appears in its serialized form.

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm run build && node --test test/sync.test.mjs --test-name-pattern="agreement key"`
Expected: FAIL — `request.version` is `1` and `keyAgreementKey` is `undefined`.

- [ ] **Step 3: Extend the request type and its validation**

In `src/sync.ts`, change `SyncEnrollmentRequest.version` to `1 | 2` and add `keyAgreementKey?: string`. In `validateEnrollmentRequest`, accept either version, and when the version is 2 require the agreement key:

```ts
  if (request.version === 2) {
    agreementPublicKeyFromBase64(request.keyAgreementKey, "Enrollment key agreement key");
    normalized.keyAgreementKey = request.keyAgreementKey;
  } else if (request.keyAgreementKey !== undefined) {
    throw new Error("A version 1 enrollment request cannot carry a key agreement key.");
  }
```

The proof-of-possession signature already covers the whole unsigned request through `enrollmentRequestPayload`, so the agreement key is authenticated by the existing Ed25519 proof with no change to the signing code.

- [ ] **Step 4: Add the agreement key path helpers**

Add next to `deviceKeyPath` in `src/sync.ts`:

```ts
function agreementKeyPath(rootDir: string, deviceId: string): string {
  if (!DEVICE_ID.test(deviceId)) throw new Error("Sync device ID must be a lowercase UUID.");
  return resolveInside(identityDir(rootDir), `${deviceId}.x25519.key.enc`);
}

function readAgreementKey(rootDir: string, vaultKey: Buffer, deviceId: string): crypto.KeyObject {
  const filePath = agreementKeyPath(rootDir, deviceId);
  if (!fs.existsSync(filePath)) {
    throw new Error(`This device has no sync key agreement key; re-enroll device ${deviceId}.`);
  }
  assertNotSymlink(filePath);
  const payload = JSON.parse(
    readTextFileLimited(filePath, 64 * 1024, "Sync device agreement key"),
  ) as DocumentPayload;
  return agreementPrivateKeyFromBase64(
    decryptDocument(payload, vaultKey, syncAgreementKeyAad(deviceId)),
    "Sync device agreement key",
  );
}

function saveAgreementKey(
  rootDir: string,
  vaultKey: Buffer,
  deviceId: string,
  key: crypto.KeyObject,
): void {
  writeFileAtomic(
    agreementKeyPath(rootDir, deviceId),
    JSON.stringify(
      encryptDocument(
        key.export({ format: "der", type: "pkcs8" }).toString("base64"),
        vaultKey,
        syncAgreementKeyAad(deviceId),
      ),
    ),
    { mode: 0o600 },
  );
}
```

- [ ] **Step 5: Generate agreement keys during enrollment**

In `initializeOwner`, after `const device = crypto.generateKeyPairSync("ed25519");` add:

```ts
      const agreement = generateAgreementKeyPair();
```

change the certificate literal to:

```ts
      const certificate: SyncDeviceCertificate = {
        version: 2,
        serial: 1,
        deviceId,
        name: deviceName(name),
        publicKey: exportPublicKey(device.publicKey),
        keyAgreementKey: exportAgreementPublicKey(agreement.publicKey),
        enrolledAt: normalizedTime,
        epoch: 1,
      };
```

and after the existing `savePrivateKey(deviceKeyPath(...))` call add:

```ts
      saveAgreementKey(this.session.rootDir, this.key(), deviceId, agreement.privateKey);
```

In `createEnrollmentRequest`, after `const pair = crypto.generateKeyPairSync("ed25519");` add `const agreement = generateAgreementKeyPair();`, set `version: 2` and `keyAgreementKey: exportAgreementPublicKey(agreement.publicKey)` in the `unsigned` object, and after the existing `savePrivateKey` call add `saveAgreementKey(this.session.rootDir, this.key(), deviceId, agreement.privateKey);`.

In `enroll`, build the certificate from the request's version:

```ts
      const certificate: SyncDeviceCertificate = {
        version: request.version,
        serial: Math.max(0, ...registry.body.devices.map((record) => record.certificate.serial)) + 1,
        deviceId: request.deviceId,
        name: request.name,
        publicKey: request.publicKey,
        enrolledAt: canonicalTimestamp(now, "Device enrollment time"),
        epoch: registry.body.epoch,
      };
      if (request.version === 2) certificate.keyAgreementKey = request.keyAgreementKey;
```

- [ ] **Step 6: Run the tests**

Run: `npm run build && node --test test/sync.test.mjs`
Expected: the agreement-key test PASSES, the first registry-v2 test PASSES, every pre-existing test PASSES. The rotation test from Task 4 still FAILS.

- [ ] **Step 7: Commit**

```bash
git add src/sync.ts test/sync.test.mjs
git commit -m "feat(sync): issue X25519 agreement keys during device enrollment"
```

---

### Task 6: Epoch-aware change envelopes

**Files:**

- Modify: `src/sync.ts` (`EncryptedSyncChange` near line 84, `changeId`/`changeEncryptionKey`/`sealSyncChange` near lines 417-442, `validateEnvelope` near line 457, `openSyncChange` near line 1391)
- Test: `test/sync.test.mjs`

**Interfaces:**

- Consumes: `AAD` (Task 1).
- Produces:
  - `EncryptedSyncChange` gains `version: 1 | 2` and optional `epoch?: number`.
  - `type SyncEpochKeyResolver = (epoch: number) => Buffer`
  - `sealSyncChange(body: SyncChangeBody, key: Buffer, epoch?: number): EncryptedSyncChange` — `epoch` omitted or `1` produces a version 1 envelope sealed with the vault key, exactly as today; `epoch >= 2` produces a version 2 envelope and `key` is that epoch's content key.
  - `openSyncChange(value: unknown, key: Buffer | SyncEpochKeyResolver): SyncChange` — a `Buffer` continues to mean the vault key and opens version 1 envelopes only; a resolver opens both.

Keeping both existing exported signatures working is deliberate: `test/sync.test.mjs` and `scripts/sync-recovery-drill.mjs` call them with a plain key and must not need editing.

- [ ] **Step 1: Write the failing test**

Append to `test/sync.test.mjs`:

```js
test("version 1 and version 2 envelopes coexist and are keyed differently", () => {
  const vaultDir = tempVault("envelope-v2");
  const session = openDocumentKey(vaultDir, PASSPHRASE);
  const epochKey = Buffer.alloc(32, 9);
  const body = {
    version: 1,
    deviceId: DEVICE_A,
    sequence: 1,
    previousDeviceChange: null,
    parents: [],
    createdAt: "2026-09-03T08:30:00.000Z",
    mutation: noteMutation(null, 1, "private body"),
  };

  const legacy = sealSyncChange(body, session.key);
  assert.equal(legacy.version, 1);
  assert.equal(legacy.epoch, undefined);

  const rotated = sealSyncChange(body, epochKey, 2);
  assert.equal(rotated.version, 2);
  assert.equal(rotated.epoch, 2);

  // The same body under a different epoch key is a different change ID.
  assert.notEqual(legacy.id, rotated.id);

  const resolver = (epoch) => (epoch === 1 ? session.key : epochKey);
  assert.equal(openSyncChange(legacy, resolver).mutation.value.body, "private body");
  assert.equal(openSyncChange(rotated, resolver).mutation.value.body, "private body");

  // A bare vault key still opens version 1 and now refuses version 2.
  assert.equal(openSyncChange(legacy, session.key).sequence, 1);
  assert.throws(() => openSyncChange(rotated, session.key), /epoch/iu);

  // Neither envelope leaks plaintext.
  assert.doesNotMatch(JSON.stringify(rotated), /private body/u);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm run build && node --test test/sync.test.mjs --test-name-pattern="coexist"`
Expected: FAIL — `sealSyncChange` ignores its third argument and `rotated.version` is `1`.

- [ ] **Step 3: Extend the envelope type and sealing**

In `src/sync.ts`:

```ts
export interface EncryptedSyncChange {
  version: 1 | 2;
  id: string;
  /** Present on version 2 envelopes only; always 2 or greater. */
  epoch?: number;
  payload: DocumentPayload;
}

/** Resolves an epoch number to its content key. Epoch 1 resolves to the vault key. */
export type SyncEpochKeyResolver = (epoch: number) => Buffer;
```

Replace `changeId` and `changeEncryptionKey` so the domain string carries the envelope version, keeping version 1 byte-identical:

```ts
function changeId(body: SyncChangeBody, key: Buffer, epoch: number): string {
  return crypto
    .createHmac("sha256", key)
    .update(AAD.syncChangeId)
    .update("\0")
    .update(epoch === 1 ? "" : `${epoch}\0`)
    .update(canonicalSyncJson(body as unknown as SyncJson))
    .digest("hex");
}

function changeEncryptionKey(key: Buffer, id: string, epoch: number): Buffer {
  return crypto
    .createHmac("sha256", key)
    .update(epoch === 1 ? AAD.syncChangeKey : AAD.syncChangeKeyV2)
    .update("\0")
    .update(id)
    .digest();
}
```

Replace `sealSyncChange`:

```ts
export function sealSyncChange(body: SyncChangeBody, key: Buffer, epoch = 1): EncryptedSyncChange {
  if (!Number.isSafeInteger(epoch) || epoch < 1) throw new Error("A sync epoch must be a positive integer.");
  const normalized = validateSyncChangeBody(body);
  const canonical = canonicalSyncJson(normalized as unknown as SyncJson);
  const id = changeId(normalized, key, epoch);
  const envelopeKey = changeEncryptionKey(key, id, epoch);
  try {
    const payload = encryptDocument(canonical, envelopeKey, syncChangeAad(id));
    return epoch === 1 ? { version: 1, id, payload } : { version: 2, id, epoch, payload };
  } finally {
    envelopeKey.fill(0);
  }
}
```

- [ ] **Step 4: Extend envelope validation and opening**

In `validateEnvelope`, accept both versions and validate `epoch`:

```ts
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope) || (envelope.version !== 1 && envelope.version !== 2)) {
    throw new Error("Unsupported or invalid encrypted sync envelope.");
  }
  if (envelope.version === 2) {
    if (!Number.isSafeInteger(envelope.epoch) || (envelope.epoch as number) < 2) {
      throw new Error("A version 2 sync envelope must declare an epoch of 2 or above.");
    }
  } else if (envelope.epoch !== undefined) {
    throw new Error("A version 1 sync envelope cannot declare an epoch.");
  }
```

Replace `openSyncChange`:

```ts
export function openSyncChange(value: unknown, key: Buffer | SyncEpochKeyResolver): SyncChange {
  const envelope = validateEnvelope(value);
  const epoch = envelope.version === 2 ? envelope.epoch! : 1;
  let contentKey: Buffer;
  if (typeof key === "function") {
    contentKey = key(epoch);
  } else {
    if (epoch !== 1) {
      throw new Error(`Opening an epoch ${epoch} sync change requires an epoch key resolver.`);
    }
    contentKey = key;
  }
  const envelopeKey = changeEncryptionKey(contentKey, envelope.id, epoch);
  let plaintext: string;
  try {
    plaintext = decryptDocument(envelope.payload, envelopeKey, syncChangeAad(envelope.id));
  } finally {
    envelopeKey.fill(0);
  }
  if (Buffer.byteLength(plaintext, "utf8") > MAX_CHANGE_BYTES) throw new Error("Sync change exceeds 8 MiB.");
  const body = validateSyncChangeBody(JSON.parse(plaintext));
  const actual = Buffer.from(changeId(body, contentKey, epoch), "hex");
  const expected = Buffer.from(envelope.id, "hex");
  if (!crypto.timingSafeEqual(actual, expected)) throw new Error("Sync change ID does not match its content.");
  if (plaintext !== canonicalSyncJson(body as unknown as SyncJson)) {
    throw new Error("Sync change plaintext is not canonically encoded.");
  }
  return { id: envelope.id, ...body };
}
```

Update the ciphertext-length guard in `validateEnvelope` and `validateRelayEnvelope`'s doc comment only if they mention version 1 explicitly; the size limits are unchanged.

- [ ] **Step 5: Run the tests**

Run: `npm run build && node --test test/sync.test.mjs test/sync-relay.test.mjs`
Expected: the coexistence test PASSES; every pre-existing test PASSES because version 1 sealing and opening are byte-identical.

- [ ] **Step 6: Commit**

```bash
git add src/sync.ts test/sync.test.mjs
git commit -m "feat(sync): add epoch-sealed version 2 change envelopes"
```

---

### Task 7: Rotation on revocation

**Files:**

- Modify: `src/sync.ts` (`SyncDeviceManager.revoke` near line 1177; `SyncChangeLog` near lines 1689-1870)
- Test: `test/sync.test.mjs`

**Interfaces:**

- Consumes: everything from Tasks 2-6.
- Produces:
  - `SyncDeviceManager.revoke(deviceId, revokedAfterSequence, now?)` now rotates as part of the same signed revision.
  - `SyncChangeLog` gains a private `epochResolver(): SyncEpochKeyResolver` and uses it wherever it currently passes `this.key()` to `openSyncChange`, and seals new changes at the registry's current epoch.

- [ ] **Step 1: Write the failing test**

Append to `test/sync.test.mjs`:

```js
test("revoking a device rotates the epoch and locks it out of later changes", () => {
  const ownerVault = tempVault("rotate-owner");
  const peerVault = tempVault("rotate-peer");
  const owner = new SyncDeviceManager(ownerVault, PASSPHRASE);
  const peer = new SyncDeviceManager(peerVault, PASSPHRASE);
  let registryAfterEnroll;
  try {
    owner.initializeOwner("Owner laptop", DEVICE_A);
    registryAfterEnroll = owner.enroll(peer.createEnrollmentRequest("Travel laptop", DEVICE_B));
    assert.equal(registryAfterEnroll.body.epoch, 1);

    const rotated = owner.revoke(DEVICE_B, 0);
    assert.equal(rotated.body.epoch, 2, "revocation advances the epoch");
    assert.equal(rotated.body.revision, registryAfterEnroll.body.revision + 1, "in one signed revision");

    // Only the remaining device gets a wrap.
    assert.deepEqual(
      rotated.body.epochKeys.map((wrap) => wrap.deviceId),
      [DEVICE_A],
    );

    // The remaining device's certificate was reissued at the new epoch,
    // reusing its existing public keys.
    const before = registryAfterEnroll.body.devices.find((r) => r.certificate.deviceId === DEVICE_A).certificate;
    const after = rotated.body.devices.find((r) => r.certificate.deviceId === DEVICE_A).certificate;
    assert.equal(after.epoch, 2);
    assert.equal(after.publicKey, before.publicKey);
    assert.equal(after.keyAgreementKey, before.keyAgreementKey);

    // The revoked device stays behind at the old epoch.
    const revoked = rotated.body.devices.find((r) => r.certificate.deviceId === DEVICE_B);
    assert.equal(revoked.certificate.epoch, 1);
    assert.ok(revoked.revokedAt);
  } finally {
    owner.close();
    peer.close();
  }
});

test("post-rotation changes are unreadable with the revoked device's epoch keys", () => {
  const vaultDir = tempVault("rotate-readability");
  const manager = new SyncDeviceManager(vaultDir, PASSPHRASE);
  const log = new SyncChangeLog(vaultDir, PASSPHRASE);
  try {
    manager.initializeOwner("Owner laptop", DEVICE_A);
    const peerVault = tempVault("rotate-readability-peer");
    const peer = new SyncDeviceManager(peerVault, PASSPHRASE);
    try {
      manager.enroll(peer.createEnrollmentRequest("Travel laptop", DEVICE_B));
    } finally {
      peer.close();
    }

    const before = log.append(DEVICE_A, noteMutation(null, 1, "before rotation"));
    assert.equal(before.version, 2, "changes are device-signed once enrolled");

    manager.revoke(DEVICE_B, 0);

    const after = log.append(DEVICE_A, noteMutation(1, 2, "after rotation"));
    const envelopes = log.envelopes();
    const rotatedEnvelope = envelopes.find((envelope) => envelope.id === after.id);
    const legacyEnvelope = envelopes.find((envelope) => envelope.id === before.id);

    assert.equal(rotatedEnvelope.version, 2);
    assert.equal(rotatedEnvelope.epoch, 2);
    assert.equal(legacyEnvelope.version, 1, "pre-rotation changes keep their epoch 1 sealing");

    // Holding only the vault key — which a revoked device still has — is no
    // longer enough for the post-rotation change.
    const session = openDocumentKey(vaultDir, PASSPHRASE);
    assert.doesNotThrow(() => openSyncChange(legacyEnvelope, session.key));
    assert.throws(() => openSyncChange(rotatedEnvelope, session.key), /epoch/iu);

    // The whole log still verifies on the device that holds the epoch key.
    assert.equal(log.verify().heads.length, 1);
  } finally {
    log.close();
    manager.close();
  }
});

test("revoking the last active device is refused", () => {
  const vaultDir = tempVault("rotate-last");
  const manager = new SyncDeviceManager(vaultDir, PASSPHRASE);
  try {
    manager.initializeOwner("Owner laptop", DEVICE_A);
    assert.throws(() => manager.revoke(DEVICE_A, 0), /last active sync device/u);
  } finally {
    manager.close();
  }
});

test("a checkpoint created before rotation still verifies afterwards", () => {
  const vaultDir = tempVault("rotate-checkpoint");
  const manager = new SyncDeviceManager(vaultDir, PASSPHRASE);
  const log = new SyncChangeLog(vaultDir, PASSPHRASE);
  try {
    manager.initializeOwner("Owner laptop", DEVICE_A);
    const peerVault = tempVault("rotate-checkpoint-peer");
    const peer = new SyncDeviceManager(peerVault, PASSPHRASE);
    try {
      manager.enroll(peer.createEnrollmentRequest("Travel laptop", DEVICE_B));
    } finally {
      peer.close();
    }
    log.append(DEVICE_A, noteMutation(null, 1, "checkpointed"));
    const checkpoint = manager.createCheckpoint(log.changes());

    manager.revoke(DEVICE_B, 0);
    log.append(DEVICE_A, noteMutation(1, 2, "after rotation"));

    const verified = manager.verifyCheckpoint(log.changes());
    assert.equal(verified.id, checkpoint.id, "the pinned checkpoint survives an epoch bump");
  } finally {
    log.close();
    manager.close();
  }
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npm run build && node --test test/sync.test.mjs --test-name-pattern="rotat"`
Expected: FAIL — `rotated.body.epoch` is `1`.

- [ ] **Step 3: Implement rotation in `revoke`**

Replace the body of `SyncDeviceManager.revoke` in `src/sync.ts`:

```ts
  revoke(deviceId: string, revokedAfterSequence: number, now = new Date().toISOString()): SignedSyncDeviceRegistry {
    return withVaultLock(this.vaultDir, () => {
      const registry = readDeviceRegistry(this.session.rootDir, this.key());
      if (!registry) throw new Error("Sync device enrollment is not initialized.");
      const record = registry.body.devices.find((candidate) => candidate.certificate.deviceId === deviceId);
      if (!record) throw new Error(`Sync device ${deviceId} is not enrolled.`);
      if (record.revokedAt) throw new Error(`Sync device ${deviceId} is already revoked.`);
      const remaining = registry.body.devices.filter(
        (candidate) => !candidate.revokedAt && candidate.certificate.deviceId !== deviceId,
      );
      if (remaining.length === 0) {
        throw new Error(
          "Refusing to revoke the last active sync device: the new epoch key would reach nobody and the log could not be extended.",
        );
      }
      for (const candidate of remaining) {
        if (candidate.certificate.version !== 2 || !candidate.certificate.keyAgreementKey) {
          throw new Error(
            `Sync device ${candidate.certificate.deviceId} predates key agreement; re-enroll it before revoking another device.`,
          );
        }
      }

      const cutoff = integer(revokedAfterSequence, 0, "Device revocation sequence");
      const authorityKey = readPrivateKey(
        authorityKeyPath(this.session.rootDir),
        this.key(),
        AAD.syncAuthorityKey,
        "Sync enrollment authority private key",
      );
      const revokedAt = canonicalTimestamp(now, "Device revocation time");
      const epoch = registry.body.epoch + 1;
      const epochKey = crypto.randomBytes(EPOCH_KEY_BYTES);

      try {
        // Reissue the remaining devices at the new epoch, reusing their keys,
        // and wrap the fresh content key to those devices only.
        const devices: SyncDeviceRecord[] = registry.body.devices.map((candidate) => {
          if (candidate.certificate.deviceId === deviceId) {
            return { ...candidate, revokedAt, revokedAfterSequence: cutoff };
          }
          if (candidate.revokedAt) return candidate;
          const certificate: SyncDeviceCertificate = { ...candidate.certificate, epoch };
          return {
            ...candidate,
            certificate,
            certificateSignature: signCanonical(certificatePayload(certificate), authorityKey),
          };
        });
        const epochKeys = remaining
          .map((candidate) =>
            wrapEpochKey(
              epochKey,
              epoch,
              candidate.certificate.deviceId,
              agreementPublicKeyFromBase64(candidate.certificate.keyAgreementKey, "Certificate key agreement key"),
            ),
          )
          .sort((left, right) => left.deviceId.localeCompare(right.deviceId));

        const next = signRegistryBody(
          {
            ...registry.body,
            version: 2,
            revision: registry.body.revision + 1,
            epoch,
            updatedAt: revokedAt,
            devices,
            epochKeys,
          },
          authorityKey,
        );
        // Persist the key before the registry: a crash between the two leaves a
        // recoverable key with no registry referencing it, rather than a
        // registry naming an epoch this device cannot open.
        saveEpochKey(this.session.rootDir, this.key(), epoch, epochKey);
        saveDeviceRegistry(this.session.rootDir, this.key(), next);
        return structuredClone(next);
      } finally {
        epochKey.fill(0);
      }
    });
  }
```

Add to the imports from `./sync-epoch.js`: `EPOCH_KEY_BYTES`, `readEpochKey`, `saveEpochKey`, `wrapEpochKey`, `unwrapEpochKey`.

- [ ] **Step 4: Teach `importRegistry` to adopt an incoming epoch key**

A second device learns the new epoch key when it imports the rotated registry. In `importRegistry`, immediately before the existing `saveDeviceRegistry(...)` call, add:

```ts
      // Adopt the epoch key wrapped to whichever local device this vault holds.
      if (incoming.body.epoch > 1 && incoming.body.epochKeys) {
        for (const wrap of incoming.body.epochKeys) {
          if (readEpochKey(this.session.rootDir, this.key(), incoming.body.epoch)) break;
          if (!fs.existsSync(agreementKeyPath(this.session.rootDir, wrap.deviceId))) continue;
          const privateKey = readAgreementKey(this.session.rootDir, this.key(), wrap.deviceId);
          const epochKey = unwrapEpochKey(wrap, incoming.body.epoch, wrap.deviceId, privateKey);
          try {
            saveEpochKey(this.session.rootDir, this.key(), incoming.body.epoch, epochKey);
          } finally {
            epochKey.fill(0);
          }
          break;
        }
      }
```

A device with no matching wrap installs the registry and simply cannot open changes from that epoch — which is exactly the revoked device's experience.

- [ ] **Step 5: Make the change log epoch-aware**

In `SyncChangeLog`, add the resolver and use it everywhere a change is opened:

```ts
  private epochResolver(): SyncEpochKeyResolver {
    const vaultKey = this.key();
    const rootDir = this.session.rootDir;
    return (epoch: number): Buffer => {
      if (epoch === 1) return vaultKey;
      const key = readEpochKey(rootDir, vaultKey, epoch);
      if (!key) {
        throw new Error(
          `This device holds no content key for sync epoch ${epoch}; import the owner-signed registry that rotated to it.`,
        );
      }
      return key;
    };
  }
```

Replace every `openSyncChange(envelope, this.key())` in `SyncChangeLog` — in `changes()`, `envelopes()` and `storeEnvelope()` — with `openSyncChange(envelope, this.epochResolver())`. Do the same for the standalone `enrollmentLegacyChanges` helper, which must keep using the plain vault key: leave it unchanged, because by definition it runs before any enrollment exists and therefore before any rotation.

In `append()`, seal at the registry's current epoch:

```ts
      const epoch = registry?.body.epoch ?? 1;
      const contentKey = epoch === 1 ? this.key() : this.epochResolver()(epoch);
      const envelope = sealSyncChange(body, contentKey, epoch);
      const change = openSyncChange(envelope, this.epochResolver());
```

- [ ] **Step 6: Run the full sync suite**

Run: `npm run build && node --test test/sync.test.mjs test/sync-epoch.test.mjs test/sync-relay.test.mjs`
Expected: PASS, including all four new rotation tests.

- [ ] **Step 7: Run the recovery drill**

Run: `npm run recovery:drill`
Expected: the drill completes. It exercises backup plus relay catch-up, which now has to carry epoch keys through a restore.

- [ ] **Step 8: Commit**

```bash
git add src/sync.ts test/sync.test.mjs
git commit -m "feat(sync): rotate the epoch content key when a device is revoked"
```

---

### Task 8: Surface the epoch in the CLI and documentation

**Files:**

- Create: `test/cli.test.mjs`
- Modify: `src/cli.ts` (`sync devices list` near line 828, `sync devices revoke` near line 887), `README.md`, `docs/ARCHITECTURE.md`, `package.json` (register the new test file)

**Interfaces:**

- Consumes: the rotated registry shape from Task 7.
- Produces: no new exports; CLI output only. Also produces the project's first CLI process harness, `runCli(args, env)`, reused by Task 9.

No existing test spawns the CLI — `test/workflows.test.mjs` exercises the library directly and has no `runCli` helper. This task adds a small one rather than asserting on CLI behaviour indirectly.

- [ ] **Step 1: Write the failing test**

Create `test/cli.test.mjs`:

```js
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const DEVICE_A = "11111111-1111-4111-8111-111111111111";

/** Runs the built CLI and returns stdout. Throws on a non-zero exit. */
function runCli(args, env = {}) {
  return execFileSync(process.execPath, ["dist/cli.js", ...args], {
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
}

function tempVault(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `secondbrain-cli-${label}-`));
}

test("sync devices list reports the active epoch and per-device state", () => {
  const vaultDir = tempVault("epoch");
  const env = { SBRAIN_PASSPHRASE: "cli-epoch-test-passphrase" };
  const flags = ["--vault", vaultDir, "--experimental-trusted-sync"];

  runCli([...flags, "sync", "devices", "init", "Owner laptop", "--device-id", DEVICE_A], env);
  const listed = runCli([...flags, "sync", "devices", "list"], env);

  assert.match(listed, /epoch 1/u, "the header names the active epoch");
  assert.match(listed, new RegExp(`${DEVICE_A}.*epoch=1.*active`, "u"), "each row carries its epoch and state");
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm run build && node --test test/cli.test.mjs`
Expected: FAIL — the output has no epoch text.

- [ ] **Step 3: Update the CLI output**

In `src/cli.ts`, in `sync devices list`, change the header and row lines:

```ts
      console.log(
        `Authority ${manager.fingerprint()} — registry revision ${registry.body.revision}, epoch ${registry.body.epoch}`,
      );
      for (const record of registry.body.devices) {
        const state = record.revokedAt ? `revoked-after=${record.revokedAfterSequence}` : "active";
        console.log(
          `${record.certificate.deviceId}  ${record.certificate.name}  serial=${record.certificate.serial}  epoch=${record.certificate.epoch}  ${state}`,
        );
      }
```

In `sync devices revoke`, report the rotation:

```ts
      const registry = manager.revoke(deviceId, cutoff);
      console.log(
        `Revoked ${deviceId} after sequence ${cutoff}; registry revision ${registry.body.revision}, rotated to epoch ${registry.body.epoch}.`,
      );
      console.log(
        "Export the registry to every remaining device so they adopt the new epoch key; changes written before this rotation stay readable to the revoked device.",
      );
```

- [ ] **Step 4: Update the honesty notes**

In `README.md`, in the "Encrypted sync protocol" section, replace the sentence listing deferred work — currently "larger blob transport, epoch content-key rotation, independently witnessed freshness and mobile clients remain Phase 6 work" — with:

```markdown
Revoking a device rotates the content key: the registry advances to a new epoch,
a fresh random content key is wrapped to each remaining device's X25519 key, and
the revoked device receives no wrap. Rotation is forward-only. A revoked device
keeps the epoch keys it already held and can still decrypt every change written
before the rotation; what it loses is everything written afterwards, including
whatever the relay accumulates from then on. Recovering historical plaintext
still only takes the passphrase and an encrypted vault backup — the passphrase
remains the security boundary. Larger blob transport, independently witnessed
freshness and mobile clients remain Phase 6 work.
```

Add the same forward-only caveat as a bullet in the README "Threat model / honesty notes" list.

In `docs/ARCHITECTURE.md`, add a paragraph after the existing checkpoint description describing the epoch key hierarchy and the wrap construction, matching the spec's "Key hierarchy" and "Distribution" sections.

- [ ] **Step 5: Register the test file and run the quality gate**

In `package.json`, add `test/cli.test.mjs` to the `test` script's file list.

Run: `npm run build && node --test test/cli.test.mjs`
Expected: PASS.

Run: `npm run quality`
Expected: PASS. This is the first full gate for Part B.

- [ ] **Step 6: Commit**

```bash
git add src/cli.ts test/cli.test.mjs package.json README.md docs/ARCHITECTURE.md
git commit -m "feat(cli): report the sync epoch and document forward-only rotation"
```

---

## Part C — Stable 1.0 format

### Task 9: Format inspection command

**Files:**

- Modify: `src/cli.ts`
- Test: `test/cli.test.mjs`

**Interfaces:**

- Consumes: `VAULT_FORMAT_VERSION`, `FORMAT_COMPATIBILITY` (Task 1); `runCli` from `test/cli.test.mjs` (Task 8).
- Produces: `sbrain format` printing a JSON version matrix.

- [ ] **Step 1: Write the failing test**

Append to `test/cli.test.mjs`:

```js
test("sbrain format prints the frozen version matrix", () => {
  const output = JSON.parse(runCli(["format"]));
  assert.equal(output.formatVersion, "1.0");
  assert.deepEqual(output.artifacts.encryptedEnvelope, {
    path: "*.kv.enc",
    reads: [0, 1],
    writes: [1],
  });
  assert.deepEqual(output.artifacts.syncChangeEnvelope.reads, [1, 2]);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm run build && node --test test/cli.test.mjs --test-name-pattern="version matrix"`
Expected: FAIL — `execFileSync` throws because `format` is an unknown command.

- [ ] **Step 3: Add the command**

In `src/cli.ts`, add the import and the command alongside the other top-level commands:

```ts
import { FORMAT_COMPATIBILITY, VAULT_FORMAT_VERSION } from "./format-version.js";

program
  .command("format")
  .description("print the on-disk format version and the artifact version matrix")
  .action(() => {
    console.log(
      JSON.stringify({ formatVersion: VAULT_FORMAT_VERSION, artifacts: FORMAT_COMPATIBILITY }, null, 2),
    );
  });
```

This command reads no vault and needs no passphrase, so it must not be registered under the `sync` sub-command and must not go through `getPassphrase`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm run build && node --test test/cli.test.mjs`
Expected: PASS, both tests.

- [ ] **Step 5: Commit**

```bash
git add src/cli.ts test/cli.test.mjs
git commit -m "feat(cli): add sbrain format for the on-disk version matrix"
```

---

### Task 10: Conformance fixtures

**Files:**

- Create: `test/fixtures/sync-epoch-v2/**` (generated, then committed)
- Modify: `scripts/make-fixtures.mjs`, `test/format-conformance.test.mjs`, `package.json` (register the test file)

**Interfaces:**

- Consumes: everything built in Parts A and B; `FIXTURE_PASSPHRASE` already exported by `scripts/make-fixtures.mjs`.
- Produces: `writeSyncEpochFixture()` in `scripts/make-fixtures.mjs`, and the committed `test/fixtures/sync-epoch-v2/` vault.

This follows the fixture convention the repository already has, rather than inventing a parallel one. `scripts/make-fixtures.mjs` is the single generator, `FIXTURE_PASSPHRASE = "fixture-only-passphrase"` is shared by every fixture, each format version gets its **own new directory** instead of editing an existing one, and the script regenerates the `test/fixtures/README.md` table itself — so the new row goes in the script's template literal, not in the Markdown file by hand.

The pre-versioning envelope is already pinned by `test/fixtures/kv-envelope-v0/health.kv.enc` and covered by an existing test; this task does not duplicate it.

Fixtures are generated once and committed. Regenerating them to make a failing test pass would defeat their entire purpose — the script's own header already says so.

- [ ] **Step 1: Extend the generator**

In `scripts/make-fixtures.mjs`, add this function alongside the existing `writeCanvasFixture()` and call it from the same place the other writers are called:

```js
/**
 * A vault that has been through one epoch rotation: an owner device, a revoked
 * device, a pre-rotation change sealed at epoch 1 and a post-rotation change
 * sealed with the epoch 2 content key. Pins the version 2 registry and
 * envelope shapes, and the fact that both envelope versions coexist.
 */
function writeSyncEpochFixture() {
  const dir = path.join(fixtures, "sync-epoch-v2");
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });

  const ownerId = "11111111-1111-4111-8111-111111111111";
  const revokedId = "22222222-2222-4222-8222-222222222222";
  const noteId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const mutation = (baseRevision, revision, body) => ({
    objectType: "note",
    objectId: noteId,
    operation: "put",
    baseRevision,
    revision,
    value: { title: "Frozen", body },
  });

  const manager = new SyncDeviceManager(dir, FIXTURE_PASSPHRASE);
  const log = new SyncChangeLog(dir, FIXTURE_PASSPHRASE);
  const peerDir = fs.mkdtempSync(path.join(os.tmpdir(), "secondbrain-fixture-peer-"));
  const peer = new SyncDeviceManager(peerDir, FIXTURE_PASSPHRASE);
  try {
    manager.initializeOwner("Owner laptop", ownerId, "2026-09-03T00:00:00.000Z");
    manager.enroll(peer.createEnrollmentRequest("Travel laptop", revokedId), "2026-09-03T00:00:01.000Z");

    // Sealed at epoch 1 with the vault key.
    log.append(ownerId, mutation(null, 1, "before rotation"), "2026-09-03T00:00:02.000Z");
    manager.createCheckpoint(log.changes(), "2026-09-03T00:00:03.000Z");

    // Revocation rotates to epoch 2 and wraps the new key to the owner only.
    manager.revoke(revokedId, 1, "2026-09-03T00:00:04.000Z");

    // Sealed at epoch 2 with the wrapped content key.
    log.append(ownerId, mutation(1, 2, "after rotation"), "2026-09-03T00:00:05.000Z");
  } finally {
    log.close();
    manager.close();
    peer.close();
    fs.rmSync(peerDir, { recursive: true, force: true });
  }
}
```

Add `import os from "node:os";` and `import { SyncChangeLog, SyncDeviceManager } from "../dist/sync.js";` to the script's imports.

The peer vault is a temporary directory deleted afterwards: it exists only to produce a proof-of-possession enrollment request, and its private identity keys must never be committed.

- [ ] **Step 2: Add the README row**

The script regenerates `test/fixtures/README.md` itself, so the new row goes in that template literal at the end of `scripts/make-fixtures.mjs`, not into the Markdown file by hand. Add it after the `documents-canvas-v1/` row:

```
| \`sync-epoch-v2/\` | sync registry v2, change envelopes v1 and v2 | A rotated vault still opens: epoch 1 changes stay vault-key sealed, epoch 2 changes need the wrapped content key, and the revoked device holds no wrap |
```

- [ ] **Step 3: Generate and inspect**

Run: `npm run fixtures`
Expected: `test/fixtures/sync-epoch-v2/` appears and `test/fixtures/README.md` gains the new row.

Run: `ls test/fixtures/sync-epoch-v2/documents/sync/identity/ && ls test/fixtures/sync-epoch-v2/documents/sync/identity/epochs/`
Expected: the owner's Ed25519 key, the owner's X25519 key and the authority key; under `epochs/`, exactly `2.key.enc`. Confirm no file named for the revoked device ID appears under `epochs/`.

- [ ] **Step 4: Write the conformance test**

Append to `test/format-conformance.test.mjs`:

```js
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { SyncChangeLog, SyncDeviceManager } from "../dist/sync.js";

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures");
const FIXTURE_PASSPHRASE = "fixture-only-passphrase";
const OWNER = "11111111-1111-4111-8111-111111111111";
const REVOKED = "22222222-2222-4222-8222-222222222222";

test("the committed rotated vault still opens both envelope versions", () => {
  const dir = path.join(FIXTURES, "sync-epoch-v2");
  const log = new SyncChangeLog(dir, FIXTURE_PASSPHRASE);
  try {
    const envelopes = log.envelopes().sort((left, right) => left.version - right.version);
    assert.equal(envelopes.length, 2);
    assert.equal(envelopes[0].version, 1);
    assert.equal(envelopes[0].epoch, undefined);
    assert.equal(envelopes[1].version, 2);
    assert.equal(envelopes[1].epoch, 2);

    // Both open on the device that holds the epoch key, and the plaintext is frozen.
    const bodies = log.changes().map((change) => change.mutation.value.body);
    assert.deepEqual(bodies.sort(), ["after rotation", "before rotation"]);
  } finally {
    log.close();
  }
});

test("the committed registry pins the post-rotation shape", () => {
  const dir = path.join(FIXTURES, "sync-epoch-v2");
  const manager = new SyncDeviceManager(dir, FIXTURE_PASSPHRASE);
  try {
    const registry = manager.state();
    assert.equal(registry.body.version, 2);
    assert.equal(registry.body.epoch, 2);

    // The epoch key reaches the owner and nobody else.
    assert.deepEqual(
      registry.body.epochKeys.map((wrap) => wrap.deviceId),
      [OWNER],
    );

    const owner = registry.body.devices.find((record) => record.certificate.deviceId === OWNER);
    const revoked = registry.body.devices.find((record) => record.certificate.deviceId === REVOKED);
    assert.equal(owner.certificate.version, 2);
    assert.equal(owner.certificate.epoch, 2);
    assert.equal(Buffer.from(owner.certificate.keyAgreementKey, "base64").length, 44);
    assert.equal(revoked.certificate.epoch, 1, "the revoked device stays at the old epoch");
    assert.equal(revoked.revokedAfterSequence, 1);
  } finally {
    manager.close();
  }
});

test("the fixture vault caches no epoch key the revoked device could use", () => {
  const epochs = path.join(FIXTURES, "sync-epoch-v2", "documents", "sync", "identity", "epochs");
  assert.deepEqual(fs.readdirSync(epochs), ["2.key.enc"], "only the current epoch key is cached");
});
```

The pre-versioning `.kv` envelope needs no assertion here — `test/fixtures/kv-envelope-v0/` is already covered by the existing migration test, and duplicating it would create a second place to update.

- [ ] **Step 5: Run the conformance suite**

Run: `npm run build && node --test test/format-conformance.test.mjs`
Expected: PASS, all five tests — the two from Task 1 plus these three.

- [ ] **Step 6: Register the test file**

In `package.json`, add `test/format-conformance.test.mjs` to the `test` script's file list.

- [ ] **Step 7: Commit**

```bash
git add scripts/make-fixtures.mjs test/fixtures/sync-epoch-v2 test/fixtures/README.md test/format-conformance.test.mjs package.json
git commit -m "test: pin the rotated sync format with a committed fixture vault"
```


---

### Task 11: The normative format specification

**Files:**

- Create: `docs/FORMAT-1.0.md`
- Modify: `package.json` (version), `README.md`

**Interfaces:**

- Consumes: `FORMAT_COMPATIBILITY` (Task 1) as the source of truth for the version table.
- Produces: documentation only.

- [ ] **Step 1: Write the specification**

Create `docs/FORMAT-1.0.md` covering, in this order:

1. **Status and scope.** Format 1.0 is frozen. It is the on-disk format version, distinct from the product version in `package.json`.
2. **Compatibility policy.** Within 1.x only additive optional fields are permitted. Bumping an artifact version, changing an AAD string, removing a field, or altering a canonical encoding requires 2.0 and a migration path. Reading support for an older version is never dropped inside a major version.
3. **Encodings.** Canonical JSON is RFC 8785-compatible: object keys sorted by code unit, no insignificant whitespace. Canonical base64 means `Buffer.from(v, "base64").toString("base64") === v`. Public keys are base64 SPKI DER, 44 decoded bytes. Private keys are base64 PKCS#8 DER, 48 decoded bytes. Signatures are base64, 64 decoded bytes. Timestamps are ISO 8601 that round-trip exactly through `new Date(t).toISOString()`.
4. **Key derivation.** scrypt with `N` between 2^14 and 2^20 (a power of two), `r` in 1..32, `p` in 1..16, 16-64 byte salt, 32-byte output. Written with `N = 2^16`. The envelope header — version, cipher and KDF parameters — is authenticated as AAD, so a header cannot be rewritten to weaken the next derivation.
5. **Artifact catalogue.** One subsection per entry in `FORMAT_COMPATIBILITY`, each giving the path, the JSON shape with field types, the version field, and the exact AAD string. Copy the AAD values verbatim from `src/format-version.ts`.
6. **Key hierarchy and epochs.** The master key, the identity keys, and the epoch rule: epoch 1 is the master-key epoch with no stored key and no wraps; epochs 2 and above use a random 32-byte content key stored at `documents/sync/identity/epochs/<n>.key.enc` under the master key and wrapped per active device inside the registry. Give the wrap construction exactly as implemented in `src/sync-epoch.ts`: ephemeral X25519, `HKDF-SHA256` with a zero-length salt and info `secondbrain-vault:sync-epoch-wrap:v1:<epoch>:<deviceId>`, then AES-256-GCM with the same string as AAD.
7. **Conformance.** Point at `test/fixtures/` — in particular `sync-epoch-v2/` and `kv-envelope-v0/` — and at `test/format-conformance.test.mjs`, and state that a third-party implementation is conformant when it opens those vaults to the same plaintext.

Every AAD string, size limit and version number must be copied from the code, not recalled. Verify each against `src/format-version.ts` before committing.

- [ ] **Step 2: Separate format version from product version**

In `package.json`, leave `version` at `0.2.0` — the product is pre-1.0 and the external audit gate is not met. In `README.md`, find the `"version": "1.0.0"` at line 353 (inside an example block) and correct it to `0.2.0` so the README does not imply a 1.0 product release. Add a line to the README's sync section: "The on-disk format is frozen at 1.0 — see [`docs/FORMAT-1.0.md`](docs/FORMAT-1.0.md). The product itself remains pre-1.0 pending independent review."

- [ ] **Step 3: Verify the document against the code**

Run: `npm run build && node -e "import('./dist/format-version.js').then(m => console.log(JSON.stringify({ v: m.VAULT_FORMAT_VERSION, aad: m.AAD, compat: m.FORMAT_COMPATIBILITY }, null, 2)))"`
Expected: every AAD string and version list printed here appears verbatim in `docs/FORMAT-1.0.md`. Fix any mismatch in the document.

- [ ] **Step 4: Run the quality gate**

Run: `npm run quality`
Expected: PASS. This is the full gate for Part C.

- [ ] **Step 5: Commit**

```bash
git add docs/FORMAT-1.0.md README.md package.json
git commit -m "docs: freeze and specify the 1.0 on-disk format"
```

---

## Part D — Read-only desktop sync status

### Task 12: Rust sync status commands

**Files:**

- Modify: `src-tauri/src/lib.rs`, `src-tauri/capabilities/main.json`
- Test: `src-tauri/src/lib.rs` (the existing `#[cfg(test)] mod tests` block)

**Interfaces:**

- Consumes: the existing Rust document-key machinery in `lib.rs` (the scrypt derivation near line 792 and the manifest handling near line 1498).
- Produces two Tauri commands:
  - `sync_status(state) -> Result<SyncStatus, String>` where `SyncStatus { enrolled: bool, authority_fingerprint: String, epoch: u64, registry_revision: u64, registry_version: u64, devices: Vec<SyncDeviceSummary>, checkpoint: Option<SyncCheckpointSummary>, change_count: usize, unapplied_count: usize, readable: bool }`
  - `sync_verify_registry(state) -> Result<bool, String>`
  - `SyncDeviceSummary { device_id: String, name: String, serial: u64, epoch: u64, revoked_after_sequence: Option<u64> }`
  - `SyncCheckpointSummary { id: String, sequence: u64, change_count: u64, created_at: String }`

  and the helpers the commands and tests are built on:
  - `load_device_registry(session: &Session) -> Result<Option<SignedDeviceRegistry>, String>` — `Ok(None)` when `documents/sync/devices.enc` does not exist
  - `load_checkpoint(session: &Session) -> Result<Option<SignedCheckpoint>, String>`
  - `count_sync_changes(session: &Session) -> Result<usize, String>`
  - `verify_registry_signature(registry: &SignedDeviceRegistry) -> Result<bool, String>`
  - `registry_is_readable(registry: &SignedDeviceRegistry) -> bool`

Use whatever the existing session type in `lib.rs` is actually called in place of `Session` — `open_session` in the existing fixture test returns it.

`readable` is `false` when the registry parses but declares a version this build does not know; the UI shows "a newer format this build cannot display" rather than an error. The change store is counted by listing `documents/sync/changes/*.change.enc` filenames — no envelope is ever decrypted, no epoch key is ever unwrapped.

- [ ] **Step 1: Write the failing Rust tests**

Add to the `#[cfg(test)] mod tests` block in `src-tauri/src/lib.rs`, following the `an_attachment_written_by_the_typescript_core_still_opens` test immediately above — same `temporary_vault` / `copy_tree` / `open_session` shape, same `"fixture-only-passphrase"`:

```rust
/// The second cross-implementation gate. This registry was written by the
/// TypeScript core after a real rotation. If the Rust core drifts on the
/// canonical JSON encoding, the AAD strings or the SPKI key layout, it can no
/// longer read or verify what the CLI wrote — and this fails.
#[test]
fn a_rotated_registry_written_by_the_typescript_core_still_verifies() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test")
        .join("fixtures")
        .join("sync-epoch-v2");
    assert!(fixture.is_dir(), "missing fixture: {}", fixture.display());

    let path = temporary_vault("sync-registry-fixture");
    copy_tree(&fixture, &path);
    let session = open_session(&path.to_string_lossy(), "fixture-only-passphrase").unwrap();

    let registry = load_device_registry(&session).unwrap().expect("the fixture is enrolled");
    assert_eq!(registry.body.version, 2);
    assert_eq!(registry.body.epoch, 2);
    assert_eq!(registry.body.devices.len(), 2);
    assert!(registry_is_readable(&registry));

    // Canonical JSON and Ed25519 verification must agree with the signer.
    assert!(verify_registry_signature(&registry).expect("verification runs"));

    drop(session);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn a_tampered_registry_body_fails_verification() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test")
        .join("fixtures")
        .join("sync-epoch-v2");
    let path = temporary_vault("sync-registry-tampered");
    copy_tree(&fixture, &path);
    let session = open_session(&path.to_string_lossy(), "fixture-only-passphrase").unwrap();

    let mut registry = load_device_registry(&session).unwrap().unwrap();
    registry.body.revision += 1;
    assert!(!verify_registry_signature(&registry).expect("verification runs"));

    drop(session);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn an_unknown_registry_version_reads_as_undisplayable_rather_than_failing() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test")
        .join("fixtures")
        .join("sync-epoch-v2");
    let path = temporary_vault("sync-registry-future");
    copy_tree(&fixture, &path);
    let session = open_session(&path.to_string_lossy(), "fixture-only-passphrase").unwrap();

    let mut registry = load_device_registry(&session).unwrap().unwrap();
    registry.body.version = 99;
    assert!(!registry_is_readable(&registry), "a future version is reported, not an error");

    drop(session);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn sync_status_counts_changes_without_decrypting_them() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test")
        .join("fixtures")
        .join("sync-epoch-v2");
    let path = temporary_vault("sync-status-count");
    copy_tree(&fixture, &path);
    let session = open_session(&path.to_string_lossy(), "fixture-only-passphrase").unwrap();

    // The fixture holds one epoch 1 change and one epoch 2 change. The count
    // comes from filenames, so it works even though this build holds no epoch
    // key and could not open the second envelope.
    assert_eq!(count_sync_changes(&session).unwrap(), 2);

    drop(session);
    fs::remove_dir_all(path).unwrap();
}
```

`load_device_registry(&session) -> Result<Option<SignedDeviceRegistry>, String>` and `count_sync_changes(&session) -> Result<usize, String>` are the two helpers Step 3 introduces; `sync_status` is a thin Tauri wrapper over them, which is why the tests target the helpers rather than the command.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --lib`
Expected: FAIL — `SignedDeviceRegistry` is not defined.

- [ ] **Step 3: Implement the parsing and verification**

Add to `src-tauri/src/lib.rs`, near the existing serde structs:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeviceCertificate {
    version: u64,
    serial: u64,
    #[serde(rename = "deviceId")]
    device_id: String,
    name: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "keyAgreementKey", skip_serializing_if = "Option::is_none")]
    key_agreement_key: Option<String>,
    #[serde(rename = "enrolledAt")]
    enrolled_at: String,
    epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeviceRecord {
    certificate: DeviceCertificate,
    #[serde(rename = "certificateSignature")]
    certificate_signature: String,
    #[serde(rename = "revokedAt", skip_serializing_if = "Option::is_none")]
    revoked_at: Option<String>,
    #[serde(rename = "revokedAfterSequence", skip_serializing_if = "Option::is_none")]
    revoked_after_sequence: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeviceRegistryBody {
    version: u64,
    revision: u64,
    epoch: u64,
    #[serde(rename = "authorityPublicKey")]
    authority_public_key: String,
    #[serde(rename = "updatedAt")]
    updated_at: String,
    #[serde(rename = "legacyChangeIds")]
    legacy_change_ids: Vec<String>,
    devices: Vec<DeviceRecord>,
    #[serde(rename = "epochKeys", skip_serializing_if = "Option::is_none")]
    epoch_keys: Option<Vec<Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedDeviceRegistry {
    body: DeviceRegistryBody,
    signature: String,
}

/// Versions this build knows how to display. Anything higher parses but is
/// reported as unreadable so the UI can say so instead of erroring.
const READABLE_REGISTRY_VERSIONS: &[u64] = &[1, 2];

fn registry_is_readable(registry: &SignedDeviceRegistry) -> bool {
    READABLE_REGISTRY_VERSIONS.contains(&registry.body.version)
}

/// Canonical JSON matching src/format-version.ts: object keys sorted by code
/// unit, no insignificant whitespace. serde_json's Map preserves insertion
/// order, so the keys are sorted explicitly here.
fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let entries: Vec<String> = keys
                .iter()
                .map(|key| format!("{}:{}", serde_json::to_string(key).unwrap(), canonical_json(&map[*key])))
                .collect();
            format!("{{{}}}", entries.join(","))
        }
        Value::Array(items) => {
            let entries: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", entries.join(","))
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

fn verify_registry_signature(registry: &SignedDeviceRegistry) -> Result<bool, String> {
    let body = serde_json::to_value(&registry.body).map_err(|error| error.to_string())?;
    let message = canonical_json(&body);
    let key_bytes = BASE64
        .decode(registry.body.authority_public_key.as_bytes())
        .map_err(|error| error.to_string())?;
    // Strip the 12-byte SPKI prefix to reach the raw 32-byte Ed25519 key.
    if key_bytes.len() != 44 {
        return Err("authority public key must be 44 bytes of SPKI DER".into());
    }
    let raw: [u8; 32] = key_bytes[12..].try_into().map_err(|_| "malformed authority key".to_string())?;
    let verifying = VerifyingKey::from_bytes(&raw).map_err(|error| error.to_string())?;
    let signature_bytes = BASE64
        .decode(registry.signature.as_bytes())
        .map_err(|error| error.to_string())?;
    let signature_bytes: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;
    Ok(verifying
        .verify(message.as_bytes(), &Signature::from_bytes(&signature_bytes))
        .is_ok())
}
```

Use whichever base64 engine alias `lib.rs` already imports at line 5 in place of `BASE64` if the name differs.

- [ ] **Step 4: Run the Rust tests**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --lib`
Expected: PASS, all three new tests. If `canonical_json` produces a different string than the TypeScript signer, the first test fails — compare against `canonicalSyncJson` output for the same body before changing anything else.

- [ ] **Step 5: Add the commands**

Add `load_checkpoint` alongside the helpers from Step 3, then the two `#[tauri::command(async)]` functions following the existing command style in `lib.rs`. `sync_status` calls `load_device_registry`, `load_checkpoint` and `count_sync_changes`, reads the applied-state object count from `documents/sync/applied.enc`, and assembles `SyncStatus`; it returns `SyncStatus { enrolled: false, .. }` when `devices.enc` does not exist. `sync_verify_registry` calls `load_device_registry` then `verify_registry_signature`. Register both in the `invoke_handler` list and add their names to `src-tauri/capabilities/main.json`.

The authority fingerprint is `sha256(base64_decode(authorityPublicKey))` as hex, matching `syncRegistryFingerprint` in `src/sync.ts` — hash the decoded SPKI bytes, not the base64 text.

- [ ] **Step 6: Run the Rust quality gate**

Run: `npm run quality:rust`
Expected: PASS, clippy clean.

- [ ] **Step 7: Commit**

```bash
git add src-tauri/src/lib.rs src-tauri/capabilities/main.json
git commit -m "feat(desktop): read sync status and verify the registry authority"
```

---

### Task 13: Sync status panel

**Files:**

- Create: `desktop/src/SyncStatus.tsx`, `desktop/src/SyncStatus.test.tsx`
- Modify: `desktop/src/App.tsx`, `desktop/src/bridge.ts`, `desktop/src/types.ts`

**Interfaces:**

- Consumes: the `sync_status` and `sync_verify_registry` commands (Task 12).
- Produces: `<SyncStatus status={SyncStatusData | null} />` rendering nothing when `status` is `null` or `status.enrolled` is `false`.

- [ ] **Step 1: Write the failing test**

Create `desktop/src/SyncStatus.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SyncStatus } from "./SyncStatus";

const base = {
  enrolled: true,
  authorityFingerprint: "a".repeat(64),
  epoch: 2,
  registryRevision: 3,
  registryVersion: 2,
  readable: true,
  changeCount: 12,
  unappliedCount: 0,
  checkpoint: { id: "b".repeat(64), sequence: 1, changeCount: 12, createdAt: "2026-09-03T00:00:00.000Z" },
  devices: [
    { deviceId: "11111111-1111-4111-8111-111111111111", name: "Owner laptop", serial: 1, epoch: 2, revokedAfterSequence: null },
    { deviceId: "22222222-2222-4222-8222-222222222222", name: "Travel laptop", serial: 2, epoch: 1, revokedAfterSequence: 0 },
  ],
};

describe("SyncStatus", () => {
  it("renders nothing before enrollment", () => {
    const { container } = render(<SyncStatus status={{ ...base, enrolled: false }} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("shows the active epoch and marks revoked devices", () => {
    render(<SyncStatus status={base} />);
    expect(screen.getByText(/epoch 2/i)).toBeInTheDocument();
    expect(screen.getByText("Owner laptop")).toBeInTheDocument();
    expect(screen.getByText(/revoked after sequence 0/i)).toBeInTheDocument();
  });

  it("states that mutation is CLI-only and shows the command", () => {
    render(<SyncStatus status={base} />);
    expect(screen.getByText(/read-only/i)).toBeInTheDocument();
    expect(screen.getByText(/sbrain --experimental-trusted-sync sync devices list/)).toBeInTheDocument();
  });

  it("warns when there are unapplied changes", () => {
    render(<SyncStatus status={{ ...base, unappliedCount: 4 }} />);
    expect(screen.getByText(/4 changes not yet applied/i)).toBeInTheDocument();
  });

  it("explains an unreadable newer format instead of failing", () => {
    render(<SyncStatus status={{ ...base, readable: false, registryVersion: 99 }} />);
    expect(screen.getByText(/newer format this build cannot display/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm run desktop:test -- SyncStatus`
Expected: FAIL — `./SyncStatus` cannot be resolved.

- [ ] **Step 3: Implement the panel**

Create `desktop/src/SyncStatus.tsx` rendering, in this order: a header with the authority fingerprint truncated to its first 12 characters, the active epoch and registry revision; the device list with each device's name, serial, epoch and either "active" or "revoked after sequence N"; the checkpoint sequence and creation time, or "no checkpoint pinned"; the change count and, when `unappliedCount > 0`, the text `${unappliedCount} changes not yet applied`; a footer reading "Sync is read-only in the desktop app. Run mutations from the CLI:" followed by `sbrain --experimental-trusted-sync sync devices list` in a `<code>` element. When `readable` is `false`, render only the header and the sentence "This vault uses a newer format this build cannot display." Return `null` when `status` is `null` or `status.enrolled` is `false`.

Follow the styling conventions in `desktop/src/PluginManager.tsx`, which is the closest existing read-mostly panel. Add the `SyncStatusData` type to `desktop/src/types.ts`, the `syncStatus()` and `syncVerifyRegistry()` wrappers to `desktop/src/bridge.ts` alongside the existing `invoke` wrappers, and mount `<SyncStatus />` in `App.tsx` in the same context region that hosts the other side panels.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm run desktop:test -- SyncStatus`
Expected: PASS, all five tests.

- [ ] **Step 5: Run the full quality gate**

Run: `npm run quality && npm run quality:rust`
Expected: PASS. This is the full gate for Part D.

- [ ] **Step 6: Commit**

```bash
git add desktop/src/SyncStatus.tsx desktop/src/SyncStatus.test.tsx desktop/src/App.tsx desktop/src/bridge.ts desktop/src/types.ts
git commit -m "feat(desktop): show read-only sync status with CLI handoff"
```

---

## Part E — Audit readiness

### Task 14: Audit scope and honest roadmap

**Files:**

- Create: `docs/AUDIT-SCOPE.md`
- Modify: `SECURITY.md`, `docs/ROADMAP.md`, `README.md`

**Interfaces:**

- Consumes: everything above.
- Produces: documentation only. No code changes, so no test cycle — the gate here is factual accuracy, verified in Step 4.

- [ ] **Step 1: Write the audit scope document**

Create `docs/AUDIT-SCOPE.md` with these sections:

1. **Purpose.** What an engagement is being asked to review and the decision it gates: whether the project may be presented as suitable for real medical, financial or identity data.
2. **In scope, with sizes.** The TypeScript core modules with current line counts from `wc -l src/*.ts`, the Rust desktop core, and the relay. Name `src/crypto.ts`, `src/document-crypto.ts`, `src/sync.ts`, `src/sync-epoch.ts`, `src/sync-relay.ts`, `src/grants.ts`, `src/plugin-signatures.ts` and `src-tauri/src/lib.rs` explicitly.
3. **Trust boundaries.** The passphrase and the encrypted files are the boundary. The relay is untrusted and holds only opaque ciphertext. Enrolled devices are trusted. Plugins run sandboxed under declared capabilities. Agents reach the vault only through MCP tools.
4. **Threat model.** Relay operator, revoked device, stolen vault at rest, hostile plugin, hostile agent, hostile envelope or registry supplied as input.
5. **Accepted known risks**, stated without softening: the passphrase is the only real boundary and anyone holding it recovers everything; the grant layer narrows what an agent is handed but is not a boundary against a model; `SBRAIN_AGENT` is a chosen name, not a credential; epoch rotation is forward-only and a revoked device retains pre-rotation plaintext access; only the Windows credential-store path is exercised by tests.
6. **The two-implementation problem**, as a first-class scope item. The TypeScript core and the 6531-line Rust core read the same format through independently written code. Ask the auditor to check them against each other, and point at `docs/FORMAT-1.0.md` and the `test/fixtures/` vaults as the material for doing it.
7. **Already-closed findings.** Link `docs/SECURITY-AUDIT-2026-09-02.md` and `docs/SECURITY-REMEDIATION-2026-09-03.md`, and state which of their items this work closed — specifically the epoch-rotation item from finding 163.
8. **Questions for the auditor.** Concrete and answerable: Does epoch rotation actually exclude a revoked device that retains the passphrase, given wraps travel inside a registry encrypted under the master key? Is the change-ID HMAC construction sound as a relay-opaque identifier across an epoch boundary? Can a hostile registry or envelope cause unbounded work before validation? Do the two implementations agree on every conformance fixture?
9. **Out of scope.** iOS and Android clients (unstarted), the plugin ecosystem's third-party packages, and the relay's hosting environment.
10. **Reproducing the build and running the evidence.** `npm ci`, `npm run quality`, `npm run quality:rust`, `npm run benchmark`, `npm run recovery:drill`, and `node --test test/format-conformance.test.mjs`.

- [ ] **Step 2: Update the security policy**

In `SECURITY.md`, under "Supported versions", replace the pre-1.0 line with a statement that the on-disk format is frozen at 1.0 while the product remains pre-1.0, and that until the independent review described in `docs/AUDIT-SCOPE.md` is complete, releases are not presented as suitable for real medical, financial or identity data. Link `docs/AUDIT-SCOPE.md` and `docs/FORMAT-1.0.md`.

- [ ] **Step 3: Update the roadmap honestly**

In `docs/ROADMAP.md`, under Phase 6, make exactly these changes and no others:

```markdown
- [x] Epoch-based content-key rotation
  - [x] Random per-epoch content keys wrapped to each active device's X25519 key
  - [x] Automatic rotation on owner-signed device revocation
  - [x] Forward-only: a revoked device retains pre-rotation read access
- [ ] Desktop multi-device release, then iOS/Android clients
  - [x] Read-only desktop sync status; mutation remains CLI-only
  - [ ] Desktop-driven enrollment, revocation and relay exchange
  - [ ] iOS/Android clients
- [ ] External security audit and stable 1.0 format
  - [x] Stable 1.0 on-disk format with committed conformance fixtures
  - [ ] External security audit (readiness package in `docs/AUDIT-SCOPE.md`)
```

The two unchecked parents stay unchecked. Do not mark a parent complete because some children are.

- [ ] **Step 4: Update the README roadmap paragraph and verify every claim**

Rewrite the README "Roadmap" paragraph to say what is now true: Phase 6 has the change log, device enrollment and revocation with automatic epoch rotation, freshness checkpoints, the opaque relay, the recovery drill, a frozen 1.0 on-disk format, and read-only desktop sync status. Desktop-driven sync mutation, mobile clients and the independent audit remain open.

Then verify, one claim at a time, that each sentence you wrote is backed by code that exists:

Run: `npm run build && npm test && npm run desktop:test && npm run quality:rust`
Expected: PASS.

Run: `git log --oneline main..HEAD`
Expected: every claim in the README and roadmap maps to a commit in this list. Any claim that does not, delete — do not soften it.

- [ ] **Step 5: Commit**

```bash
git add docs/AUDIT-SCOPE.md SECURITY.md docs/ROADMAP.md README.md
git commit -m "docs: add the external audit readiness package and correct the roadmap"
```

---

## Self-review

**Spec coverage.** Every spec section maps to a task: the key hierarchy and distribution to Tasks 2-3; certificate and registry v2 to Task 4; enrollment agreement keys to Task 5; envelope v2 and the epoch-1 rule to Task 6; rotation on revocation, the last-device refusal and registry adoption to Task 7; the forward-only documentation to Task 8; `format-version.ts` to Task 1; `FORMAT-1.0.md` to Task 11; conformance fixtures to Task 10; `sbrain format` to Task 9; the Rust read-only commands to Task 12; the panel to Task 13; `AUDIT-SCOPE.md`, `SECURITY.md` and the honest roadmap to Task 14. The spec's rotation test list is distributed across Tasks 2, 4, 6 and 7, with all seven cases present.

**Naming consistency.** `EpochKeyWrap`, `wrapEpochKey`, `unwrapEpochKey`, `readEpochKey`, `saveEpochKey`, `SyncEpochKeyResolver`, `keyAgreementKey` and `epochKeys` are used identically wherever they appear. `sealSyncChange(body, key, epoch?)` and `openSyncChange(value, keyOrResolver)` keep their existing call shapes so no existing caller needs editing.

**Three deviations from the spec, all deliberate and stated inline.** The constants module moves ahead of rotation, for the reason given in the ordering note. The AAD inventory covers `documents.ts` as well as the three files the spec named — the spec said "roughly a dozen across three files"; the actual count is 23 across four, which Task 1's test asserts. And the conformance fixtures follow the repository's existing convention — one generator (`scripts/make-fixtures.mjs`), the shared `fixture-only-passphrase`, a new directory per format version, and a README table the script regenerates — rather than the standalone `format-1.0/` tree the spec sketched, which would have been a second parallel convention.

**One gap the spec did not anticipate.** No existing test spawns the CLI, so Task 8 adds a small `runCli` harness in a new `test/cli.test.mjs` rather than asserting on CLI output indirectly.
