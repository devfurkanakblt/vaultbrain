# Phase 7.1 — Vault Keyring Format and Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put every one of the vault's data keys behind a passphrase-wrapped keyring, and add a `vbrain migrate` step that upgrades an existing vault to it without re-encrypting a single note.

**Architecture:** A new `src/keyring.ts` owns all key material resolution. `openVaultKeys(vaultDir, passphrase)` returns a five-key keyset when `keyring.json` exists and `null` when it does not — `null` means "this is a legacy vault, use the derivation you already have". Every consumer keeps its existing legacy branch untouched and gains a keyring branch, so no behaviour changes for a vault that has not been migrated. `src/keyring-migrate.ts` performs the upgrade: it adopts the legacy keys verbatim into the keyset so attachment content IDs and sync change IDs stay byte-identical.

**Tech Stack:** TypeScript (ESM, Node 20+), `node:crypto` (scrypt, AES-256-GCM, HMAC-SHA256), `node:test` integration tests against `dist/`.

## Global Constraints

- Design contract: `docs/superpowers/specs/2026-09-03-vault-keyring-design.md`. Read it before starting.
- Node.js 20 or newer; CI uses Node.js 22.
- No new runtime dependencies. `package.json` `dependencies` stays exactly `@modelcontextprotocol/sdk`, `commander`, `yaml`.
- Keyring version: `2`. Keyset version: `1`. Key-value envelope version: `2`.
- Default KDF: `scrypt`, `N = 2 ** 17` (131072), `r = 8`, `p = 1`, 16-byte salt, 32-byte output.
- Accepted KDF bounds on read: `N` a power of two in `[2 ** 14, 2 ** 20]`, `r` in `[1, 32]`, `p` in `[1, 16]`, salt 16–64 bytes.
- Node `scrypt` needs `maxmem` above `128 * N * r`; every call site passes `Math.max(256 * 1024 * 1024, 256 * N * r)`.
- Key names, in this exact order, everywhere: `documents`, `kv`, `attachmentId`, `syncChange`, `audit`.
- The `secondbrain-vault:*` associated-data namespace is immutable. Do not rename an existing identifier. New identifiers added by this phase: `secondbrain-vault:keyring-slot:v1` and `secondbrain-vault:kv:v2`.
- Never regenerate or hand-edit an existing fixture under `test/fixtures/`. Add new directories only.
- Tests import from `../dist/`, so every test run is `npm run build && node --test <file>`.
- Every file write uses `writeFileAtomic` from `src/fs-safe.ts` with `mode: 0o600`; every read of a vault file calls `assertNotSymlink` first.
- Commit after every task. Branch is `phase-7-vault-keyring`, already created.

**Deliberate sequencing decision, agreed with the spec:** in this phase a brand-new empty vault is still created in the legacy format. Only `vbrain migrate` writes a keyring. New vaults become keyring-native in Phase 7.2, once the Rust core can read one. This keeps 7.1 strictly additive: no vault that the desktop application can open today becomes unopenable.

---

## File Structure

**Create:**

- `src/keyring.ts` — the keyring format: slot wrapping and unwrapping, validation, vault format detection, `openVaultKeys` and its process cache. Depends on `fs-safe.ts` and `safety.ts` only, so nothing can import it circularly.
- `src/keyring-migrate.ts` — the v1 → v2 migration. Imports `keyring.ts`, `store.ts`, `grants.ts` and `vault-lock.ts`. Kept separate from `keyring.ts` precisely because `store.ts` imports `keyring.ts`; putting migration in `keyring.ts` would create a cycle.
- `test/keyring.test.mjs` — format, tampering, detection and session tests.
- `test/keyring-migrate.test.mjs` — migration, adoption-identity and idempotency tests against the checked-in fixtures.

**Modify:**

- `src/crypto.ts` — add the keyed envelope v2 alongside v0 and v1.
- `src/store.ts` — route key-value files through the keyring when there is one.
- `src/grants.ts` — same, for `grants.enc`.
- `src/audit.ts` — take the chain HMAC key from the keyring when there is one.
- `src/document-crypto.ts` — `DocumentKeySession` gains `attachmentIdKey` and `syncChangeKey`; `openDocumentKey` delegates to the keyring when there is one.
- `src/documents.ts:2165`, `src/documents.ts:2205`, `src/documents.ts:521` — attachment content IDs use `attachmentIdKey`; `lock()` zeroizes all three keys.
- `src/sync/change-log.ts` — sync change sealing uses `syncChangeKey`; `applied.enc` keeps using the documents key.
- `src/cli.ts:1196` — `migrate` performs the keyring upgrade; `keychain-status` reports the vault format.
- `package.json` — add the two new test files to the `test` script.
- `scripts/make-fixtures.mjs`, `test/fixtures/README.md`, `docs/ROADMAP.md` — the new fixture and its documentation.

`src/sync/transaction.ts` needs no change: it only reads `session.rootDir` and `session.key`.

---

### Task 1: Keyring slot format

**Files:**

- Create: `src/keyring.ts`
- Create: `test/keyring.test.mjs`
- Modify: `package.json` (test script)

**Interfaces:**

- Consumes: `writeFileAtomic`, `assertNotSymlink` from `src/fs-safe.js`; `resolveInside` from `src/safety.js`.
- Produces: `KEY_NAMES`, `KeyName`, `KeySet`, `KeyringSlot`, `KeyringFile`, `KEYRING_VERSION`, `KEYSET_VERSION`, `DEFAULT_SCRYPT_N`, `randomKeySet()`, `wrapKeySet(keys, passphrase, N?)`, `unwrapSlot(slot, passphrase)`, `keyringPath(vaultDir)`, `readKeyring(vaultDir)`, `writeKeyring(vaultDir, file)`, `unwrapKeyring(file, passphrase)`.

- [ ] **Step 1: Write the failing test**

Create `test/keyring.test.mjs`:

```js
import assert from "node:assert/strict";
import test from "node:test";

import {
  DEFAULT_SCRYPT_N,
  KEY_NAMES,
  randomKeySet,
  unwrapSlot,
  wrapKeySet,
} from "../dist/keyring.js";

const PASSPHRASE = "keyring-test-passphrase";

test("a wrapped keyset round-trips and records its own cost", () => {
  const keys = randomKeySet();
  const slot = wrapKeySet(keys, PASSPHRASE);

  assert.equal(slot.type, "passphrase");
  assert.equal(slot.kdf.name, "scrypt");
  assert.equal(slot.kdf.N, DEFAULT_SCRYPT_N);
  assert.equal(slot.kdf.r, 8);
  assert.equal(slot.kdf.p, 1);
  assert.match(slot.id, /^[0-9a-f-]{36}$/u);

  const opened = unwrapSlot(slot, PASSPHRASE);
  for (const name of KEY_NAMES) {
    assert.equal(opened[name].length, 32);
    assert.equal(opened[name].toString("base64"), keys[name].toString("base64"));
  }
});

test("a fresh keyset uses five independent keys", () => {
  const keys = randomKeySet();
  const seen = new Set(KEY_NAMES.map((name) => keys[name].toString("base64")));
  assert.equal(seen.size, KEY_NAMES.length);
});

test("a wrapped keyset rejects a wrong passphrase and a rewritten header", () => {
  const slot = wrapKeySet(randomKeySet(), PASSPHRASE);

  assert.throws(() => unwrapSlot(slot, "wrong passphrase"));

  // The recorded cost is authenticated, so it cannot be weakened for the next derivation.
  assert.throws(() => unwrapSlot({ ...slot, kdf: { ...slot.kdf, N: 2 ** 14 } }, PASSPHRASE));
  // Nor can a slot's ciphertext be transplanted onto another slot's identity.
  assert.throws(() => unwrapSlot({ ...slot, id: "00000000-0000-4000-8000-000000000000" }, PASSPHRASE));
  assert.throws(
    () => unwrapSlot({ ...slot, wrapped: { ...slot.wrapped, ciphertext: `${slot.wrapped.ciphertext.slice(0, -2)}AA` } }, PASSPHRASE),
  );
});

test("a hostile slot cannot dictate an unacceptable derivation", () => {
  const slot = wrapKeySet(randomKeySet(), PASSPHRASE);

  assert.throws(() => unwrapSlot({ ...slot, kdf: { ...slot.kdf, N: 2 ** 24 } }, PASSPHRASE), /unacceptable scrypt cost/u);
  assert.throws(() => unwrapSlot({ ...slot, kdf: { ...slot.kdf, N: 100000 } }, PASSPHRASE), /unacceptable scrypt cost/u);
  assert.throws(() => unwrapSlot({ ...slot, kdf: { ...slot.kdf, r: 0 } }, PASSPHRASE), /unacceptable scrypt block size/u);
  assert.throws(() => unwrapSlot({ ...slot, kdf: { ...slot.kdf, p: 99 } }, PASSPHRASE), /unacceptable scrypt parallelism/u);
  assert.throws(() => unwrapSlot({ ...slot, kdf: { ...slot.kdf, name: "pbkdf2" } }, PASSPHRASE), /Unsupported key-derivation/u);
  assert.throws(() => unwrapSlot({ ...slot, kdf: { ...slot.kdf, salt: "AAAA" } }, PASSPHRASE), /out-of-range salt/u);
});

test("wrapping refuses an empty passphrase", () => {
  assert.throws(() => wrapKeySet(randomKeySet(), ""), /non-empty vault passphrase/u);
});
```

- [ ] **Step 2: Add the test file to the suite**

In `package.json`, extend the `test` script so it ends with the new file:

```json
"test": "npm run build && node --test test/package.test.mjs test/core.test.mjs test/documents.test.mjs test/workflows.test.mjs test/durability.test.mjs test/canvas.test.mjs test/grants.test.mjs test/plugins.test.mjs test/obsidian-import.test.mjs test/semantic.test.mjs test/sync.test.mjs test/sync-protocol.test.mjs test/sync-transaction.test.mjs test/sync-apply.test.mjs test/keyring.test.mjs",
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `npm run build && node --test test/keyring.test.mjs`
Expected: FAIL — `Cannot find module '.../dist/keyring.js'`.

- [ ] **Step 4: Write the implementation**

Create `src/keyring.ts`:

```ts
import crypto from "node:crypto";
import fs from "node:fs";
import { assertNotSymlink, writeFileAtomic } from "./fs-safe.js";
import { resolveInside } from "./safety.js";

export const KEYRING_VERSION = 2;
export const KEYSET_VERSION = 1;
export const KEYRING_FILENAME = "keyring.json";
export const DEFAULT_SCRYPT_N = 2 ** 17;

const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LENGTH = 32;
const SLOT_AAD_CONTEXT = "secondbrain-vault:keyring-slot:v1";

/** The order is part of the format: it is what `serializeKeySet` writes. */
export const KEY_NAMES = ["documents", "kv", "attachmentId", "syncChange", "audit"] as const;
export type KeyName = (typeof KEY_NAMES)[number];
export type KeySet = { [K in KeyName]: Buffer };

export interface SlotKdf {
  name: "scrypt";
  N: number;
  r: number;
  p: number;
  salt: string;
}

export interface KeyringSlot {
  id: string;
  type: "passphrase";
  label: string;
  kdf: SlotKdf;
  createdAt: string;
  wrapped: { iv: string; authTag: string; ciphertext: string };
}

export interface KeyringFile {
  version: number;
  slots: KeyringSlot[];
}

function base64Bytes(value: unknown, min: number, max: number, label: string): Buffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/u.test(value)) {
    throw new Error(`Vault keyring has a malformed ${label}.`);
  }
  const bytes = Buffer.from(value, "base64");
  if (bytes.length < min || bytes.length > max) {
    throw new Error(`Vault keyring has an out-of-range ${label}.`);
  }
  return bytes;
}

/**
 * Reject parameters the file could otherwise dictate to us: a hostile keyring
 * must not be able to demand a multi-gigabyte scrypt run, nor silently
 * downgrade the work factor below what this build considers acceptable. Same
 * bounds as the key-value envelope in `crypto.ts`.
 */
function validateKdf(kdf: unknown): SlotKdf {
  const candidate = kdf as SlotKdf | undefined;
  if (!candidate || candidate.name !== "scrypt") {
    throw new Error("Unsupported key-derivation function in vault keyring.");
  }
  const { N, r, p } = candidate;
  if (!Number.isSafeInteger(N) || N < 2 ** 14 || N > 2 ** 20 || (N & (N - 1)) !== 0) {
    throw new Error("Vault keyring declares an unacceptable scrypt cost.");
  }
  if (!Number.isSafeInteger(r) || r < 1 || r > 32) {
    throw new Error("Vault keyring declares an unacceptable scrypt block size.");
  }
  if (!Number.isSafeInteger(p) || p < 1 || p > 16) {
    throw new Error("Vault keyring declares an unacceptable scrypt parallelism.");
  }
  base64Bytes(candidate.salt, 16, 64, "salt");
  return { name: "scrypt", N, r, p, salt: candidate.salt };
}

export function validateSlot(value: unknown): KeyringSlot {
  const slot = value as KeyringSlot | undefined;
  if (!slot || typeof slot !== "object") throw new Error("Vault keyring has a malformed slot.");
  if (typeof slot.id !== "string" || !/^[0-9a-f-]{36}$/u.test(slot.id)) {
    throw new Error("Vault keyring has a malformed slot ID.");
  }
  if (slot.type !== "passphrase") throw new Error(`Unsupported vault keyring slot type: ${String(slot.type)}`);
  if (typeof slot.label !== "string" || slot.label.length > 64) {
    throw new Error("Vault keyring has a malformed slot label.");
  }
  if (typeof slot.createdAt !== "string" || Number.isNaN(Date.parse(slot.createdAt))) {
    throw new Error("Vault keyring has a malformed slot timestamp.");
  }
  const kdf = validateKdf(slot.kdf);
  const wrapped = slot.wrapped;
  if (!wrapped || typeof wrapped !== "object") throw new Error("Vault keyring has a malformed wrapped keyset.");
  base64Bytes(wrapped.iv, 12, 12, "iv");
  base64Bytes(wrapped.authTag, 16, 16, "authentication tag");
  base64Bytes(wrapped.ciphertext, 16, 4096, "wrapped keyset");
  return { id: slot.id, type: "passphrase", label: slot.label, kdf, createdAt: slot.createdAt, wrapped };
}

function scryptMaxmem(kdf: SlotKdf): number {
  return Math.max(256 * 1024 * 1024, 256 * kdf.N * kdf.r);
}

function deriveSlotKey(passphrase: string, kdf: SlotKdf): Buffer {
  return crypto.scryptSync(passphrase, Buffer.from(kdf.salt, "base64"), KEY_LENGTH, {
    N: kdf.N,
    r: kdf.r,
    p: kdf.p,
    maxmem: scryptMaxmem(kdf),
  });
}

/**
 * The slot's identity and its declared cost are authenticated alongside the
 * wrapped keyset, so nobody can weaken the header or move one slot's
 * ciphertext under another slot's identity without the tag check failing.
 */
function slotAad(slot: Omit<KeyringSlot, "wrapped">): Buffer {
  return Buffer.from(
    JSON.stringify({
      context: SLOT_AAD_CONTEXT,
      version: KEYRING_VERSION,
      id: slot.id,
      type: slot.type,
      kdf: { name: slot.kdf.name, N: slot.kdf.N, r: slot.kdf.r, p: slot.kdf.p, salt: slot.kdf.salt },
    }),
    "utf8",
  );
}

function serializeKeySet(keys: KeySet): string {
  const encoded: Record<string, string> = {};
  for (const name of KEY_NAMES) encoded[name] = keys[name].toString("base64");
  return JSON.stringify({ version: KEYSET_VERSION, keys: encoded });
}

function parseKeySet(plaintext: string): KeySet {
  const parsed = JSON.parse(plaintext) as { version?: number; keys?: Record<string, unknown> };
  if (parsed?.version !== KEYSET_VERSION) {
    throw new Error(`Unsupported vault keyset version: ${String(parsed?.version)}`);
  }
  const keys = {} as KeySet;
  for (const name of KEY_NAMES) {
    keys[name] = base64Bytes(parsed.keys?.[name], KEY_LENGTH, KEY_LENGTH, `${name} key`);
  }
  return keys;
}

export function randomKeySet(): KeySet {
  const keys = {} as KeySet;
  for (const name of KEY_NAMES) keys[name] = crypto.randomBytes(KEY_LENGTH);
  return keys;
}

export function copyKeySet(keys: KeySet): KeySet {
  const copy = {} as KeySet;
  for (const name of KEY_NAMES) copy[name] = Buffer.from(keys[name]);
  return copy;
}

export function zeroKeySet(keys: KeySet): void {
  for (const name of KEY_NAMES) keys[name].fill(0);
}

export function wrapKeySet(keys: KeySet, passphrase: string, N: number = DEFAULT_SCRYPT_N): KeyringSlot {
  if (!passphrase) throw new Error("A non-empty vault passphrase is required.");
  const header = {
    id: crypto.randomUUID(),
    type: "passphrase" as const,
    label: "primary",
    kdf: validateKdf({ name: "scrypt", N, r: SCRYPT_R, p: SCRYPT_P, salt: crypto.randomBytes(16).toString("base64") }),
    createdAt: new Date().toISOString(),
  };
  const derived = deriveSlotKey(passphrase, header.kdf);
  try {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", derived, iv);
    cipher.setAAD(slotAad(header));
    const ciphertext = Buffer.concat([cipher.update(serializeKeySet(keys), "utf8"), cipher.final()]);
    return {
      ...header,
      wrapped: {
        iv: iv.toString("base64"),
        authTag: cipher.getAuthTag().toString("base64"),
        ciphertext: ciphertext.toString("base64"),
      },
    };
  } finally {
    derived.fill(0);
  }
}

/**
 * A wrong passphrase fails as an authentication error. There is deliberately
 * no verifier field: publishing one hands an offline attacker a free
 * passphrase-guessing oracle.
 */
export function unwrapSlot(slot: KeyringSlot, passphrase: string): KeySet {
  const validated = validateSlot(slot);
  const derived = deriveSlotKey(passphrase, validated.kdf);
  let plaintext: Buffer | undefined;
  try {
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      derived,
      base64Bytes(validated.wrapped.iv, 12, 12, "iv"),
    );
    decipher.setAAD(slotAad(validated));
    decipher.setAuthTag(base64Bytes(validated.wrapped.authTag, 16, 16, "authentication tag"));
    plaintext = Buffer.concat([
      decipher.update(Buffer.from(validated.wrapped.ciphertext, "base64")),
      decipher.final(),
    ]);
    return parseKeySet(plaintext.toString("utf8"));
  } finally {
    derived.fill(0);
    plaintext?.fill(0);
  }
}

export function keyringPath(vaultDir: string): string {
  return resolveInside(vaultDir, KEYRING_FILENAME);
}

export function readKeyring(vaultDir: string): KeyringFile | null {
  const filePath = keyringPath(vaultDir);
  if (!fs.existsSync(filePath)) return null;
  assertNotSymlink(filePath);
  const parsed = JSON.parse(fs.readFileSync(filePath, "utf8")) as KeyringFile;
  if (parsed?.version !== KEYRING_VERSION) {
    throw new Error(
      `This vault keyring uses version ${String(parsed?.version)}; this build understands ${KEYRING_VERSION}. Upgrade Vault Brain to open it.`,
    );
  }
  if (!Array.isArray(parsed.slots) || parsed.slots.length === 0 || parsed.slots.length > 16) {
    throw new Error("Vault keyring has no usable slots.");
  }
  return { version: KEYRING_VERSION, slots: parsed.slots.map(validateSlot) };
}

export function writeKeyring(vaultDir: string, file: KeyringFile): void {
  fs.mkdirSync(vaultDir, { recursive: true, mode: 0o700 });
  writeFileAtomic(keyringPath(vaultDir), `${JSON.stringify(file, null, 2)}\n`, { mode: 0o600 });
}

export function unwrapKeyring(file: KeyringFile, passphrase: string): KeySet {
  for (const slot of file.slots) {
    try {
      return unwrapSlot(slot, passphrase);
    } catch {
      // Try the next slot: a keyring may hold several, and only one has to open.
    }
  }
  throw new Error("Unable to unlock this vault: wrong passphrase, or the keyring is damaged.");
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `npm run build && node --test test/keyring.test.mjs`
Expected: PASS, 5 tests.

- [ ] **Step 6: Commit**

```bash
git add src/keyring.ts test/keyring.test.mjs package.json
git commit -m "feat: add the vault keyring slot format"
```

---

### Task 2: Vault format detection and `openVaultKeys`

**Files:**

- Modify: `src/keyring.ts`
- Modify: `test/keyring.test.mjs`

**Interfaces:**

- Consumes: everything Task 1 produced.
- Produces: `VaultFormat` (`"keyring" | "legacy" | "empty"`), `detectVaultFormat(vaultDir): VaultFormat`, `openVaultKeys(vaultDir, passphrase): KeySet | null`, `forgetVaultKeys(vaultDir?): void`.

`openVaultKeys` returns `null` for a legacy or empty vault. `null` is the signal every consumer uses to take its existing, unchanged code path. It returns a **fresh copy** of the cached keyset on every call, because callers such as `DocumentVault.lock()` and `SyncLocalTransaction.close()` zeroize the buffers they were handed.

- [ ] **Step 1: Write the failing test**

Append to `test/keyring.test.mjs`. Every task from here on adds imports to this file: merge each new name into the existing `import ... from "../dist/keyring.js"` statement rather than adding a second one, and keep the `node:` imports together at the top.

```js
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  detectVaultFormat,
  forgetVaultKeys,
  openVaultKeys,
  randomKeySet,
  wrapKeySet,
  writeKeyring,
} from "../dist/keyring.js";

function tempVault() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "vault-brain-keyring-"));
}

function seedKeyring(vaultDir, passphrase) {
  const keys = randomKeySet();
  writeKeyring(vaultDir, { version: 2, slots: [wrapKeySet(keys, passphrase, 2 ** 14)] });
  forgetVaultKeys(vaultDir);
  return keys;
}

test("an empty directory is an empty vault and gets no keyring implicitly", () => {
  const vault = tempVault();
  assert.equal(detectVaultFormat(vault), "empty");
  assert.equal(openVaultKeys(vault, PASSPHRASE), null);
  assert.equal(fs.existsSync(path.join(vault, "keyring.json")), false);
});

test("a vault holding legacy material is a legacy vault", () => {
  const vault = tempVault();
  fs.mkdirSync(path.join(vault, "documents"), { recursive: true });
  fs.writeFileSync(path.join(vault, "documents", "manifest.json"), "{}");
  assert.equal(detectVaultFormat(vault), "legacy");
  assert.equal(openVaultKeys(vault, PASSPHRASE), null);

  const kvOnly = tempVault();
  fs.writeFileSync(path.join(kvOnly, "health.kv.enc"), "{}");
  assert.equal(detectVaultFormat(kvOnly), "legacy");
});

test("a keyring vault resolves all five keys and rejects a wrong passphrase", () => {
  const vault = tempVault();
  const keys = seedKeyring(vault, PASSPHRASE);

  assert.equal(detectVaultFormat(vault), "keyring");
  const opened = openVaultKeys(vault, PASSPHRASE);
  assert.ok(opened);
  for (const name of KEY_NAMES) {
    assert.equal(opened[name].toString("base64"), keys[name].toString("base64"));
  }
  assert.throws(() => openVaultKeys(vault, "wrong passphrase"), /wrong passphrase/u);
});

test("each caller gets its own buffers, so zeroizing one session cannot blind another", () => {
  const vault = tempVault();
  const keys = seedKeyring(vault, PASSPHRASE);

  const first = openVaultKeys(vault, PASSPHRASE);
  first.documents.fill(0);

  const second = openVaultKeys(vault, PASSPHRASE);
  assert.equal(second.documents.toString("base64"), keys.documents.toString("base64"));
});

test("forgetVaultKeys drops the cached keyset", () => {
  const vault = tempVault();
  seedKeyring(vault, PASSPHRASE);
  assert.ok(openVaultKeys(vault, PASSPHRASE));

  fs.rmSync(path.join(vault, "keyring.json"));
  forgetVaultKeys(vault);
  assert.equal(openVaultKeys(vault, PASSPHRASE), null);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm run build && node --test test/keyring.test.mjs`
Expected: FAIL — `detectVaultFormat is not a function`.

- [ ] **Step 3: Write the implementation**

Append to `src/keyring.ts`:

```ts
import path from "node:path";

export type VaultFormat = "keyring" | "legacy" | "empty";

const LEGACY_MARKERS = [
  path.join("documents", "manifest.json"),
  "audit.meta.json",
  "grants.enc",
  "schema.json",
];

/**
 * A vault is legacy when it holds material an earlier release wrote. Detection
 * never writes anything: creating a keyring is `vbrain migrate`'s job, not a
 * side effect of opening a vault.
 */
export function detectVaultFormat(vaultDir: string): VaultFormat {
  if (fs.existsSync(keyringPath(vaultDir))) return "keyring";
  if (!fs.existsSync(vaultDir)) return "empty";
  for (const marker of LEGACY_MARKERS) {
    if (fs.existsSync(resolveInside(vaultDir, marker))) return "legacy";
  }
  if (fs.readdirSync(vaultDir).some((entry) => entry.endsWith(".kv.enc"))) return "legacy";
  return "empty";
}

/**
 * One resolved keyset per vault per passphrase, so unlocking does not pay the
 * KDF again on every operation. The fingerprint identifies an already-unlocked
 * in-process session; neither it nor the keyset is ever written to disk. This
 * is the pattern `audit.ts` already uses for its chain key.
 */
const keySetCache = new Map<string, KeySet>();

function cacheId(vaultDir: string, passphrase: string, file: KeyringFile): string {
  const fingerprint = crypto
    .createHash("sha256")
    .update(file.slots[0].kdf.salt, "utf8")
    .update("\0", "utf8")
    .update(passphrase, "utf8")
    .digest("hex");
  return `${resolveInside(vaultDir, ".")}\0${fingerprint}`;
}

/**
 * Returns the vault's keyset, or `null` when this vault has no keyring — which
 * means the caller must use the legacy derivation it already has. Callers
 * receive their own buffers: several of them zeroize what they are handed when
 * they lock, and that must not blind the next caller.
 */
export function openVaultKeys(vaultDir: string, passphrase: string): KeySet | null {
  const file = readKeyring(vaultDir);
  if (!file) return null;
  if (!passphrase) throw new Error("A non-empty vault passphrase is required.");

  const id = cacheId(vaultDir, passphrase, file);
  const cached = keySetCache.get(id);
  if (cached) return copyKeySet(cached);

  const keys = unwrapKeyring(file, passphrase);
  keySetCache.set(id, keys);
  return copyKeySet(keys);
}

/** Drops cached key material, for one vault or for all of them. */
export function forgetVaultKeys(vaultDir?: string): void {
  if (vaultDir === undefined) {
    for (const keys of keySetCache.values()) zeroKeySet(keys);
    keySetCache.clear();
    return;
  }
  const prefix = `${resolveInside(vaultDir, ".")}\0`;
  for (const [id, keys] of keySetCache) {
    if (!id.startsWith(prefix)) continue;
    zeroKeySet(keys);
    keySetCache.delete(id);
  }
}
```

Move the `import path from "node:path";` line up to join the other imports at the top of the file rather than leaving it mid-file.

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm run build && node --test test/keyring.test.mjs`
Expected: PASS, 10 tests.

- [ ] **Step 5: Run the whole suite to prove nothing regressed**

Run: `npm test`
Expected: PASS. No existing code imports `keyring.ts` yet, so this is a baseline check.

- [ ] **Step 6: Commit**

```bash
git add src/keyring.ts test/keyring.test.mjs
git commit -m "feat: detect vault format and resolve a cached keyset"
```

---

### Task 3: Keyed key-value envelope v2

**Files:**

- Modify: `src/crypto.ts`
- Modify: `test/keyring.test.mjs`

**Interfaces:**

- Consumes: nothing from earlier tasks. `crypto.ts` deliberately does not import `keyring.ts`; the caller passes the key in.
- Produces: `KEYED_ENVELOPE_VERSION = 2`, `KeyedEncryptedPayload`, `encryptWithKey(plaintext, key, name): KeyedEncryptedPayload`, `decryptWithKey(payload, key, name): string`. `AnyEncryptedPayload` widens to include the new shape.

`name` is the logical file identity — `health`, `finance`, `grants` — and it is authenticated, which is what stops one encrypted file being swapped for another.

- [ ] **Step 1: Write the failing test**

Append to `test/keyring.test.mjs`:

```js
import crypto from "node:crypto";

import { decrypt, decryptWithKey, encryptWithKey, envelopeVersion } from "../dist/crypto.js";

test("the keyed envelope binds its ciphertext to one file identity", () => {
  const key = crypto.randomBytes(32);
  const payload = encryptWithKey("BLOOD_TYPE=0 Rh+", key, "health");

  assert.equal(payload.version, 2);
  assert.equal(payload.cipher, "aes-256-gcm");
  assert.equal(payload.keyId, "kv");
  assert.equal(envelopeVersion(payload), 2);
  assert.equal(decryptWithKey(payload, key, "health"), "BLOOD_TYPE=0 Rh+");

  // Moving health.kv.enc onto finance.kv.enc must not decrypt.
  assert.throws(() => decryptWithKey(payload, key, "finance"));
  assert.throws(() => decryptWithKey(payload, crypto.randomBytes(32), "health"));
  assert.throws(() =>
    decryptWithKey({ ...payload, ciphertext: `${payload.ciphertext.slice(0, -2)}AA` }, key, "health"),
  );
});

test("the passphrase envelope refuses a keyed payload with a usable message", () => {
  const payload = encryptWithKey("secret", crypto.randomBytes(32), "health");
  assert.throws(() => decrypt(payload, PASSPHRASE), /keyring/u);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm run build && node --test test/keyring.test.mjs`
Expected: FAIL — `encryptWithKey is not a function`.

- [ ] **Step 3: Write the implementation**

In `src/crypto.ts`, add after the `LegacyEncryptedPayload` interface:

```ts
/** Envelope version written when the vault has a keyring: no KDF, the key comes from the keyset. */
export const KEYED_ENVELOPE_VERSION = 2;

export interface KeyedEncryptedPayload {
  version: 2;
  cipher: "aes-256-gcm";
  keyId: "kv";
  iv: string;
  authTag: string;
  ciphertext: string;
}
```

Widen the union:

```ts
export type AnyEncryptedPayload = EncryptedPayload | LegacyEncryptedPayload | KeyedEncryptedPayload;
```

Add the keyed pair at the end of the file:

```ts
const KEYED_AAD_CONTEXT = "secondbrain-vault:kv:v2";

/**
 * The logical file name is authenticated, so an attacker with write access
 * cannot swap one encrypted category for another and have it open as that
 * category. The v1 envelope could not do this: it bound only its own header.
 */
function keyedAad(name: string): Buffer {
  if (!name || name.length > 128) throw new Error("Invalid encrypted file identity.");
  return Buffer.from(
    JSON.stringify({ context: KEYED_AAD_CONTEXT, version: KEYED_ENVELOPE_VERSION, cipher: ALGO, keyId: "kv", name }),
    "utf8",
  );
}

export function encryptWithKey(plaintext: string, key: Buffer, name: string): KeyedEncryptedPayload {
  if (key.length !== KEY_LEN) throw new Error("A 256-bit key is required.");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  cipher.setAAD(keyedAad(name));
  const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return {
    version: KEYED_ENVELOPE_VERSION,
    cipher: ALGO,
    keyId: "kv",
    iv: iv.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64"),
    ciphertext: enc.toString("base64"),
  };
}

export function decryptWithKey(payload: KeyedEncryptedPayload, key: Buffer, name: string): string {
  if (payload.version !== KEYED_ENVELOPE_VERSION) {
    throw new Error(`Unsupported keyed envelope version: ${String(payload.version)}`);
  }
  if (payload.cipher !== ALGO) throw new Error("Unsupported cipher in encrypted envelope.");
  if (payload.keyId !== "kv") throw new Error(`Unsupported key ID in encrypted envelope: ${String(payload.keyId)}`);
  if (key.length !== KEY_LEN) throw new Error("A 256-bit key is required.");
  const decipher = crypto.createDecipheriv(ALGO, key, base64Bytes(payload.iv, 12, 12, "iv"));
  decipher.setAAD(keyedAad(name));
  decipher.setAuthTag(base64Bytes(payload.authTag, 16, 16, "authentication tag"));
  return Buffer.concat([
    decipher.update(Buffer.from(payload.ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");
}
```

In `decrypt`, replace the "version too new" guard so a keyed payload gets an accurate message instead of an upgrade prompt. Change:

```ts
  if (version > ENVELOPE_VERSION) {
    throw new Error(
      `This vault file uses envelope version ${version}; this build understands up to ${ENVELOPE_VERSION}. Upgrade Vault Brain to open it.`,
    );
  }
```

to:

```ts
  if (version === KEYED_ENVELOPE_VERSION) {
    throw new Error("This file is encrypted with the vault keyring; open it with the vault's keyset, not a passphrase.");
  }
  if (version > ENVELOPE_VERSION) {
    throw new Error(
      `This vault file uses envelope version ${version}; this build understands up to ${ENVELOPE_VERSION}. Upgrade Vault Brain to open it.`,
    );
  }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm run build && node --test test/keyring.test.mjs`
Expected: PASS, 12 tests.

- [ ] **Step 5: Run the durability tests, which pin the v0 and v1 envelopes**

Run: `npm run build && node --test test/durability.test.mjs test/core.test.mjs`
Expected: PASS. The existing `decrypt({ ...payload, version: 9 })` assertion still matches `/envelope version 9/`.

- [ ] **Step 6: Commit**

```bash
git add src/crypto.ts test/keyring.test.mjs
git commit -m "feat: add a keyed key-value envelope bound to its file identity"
```

---

### Task 4: Route key-value files and grants through the keyring

**Files:**

- Modify: `src/store.ts`
- Modify: `src/grants.ts`
- Modify: `test/keyring.test.mjs`

**Interfaces:**

- Consumes: `openVaultKeys` (Task 2); `encryptWithKey`, `decryptWithKey`, `KEYED_ENVELOPE_VERSION` (Task 3).
- Produces: no new exports. `loadVaultFile`, `saveVaultFile`, `migrateVaultFile`, `loadGrants` and `saveGrants` keep their current signatures.

The read path accepts v0, v1 and v2 in every mode. This matters: a migration interrupted between writing the keyring and rewriting the last key-value file leaves a keyring vault holding v1 files, and those must still open.

- [ ] **Step 1: Write the failing test**

Append to `test/keyring.test.mjs`:

```js
import { loadVaultFile, saveVaultFile, vaultFileEnvelopeVersion } from "../dist/store.js";

test("key-value files use the keyed envelope once a vault has a keyring", () => {
  const vault = tempVault();
  saveVaultFile(vault, "health", [{ key: "BLOOD_TYPE", value: "0 Rh+", desc: "blood group" }], PASSPHRASE);
  assert.equal(vaultFileEnvelopeVersion(vault, "health"), 1);

  seedKeyring(vault, PASSPHRASE);

  // A v1 file written before the keyring existed still opens.
  assert.deepEqual(loadVaultFile(vault, "health", PASSPHRASE), [
    { key: "BLOOD_TYPE", value: "0 Rh+", desc: "blood group" },
  ]);

  // The next write uses the keyset.
  saveVaultFile(vault, "health", [{ key: "BLOOD_TYPE", value: "A Rh-", desc: "blood group" }], PASSPHRASE);
  assert.equal(vaultFileEnvelopeVersion(vault, "health"), 2);
  assert.deepEqual(loadVaultFile(vault, "health", PASSPHRASE), [
    { key: "BLOOD_TYPE", value: "A Rh-", desc: "blood group" },
  ]);
});

test("a keyed key-value file cannot be renamed into another category", () => {
  const vault = tempVault();
  seedKeyring(vault, PASSPHRASE);
  saveVaultFile(vault, "health", [{ key: "BLOOD_TYPE", value: "0 Rh+", desc: "blood group" }], PASSPHRASE);

  fs.copyFileSync(path.join(vault, "health.kv.enc"), path.join(vault, "finance.kv.enc"));
  assert.throws(() => loadVaultFile(vault, "finance", PASSPHRASE));
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm run build && node --test test/keyring.test.mjs`
Expected: FAIL — the second write is still envelope v1, so the `vaultFileEnvelopeVersion(vault, "health") === 2` assertion fails.

- [ ] **Step 3: Write the store implementation**

In `src/store.ts`, extend the imports:

```ts
import {
  decrypt,
  decryptWithKey,
  encrypt,
  encryptWithKey,
  ENVELOPE_VERSION,
  envelopeVersion,
  KEYED_ENVELOPE_VERSION,
  type AnyEncryptedPayload,
  type KeyedEncryptedPayload,
} from "./crypto.js";
import { openVaultKeys } from "./keyring.js";
```

Add a helper above `loadVaultFile`:

```ts
/** The keyed key-value key when this vault has a keyring, otherwise null. */
function kvKey(vaultDir: string, passphrase: string): Buffer | null {
  return openVaultKeys(vaultDir, passphrase)?.kv ?? null;
}
```

Replace the body of `loadVaultFile`:

```ts
export function loadVaultFile(
  vaultDir: string,
  name: string,
  passphrase: string
): KVEntry[] {
  const filePath = vaultFilePath(vaultDir, name);
  if (!fs.existsSync(filePath)) return [];
  assertNotSymlink(filePath);
  const payload: AnyEncryptedPayload = JSON.parse(fs.readFileSync(filePath, "utf8"));
  // A vault interrupted mid-migration holds a keyring and older files at the
  // same time, so both envelopes stay readable regardless of vault format.
  const plaintext =
    envelopeVersion(payload) === KEYED_ENVELOPE_VERSION
      ? decryptWithKey(payload as KeyedEncryptedPayload, requireKvKey(vaultDir, passphrase), normalizeVaultName(name))
      : decrypt(payload, passphrase);
  return parseKV(plaintext);
}

function requireKvKey(vaultDir: string, passphrase: string): Buffer {
  const key = kvKey(vaultDir, passphrase);
  if (!key) throw new Error("This file is keyring-encrypted but the vault has no readable keyring.");
  return key;
}
```

Replace the body of `saveVaultFile`:

```ts
export function saveVaultFile(
  vaultDir: string,
  name: string,
  entries: KVEntry[],
  passphrase: string
): void {
  if (!fs.existsSync(vaultDir)) fs.mkdirSync(vaultDir, { recursive: true });
  const filePath = vaultFilePath(vaultDir, name);
  const plaintext = serializeKV(entries);
  const key = kvKey(vaultDir, passphrase);
  const payload = key
    ? encryptWithKey(plaintext, key, normalizeVaultName(name))
    : encrypt(plaintext, passphrase);
  writeFileAtomic(filePath, JSON.stringify(payload, null, 2), { mode: 0o600 });
}
```

Replace `migrateVaultFile` so its target follows the vault's format:

```ts
export function migrateVaultFile(
  vaultDir: string,
  name: string,
  passphrase: string
): MigrationReport {
  const from = vaultFileEnvelopeVersion(vaultDir, name);
  if (from === undefined) throw new Error(`No such vault file: ${name}`);
  const to = kvKey(vaultDir, passphrase) ? KEYED_ENVELOPE_VERSION : ENVELOPE_VERSION;
  if (from === to) return { name, from, to, migrated: false };
  const entries = loadVaultFile(vaultDir, name, passphrase);
  saveVaultFile(vaultDir, name, entries, passphrase);
  return { name, from, to, migrated: true };
}
```

- [ ] **Step 4: Write the grants implementation**

In `src/grants.ts`, extend the imports:

```ts
import {
  decrypt,
  decryptWithKey,
  encrypt,
  encryptWithKey,
  envelopeVersion,
  KEYED_ENVELOPE_VERSION,
  type AnyEncryptedPayload,
  type KeyedEncryptedPayload,
} from "./crypto.js";
import { openVaultKeys } from "./keyring.js";
```

Add above `loadGrants`:

```ts
const GRANTS_FILE_IDENTITY = "grants";
```

In `loadGrants`, replace the decryption line:

```ts
  const parsed: GrantFile = JSON.parse(
    envelopeVersion(payload) === KEYED_ENVELOPE_VERSION
      ? decryptWithKey(payload as KeyedEncryptedPayload, requireGrantsKey(vaultDir, passphrase), GRANTS_FILE_IDENTITY)
      : decrypt(payload, passphrase),
  );
```

and add the helper next to it:

```ts
function requireGrantsKey(vaultDir: string, passphrase: string): Buffer {
  const key = openVaultKeys(vaultDir, passphrase)?.kv;
  if (!key) throw new Error("The grant file is keyring-encrypted but the vault has no readable keyring.");
  return key;
}
```

In `saveGrants`, replace the write:

```ts
  const key = openVaultKeys(vaultDir, passphrase)?.kv ?? null;
  const payload = key
    ? encryptWithKey(JSON.stringify(stored), key, GRANTS_FILE_IDENTITY)
    : encrypt(JSON.stringify(stored), passphrase);
  writeFileAtomic(path, JSON.stringify(payload, null, 2), { mode: 0o600 });
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `npm run build && node --test test/keyring.test.mjs test/core.test.mjs test/grants.test.mjs test/durability.test.mjs`
Expected: PASS. `durability.test.mjs` covers the `kv-envelope-v0` fixture, which has no keyring and must still migrate v0 → v1.

- [ ] **Step 6: Commit**

```bash
git add src/store.ts src/grants.ts test/keyring.test.mjs
git commit -m "feat: encrypt key-value files and grants with the keyring key"
```

---

### Task 5: Take the audit chain key from the keyring

**Files:**

- Modify: `src/audit.ts`
- Modify: `test/keyring.test.mjs`

**Interfaces:**

- Consumes: `openVaultKeys` (Task 2).
- Produces: no new exports. `appendAudit` and `verifyAudit` keep their signatures.

`keyring.ts` must not import `audit.ts`, so the direction is one-way: `audit.ts` asks the keyring for its key and falls back to its own `audit.meta.json` derivation when there is none.

- [ ] **Step 1: Write the failing test**

Append to `test/keyring.test.mjs`:

```js
import { appendAudit, verifyAudit } from "../dist/audit.js";

test("the audit chain keeps verifying after a keyring appears", () => {
  const vault = tempVault();
  appendAudit(vault, { actor: "cli-direct", file: "health", key: "BLOOD_TYPE" }, PASSPHRASE);
  assert.equal(verifyAudit(vault, PASSPHRASE).valid, true);

  seedKeyring(vault, PASSPHRASE);

  // The keyring's audit key is new material, so entries signed with the old
  // one no longer verify. Migration adopts the old key precisely to avoid
  // this; here we prove the two keys are genuinely distinct.
  assert.equal(verifyAudit(vault, PASSPHRASE).valid, false);

  const fresh = tempVault();
  seedKeyring(fresh, PASSPHRASE);
  appendAudit(fresh, { actor: "cli-direct", file: "health", key: "BLOOD_TYPE" }, PASSPHRASE);
  const verified = verifyAudit(fresh, PASSPHRASE);
  assert.equal(verified.valid, true);
  assert.equal(verified.signedEntries, 1);
  assert.equal(fs.existsSync(path.join(fresh, "audit.meta.json")), false);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm run build && node --test test/keyring.test.mjs`
Expected: FAIL — `audit.meta.json` is still created in a keyring vault, so the last assertion fails.

- [ ] **Step 3: Write the implementation**

In `src/audit.ts`, add the import:

```ts
import { openVaultKeys } from "./keyring.js";
```

Add below `auditKey`:

```ts
/**
 * A keyring vault keeps its chain key in the keyset, so changing the
 * passphrase later cannot orphan the audit history. A legacy vault keeps
 * deriving from `audit.meta.json` exactly as before.
 */
function chainKeyForAppend(vaultDir: string, passphrase: string): Buffer {
  const keys = openVaultKeys(vaultDir, passphrase);
  if (keys) return keys.audit;
  return auditKey(vaultDir, passphrase, loadOrCreateMeta(vaultDir));
}
```

In `appendAudit`, replace:

```ts
  const hash = calculateHash(unsigned, auditKey(vaultDir, passphrase, loadOrCreateMeta(vaultDir)));
```

with:

```ts
  const hash = calculateHash(unsigned, chainKeyForAppend(vaultDir, passphrase));
```

In `verifyAudit`, replace:

```ts
  const meta = loadMeta(vaultDir);
  if (!meta) {
    return { valid: false, signedEntries: signed.length, legacyEntries, error: "Missing audit metadata." };
  }

  const key = auditKey(vaultDir, passphrase, meta);
```

with:

```ts
  const keys = openVaultKeys(vaultDir, passphrase);
  let key: Buffer;
  if (keys) {
    key = keys.audit;
  } else {
    const meta = loadMeta(vaultDir);
    if (!meta) {
      return { valid: false, signedEntries: signed.length, legacyEntries, error: "Missing audit metadata." };
    }
    key = auditKey(vaultDir, passphrase, meta);
  }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm run build && node --test test/keyring.test.mjs test/core.test.mjs test/workflows.test.mjs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/audit.ts test/keyring.test.mjs
git commit -m "feat: take the audit chain key from the vault keyring"
```

---

### Task 6: Split the document, attachment-identity and sync-change keys

**Files:**

- Modify: `src/document-crypto.ts`
- Modify: `src/documents.ts`
- Modify: `src/sync/change-log.ts`
- Modify: `test/keyring.test.mjs`

**Interfaces:**

- Consumes: `openVaultKeys` (Task 2).
- Produces: `DocumentKeySession` gains `attachmentIdKey: Buffer` and `syncChangeKey: Buffer`; `manifest` becomes `DocumentManifest | null`. `openDocumentKey(vaultDir, passphrase)` keeps its signature.

In a legacy vault the three keys hold the same bytes in three separate buffers, so nothing about a legacy vault's behaviour changes. In a keyring vault they are independent.

- [ ] **Step 1: Write the failing test**

Append to `test/keyring.test.mjs`:

```js
import { openDocumentKey } from "../dist/document-crypto.js";
import { DocumentVault } from "../dist/documents.js";

test("a legacy session uses one key for content and identity, a keyring session does not", () => {
  const legacy = tempVault();
  const legacySession = openDocumentKey(legacy, PASSPHRASE);
  assert.equal(legacySession.attachmentIdKey.toString("base64"), legacySession.key.toString("base64"));
  assert.equal(legacySession.syncChangeKey.toString("base64"), legacySession.key.toString("base64"));

  const keyed = tempVault();
  const keys = seedKeyring(keyed, PASSPHRASE);
  const session = openDocumentKey(keyed, PASSPHRASE);
  assert.equal(session.key.toString("base64"), keys.documents.toString("base64"));
  assert.equal(session.attachmentIdKey.toString("base64"), keys.attachmentId.toString("base64"));
  assert.equal(session.syncChangeKey.toString("base64"), keys.syncChange.toString("base64"));
  assert.equal(session.manifest, null);
});

test("a keyring vault stores and reads attachments end to end", () => {
  const vault = tempVault();
  seedKeyring(vault, PASSPHRASE);
  const documents = new DocumentVault(vault, PASSPHRASE);
  const info = documents.putAttachment(Buffer.from("attachment bytes"), "note.txt", "text/plain");
  assert.equal(documents.getAttachment(info.id).data.toString("utf8"), "attachment bytes");
  documents.lock();
});

test("locking zeroizes every key the session was handed", () => {
  const vault = tempVault();
  seedKeyring(vault, PASSPHRASE);
  const documents = new DocumentVault(vault, PASSPHRASE);
  documents.lock();
  // A second vault opened afterwards must still work: the cache handed out copies.
  const second = new DocumentVault(vault, PASSPHRASE);
  assert.deepEqual(second.list(), []);
  second.lock();
});

test("a version 2 manifest without a keyring fails closed", () => {
  const vault = tempVault();
  fs.mkdirSync(path.join(vault, "documents"), { recursive: true });
  fs.writeFileSync(path.join(vault, "documents", "manifest.json"), JSON.stringify({ version: 2, keyring: true }));
  assert.throws(() => openDocumentKey(vault, PASSPHRASE), /keyring/u);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm run build && node --test test/keyring.test.mjs`
Expected: FAIL — `session.attachmentIdKey` is undefined.

- [ ] **Step 3: Update `src/document-crypto.ts`**

Add the import:

```ts
import { openVaultKeys } from "./keyring.js";
```

Replace the `DocumentKeySession` interface:

```ts
export interface DocumentKeySession {
  rootDir: string;
  /** Encrypts every object under `documents/`. */
  key: Buffer;
  /** Keys the content address of an attachment. Never rotated. */
  attachmentIdKey: Buffer;
  /** Keys sync change IDs and their envelope subkeys. Never rotated. */
  syncChangeKey: Buffer;
  /** The legacy manifest, or null when the keys came from the vault keyring. */
  manifest: DocumentManifest | null;
}
```

Replace `openDocumentKey` with:

```ts
export function openDocumentKey(vaultDir: string, passphrase: string): DocumentKeySession {
  if (!passphrase) throw new Error("A non-empty vault passphrase is required.");
  const rootDir = resolveInside(vaultDir, "documents");
  const manifestPath = resolveInside(rootDir, "manifest.json");
  assertNoSymlinkComponents(vaultDir, rootDir);
  fs.mkdirSync(rootDir, { recursive: true, mode: 0o700 });

  const vaultKeys = openVaultKeys(vaultDir, passphrase);
  if (vaultKeys) {
    return {
      rootDir,
      key: vaultKeys.documents,
      attachmentIdKey: vaultKeys.attachmentId,
      syncChangeKey: vaultKeys.syncChange,
      manifest: null,
    };
  }

  let manifest: DocumentManifest;
  if (fs.existsSync(manifestPath)) {
    assertNotSymlink(manifestPath);
    manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as DocumentManifest;
    if ((manifest.version as number) === 2) {
      throw new Error("This vault was upgraded to a keyring, but keyring.json is missing or unreadable.");
    }
    if (
      manifest.version !== 1 ||
      manifest.kdf?.name !== "scrypt" ||
      manifest.kdf.N !== SCRYPT_N ||
      !manifest.kdf.salt ||
      !/^[a-f0-9]{64}$/u.test(manifest.verifier)
    ) {
      throw new Error("Unsupported or invalid document vault manifest.");
    }
    const key = derive(passphrase, Buffer.from(manifest.kdf.salt, "base64"), manifest.kdf.N);
    const actual = Buffer.from(verifier(key), "hex");
    const expected = Buffer.from(manifest.verifier, "hex");
    if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
      throw new Error("Unable to unlock document vault: wrong passphrase or damaged manifest.");
    }
    return { rootDir, key, attachmentIdKey: Buffer.from(key), syncChangeKey: Buffer.from(key), manifest };
  }

  const salt = crypto.randomBytes(16);
  const key = derive(passphrase, salt, SCRYPT_N);
  manifest = {
    version: 1,
    kdf: { name: "scrypt", N: SCRYPT_N, salt: salt.toString("base64") },
    verifier: verifier(key),
  };
  writeFileAtomic(manifestPath, JSON.stringify(manifest, null, 2), { mode: 0o600 });
  return { rootDir, key, attachmentIdKey: Buffer.from(key), syncChangeKey: Buffer.from(key), manifest };
}
```

- [ ] **Step 4: Update `src/documents.ts`**

At `src/documents.ts:521`, replace:

```ts
    this.session.key.fill(0);
```

with:

```ts
    this.session.key.fill(0);
    this.session.attachmentIdKey.fill(0);
    this.session.syncChangeKey.fill(0);
```

There are exactly **three** attachment content-address computations, at `src/documents.ts:2130`, `:2166` and `:2207`. Each is a `createHmac` line immediately followed by the `attachment-id:v1` update. Change the key argument in all three from `this.session.key` to `this.session.attachmentIdKey`. Each becomes:

```ts
      .createHmac("sha256", this.session.attachmentIdKey)
      .update("secondbrain-vault:attachment-id:v1\0", "utf8")
```

The three sites are: the attachment preparation helper (`:2130`), `putAttachment` (`:2166`), and `getAttachment`'s integrity recomputation (`:2207`). Miss one and attachments written before a re-key stop verifying.

Confirm none is left on the documents key:

```bash
grep -n -B1 "attachment-id:v1" src/documents.ts
```

Expected: three matches, each preceded by `createHmac("sha256", this.session.attachmentIdKey)`.

- [ ] **Step 5: Update `src/sync/change-log.ts`**

Replace `close()` and add the sync key accessor:

```ts
  close(): void {
    if (this.closed) return;
    this.session.key.fill(0);
    this.session.attachmentIdKey.fill(0);
    this.session.syncChangeKey.fill(0);
    this.closed = true;
  }

  private key(): Buffer {
    if (this.closed) throw new Error("Sync change log is closed.");
    return this.session.key;
  }

  /** Change IDs and their envelope subkeys are keyed by an identity key that survives a re-key. */
  private syncKey(): Buffer {
    if (this.closed) throw new Error("Sync change log is closed.");
    return this.session.syncChangeKey;
  }
```

Change every `sealSyncChange(body, this.key())` to `sealSyncChange(body, this.syncKey())` and every `openSyncChange(envelope, this.key())` to `openSyncChange(envelope, this.syncKey())`. Leave `readAppliedState` and `saveAppliedState` on `this.key()` — `applied.enc` is a document object, not a change.

Confirm with:

```bash
grep -n "sealSyncChange\|openSyncChange" src/sync/change-log.ts
```

Every reported line must pass `this.syncKey()`.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `npm test`
Expected: PASS, including all four sync test files and the attachment fixtures.

- [ ] **Step 7: Commit**

```bash
git add src/document-crypto.ts src/documents.ts src/sync/change-log.ts test/keyring.test.mjs
git commit -m "feat: separate document, attachment-identity and sync-change keys"
```

---

### Task 7: Migrate a vault to the keyring

**Files:**

- Create: `src/keyring-migrate.ts`
- Create: `test/keyring-migrate.test.mjs`
- Modify: `src/cli.ts`
- Modify: `package.json` (test script)

**Interfaces:**

- Consumes: `randomKeySet`, `wrapKeySet`, `writeKeyring`, `readKeyring`, `detectVaultFormat`, `forgetVaultKeys`, `KEY_NAMES`, `KeySet` (Tasks 1–2); `listVaultFiles`, `loadVaultFile`, `saveVaultFile`, `vaultFileEnvelopeVersion` (Task 4); `loadGrants`, `saveGrants` (Task 4); `withVaultLock` from `src/vault-lock.js`.
- Produces: `KeyringMigrationReport`, `migrateToKeyring(vaultDir, passphrase): KeyringMigrationReport`.

The migration is resumable. It never returns early merely because a keyring already exists: a run interrupted after the keyring was written finishes the key-value rewrite and the manifest tombstone on the next run.

- [ ] **Step 1: Write the failing test**

Create `test/keyring-migrate.test.mjs`:

```js
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { appendAudit, verifyAudit } from "../dist/audit.js";
import { encrypt } from "../dist/crypto.js";
import { DocumentVault } from "../dist/documents.js";
import { serializeKV } from "../dist/format.js";
import { detectVaultFormat } from "../dist/keyring.js";
import { migrateToKeyring } from "../dist/keyring-migrate.js";
import { loadVaultFile, saveVaultFile, upsertEntry, vaultFileEnvelopeVersion } from "../dist/store.js";

const FIXTURES = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "fixtures");
const FIXTURE_PASSPHRASE = "fixture-only-passphrase";
const PASSPHRASE = "migrate-test-passphrase";

function tempDir(label = "migrate") {
  return fs.mkdtempSync(path.join(os.tmpdir(), `vault-brain-${label}-`));
}

function copyFixture(name) {
  const target = tempDir(name);
  fs.cpSync(path.join(FIXTURES, name), target, { recursive: true });
  return target;
}

test("migration adopts the legacy key so attachment identities never move", () => {
  const vault = copyFixture("documents-attachments-v1");

  const before = new DocumentVault(vault, FIXTURE_PASSPHRASE);
  const identities = before.listAttachments().map((info) => ({ id: info.id, size: info.size }));
  assert.ok(identities.length > 0, "the fixture must contain attachments");
  before.lock();

  const report = migrateToKeyring(vault, FIXTURE_PASSPHRASE);
  assert.equal(report.created, true);
  assert.ok(report.adopted.includes("documents"));
  assert.ok(report.adopted.includes("attachmentId"));
  assert.ok(report.adopted.includes("syncChange"));
  assert.equal(detectVaultFormat(vault), "keyring");

  const after = new DocumentVault(vault, FIXTURE_PASSPHRASE);
  assert.deepEqual(
    after.listAttachments().map((info) => ({ id: info.id, size: info.size })),
    identities,
  );
  for (const { id } of identities) {
    // getAttachment recomputes the content address and throws when it moved.
    assert.ok(after.getAttachment(id).data.length > 0);
  }
  after.lock();
});

test("migration keeps notes, revisions and search working", () => {
  const vault = copyFixture("documents-v1");

  const before = new DocumentVault(vault, FIXTURE_PASSPHRASE);
  const notes = before.list().map((note) => ({ id: note.id, path: note.path }));
  before.lock();

  migrateToKeyring(vault, FIXTURE_PASSPHRASE);

  const after = new DocumentVault(vault, FIXTURE_PASSPHRASE);
  assert.deepEqual(after.list().map((note) => ({ id: note.id, path: note.path })), notes);
  for (const { id } of notes) assert.ok(after.get(id).body.length >= 0);
  after.lock();
});

test("migration adopts the audit key so the existing chain still verifies", () => {
  const vault = tempDir("audit");
  upsertEntry(vault, "health", "BLOOD_TYPE", "0 Rh+", "blood group", PASSPHRASE);
  appendAudit(vault, { actor: "cli-direct-write", file: "health", key: "BLOOD_TYPE" }, PASSPHRASE);
  assert.equal(verifyAudit(vault, PASSPHRASE).valid, true);

  const report = migrateToKeyring(vault, PASSPHRASE);
  assert.ok(report.adopted.includes("audit"));
  assert.equal(verifyAudit(vault, PASSPHRASE).valid, true);

  appendAudit(vault, { actor: "cli-direct", file: "health", key: "BLOOD_TYPE" }, PASSPHRASE);
  const verified = verifyAudit(vault, PASSPHRASE);
  assert.equal(verified.valid, true);
  assert.equal(verified.signedEntries, 2);
});

test("migration rewrites key-value files and the manifest tombstone", () => {
  const vault = tempDir("kv");
  upsertEntry(vault, "health", "BLOOD_TYPE", "0 Rh+", "blood group", PASSPHRASE);
  assert.equal(vaultFileEnvelopeVersion(vault, "health"), 1);
  new DocumentVault(vault, PASSPHRASE).lock();

  const report = migrateToKeyring(vault, PASSPHRASE);
  assert.deepEqual(report.kvFilesRewritten, ["health"]);
  assert.equal(report.manifestTombstoned, true);
  assert.equal(vaultFileEnvelopeVersion(vault, "health"), 2);
  assert.deepEqual(loadVaultFile(vault, "health", PASSPHRASE), [
    { key: "BLOOD_TYPE", value: "0 Rh+", desc: "blood group" },
  ]);

  const manifest = JSON.parse(fs.readFileSync(path.join(vault, "documents", "manifest.json"), "utf8"));
  assert.deepEqual(manifest, { version: 2, keyring: true });
  assert.equal(manifest.verifier, undefined);
});

test("a key-value-only vault generates the keys it cannot adopt", () => {
  const vault = tempDir("kvonly");
  saveVaultFile(vault, "health", [{ key: "BLOOD_TYPE", value: "0 Rh+", desc: "blood group" }], PASSPHRASE);

  const report = migrateToKeyring(vault, PASSPHRASE);
  assert.equal(report.created, true);
  assert.deepEqual(report.adopted, []);
  assert.deepEqual(report.generated.sort(), ["attachmentId", "audit", "documents", "kv", "syncChange"]);
  assert.equal(report.manifestTombstoned, false);
  assert.deepEqual(loadVaultFile(vault, "health", PASSPHRASE), [
    { key: "BLOOD_TYPE", value: "0 Rh+", desc: "blood group" },
  ]);
});

test("migration is idempotent and finishes an interrupted run", () => {
  const vault = tempDir("resume");
  upsertEntry(vault, "health", "BLOOD_TYPE", "0 Rh+", "blood group", PASSPHRASE);
  new DocumentVault(vault, PASSPHRASE).lock();

  migrateToKeyring(vault, PASSPHRASE);
  const second = migrateToKeyring(vault, PASSPHRASE);
  assert.equal(second.created, false);
  assert.deepEqual(second.kvFilesRewritten, []);

  // Simulate a crash between writing the keyring and rewriting a file: a
  // passphrase-enveloped file sitting in a vault that already has a keyring.
  const stale = encrypt(serializeKV([{ key: "IBAN", value: "TR00", desc: "iban" }]), PASSPHRASE);
  fs.writeFileSync(path.join(vault, "stale.kv.enc"), JSON.stringify(stale, null, 2));
  assert.equal(vaultFileEnvelopeVersion(vault, "stale"), 1);

  const third = migrateToKeyring(vault, PASSPHRASE);
  assert.equal(third.created, false);
  assert.deepEqual(third.kvFilesRewritten, ["stale"]);
  assert.equal(vaultFileEnvelopeVersion(vault, "stale"), 2);
  assert.deepEqual(loadVaultFile(vault, "stale", PASSPHRASE), [{ key: "IBAN", value: "TR00", desc: "iban" }]);
});
```

Every test here uses one passphrase per vault. The `stale.kv.enc` file is written with `encrypt` — the v1 passphrase envelope — into a vault that already carries a keyring, which is exactly the state a run interrupted between step 6 and step 7 leaves behind.

- [ ] **Step 2: Add the test file to the suite**

In `package.json`, append ` test/keyring-migrate.test.mjs` to the end of the `test` script value.

- [ ] **Step 3: Run the test to verify it fails**

Run: `npm run build && node --test test/keyring-migrate.test.mjs`
Expected: FAIL — `Cannot find module '.../dist/keyring-migrate.js'`.

- [ ] **Step 4: Write the implementation**

Create `src/keyring-migrate.ts`:

```ts
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { assertNotSymlink, writeFileAtomic } from "./fs-safe.js";
import { loadGrants, saveGrants } from "./grants.js";
import {
  detectVaultFormat,
  forgetVaultKeys,
  randomKeySet,
  wrapKeySet,
  writeKeyring,
  type KeyName,
  type KeySet,
} from "./keyring.js";
import { resolveInside } from "./safety.js";
import { listVaultFiles, loadVaultFile, saveVaultFile, vaultFileEnvelopeVersion } from "./store.js";
import { withVaultLock } from "./vault-lock.js";

const LEGACY_SCRYPT_N = 2 ** 15;
const LEGACY_KEY_LENGTH = 32;
const LEGACY_KEY_CHECK_CONTEXT = "secondbrain-vault:document-key:v1";

export interface KeyringMigrationReport {
  /** True when this run wrote the keyring; false when it resumed or did nothing. */
  created: boolean;
  adopted: KeyName[];
  generated: KeyName[];
  kvFilesRewritten: string[];
  grantsRewritten: boolean;
  manifestTombstoned: boolean;
}

function legacyDerive(passphrase: string, salt: Buffer, N: number): Buffer {
  return crypto.scryptSync(passphrase, salt, LEGACY_KEY_LENGTH, { N, maxmem: 256 * 1024 * 1024 });
}

/**
 * The legacy document key, or null when this vault never used the document
 * engine. Reading is enough: this never creates a manifest, because creating
 * one during a migration would invent material to adopt.
 */
function legacyDocumentKey(vaultDir: string, passphrase: string): Buffer | null {
  const manifestPath = resolveInside(vaultDir, path.join("documents", "manifest.json"));
  if (!fs.existsSync(manifestPath)) return null;
  assertNotSymlink(manifestPath);
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as {
    version?: number;
    kdf?: { name?: string; N?: number; salt?: string };
    verifier?: string;
  };
  if (manifest.version === 2) return null;
  if (
    manifest.version !== 1 ||
    manifest.kdf?.name !== "scrypt" ||
    manifest.kdf.N !== LEGACY_SCRYPT_N ||
    !manifest.kdf.salt ||
    typeof manifest.verifier !== "string" ||
    !/^[a-f0-9]{64}$/u.test(manifest.verifier)
  ) {
    throw new Error("Unsupported or invalid document vault manifest.");
  }
  const key = legacyDerive(passphrase, Buffer.from(manifest.kdf.salt, "base64"), manifest.kdf.N);
  const actual = crypto.createHmac("sha256", key).update(LEGACY_KEY_CHECK_CONTEXT).digest();
  const expected = Buffer.from(manifest.verifier, "hex");
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
    key.fill(0);
    throw new Error("Unable to unlock document vault: wrong passphrase or damaged manifest.");
  }
  return key;
}

/**
 * The legacy audit chain key, or null when this vault has no audit metadata.
 * Read here rather than imported from `audit.ts` so that `keyring.ts` and its
 * migration stay free of a cycle back through the modules that consume them.
 */
function legacyAuditKey(vaultDir: string, passphrase: string): Buffer | null {
  const metaPath = resolveInside(vaultDir, "audit.meta.json");
  if (!fs.existsSync(metaPath)) return null;
  assertNotSymlink(metaPath);
  const meta = JSON.parse(fs.readFileSync(metaPath, "utf8")) as { version?: number; salt?: string };
  if (meta.version !== 1 || !meta.salt) throw new Error("Invalid audit metadata.");
  return legacyDerive(passphrase, Buffer.from(meta.salt, "base64"), LEGACY_SCRYPT_N);
}

function tombstoneManifest(vaultDir: string): boolean {
  const manifestPath = resolveInside(vaultDir, path.join("documents", "manifest.json"));
  if (!fs.existsSync(manifestPath)) return false;
  assertNotSymlink(manifestPath);
  const current = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as { version?: number };
  if (current.version === 2) return false;
  writeFileAtomic(manifestPath, `${JSON.stringify({ version: 2, keyring: true }, null, 2)}\n`, { mode: 0o600 });
  return true;
}

/**
 * Upgrades a vault to the keyring format. Existing keys are adopted verbatim,
 * so attachment content IDs, sync change IDs and the audit chain all keep
 * verifying and not one encrypted object is rewritten.
 *
 * Resumable: a run interrupted after the keyring was written finishes the
 * remaining key-value rewrites and the manifest tombstone on the next call.
 */
export function migrateToKeyring(vaultDir: string, passphrase: string): KeyringMigrationReport {
  if (!passphrase) throw new Error("A non-empty vault passphrase is required.");
  return withVaultLock(vaultDir, () => {
    const adopted: KeyName[] = [];
    const generated: KeyName[] = [];
    let created = false;

    if (detectVaultFormat(vaultDir) !== "keyring") {
      const documentKey = legacyDocumentKey(vaultDir, passphrase);
      const auditKey = legacyAuditKey(vaultDir, passphrase);
      const keys: KeySet = randomKeySet();

      if (documentKey) {
        for (const name of ["documents", "attachmentId", "syncChange"] as const) {
          keys[name] = Buffer.from(documentKey);
          adopted.push(name);
        }
        documentKey.fill(0);
      } else {
        generated.push("documents", "attachmentId", "syncChange");
      }

      if (auditKey) {
        keys.audit = auditKey;
        adopted.push("audit");
      } else {
        generated.push("audit");
      }
      generated.push("kv");

      // Prove every key-value file opens before committing the keyring, so a
      // wrong passphrase cannot leave a vault half-converted.
      const pending = new Map(listVaultFiles(vaultDir).map((name) => [name, loadVaultFile(vaultDir, name, passphrase)]));
      const grants = loadGrants(vaultDir, passphrase);

      writeKeyring(vaultDir, { version: 2, slots: [wrapKeySet(keys, passphrase)] });
      forgetVaultKeys(vaultDir);
      created = true;

      for (const [name, entries] of pending) saveVaultFile(vaultDir, name, entries, passphrase);
      if (grants) saveGrants(vaultDir, grants, passphrase);

      return {
        created,
        adopted,
        generated,
        kvFilesRewritten: [...pending.keys()],
        grantsRewritten: grants !== null,
        manifestTombstoned: tombstoneManifest(vaultDir),
      };
    }

    // Resume: the keyring exists, so finish anything an earlier run left behind.
    const kvFilesRewritten: string[] = [];
    for (const name of listVaultFiles(vaultDir)) {
      if (vaultFileEnvelopeVersion(vaultDir, name) === 2) continue;
      saveVaultFile(vaultDir, name, loadVaultFile(vaultDir, name, passphrase), passphrase);
      kvFilesRewritten.push(name);
    }
    let grantsRewritten = false;
    const grants = loadGrants(vaultDir, passphrase);
    if (grants) {
      const grantsPath = resolveInside(vaultDir, "grants.enc");
      const payload = JSON.parse(fs.readFileSync(grantsPath, "utf8")) as { version?: number };
      if (payload.version !== 2) {
        saveGrants(vaultDir, grants, passphrase);
        grantsRewritten = true;
      }
    }
    return {
      created: false,
      adopted,
      generated,
      kvFilesRewritten,
      grantsRewritten,
      manifestTombstoned: tombstoneManifest(vaultDir),
    };
  });
}
```

`@typescript-eslint/no-unused-vars` is an error in this project, so every import in this file must actually be used. `import path from "node:path";` belongs at the top with the others — `resolveInside` takes a relative path and `path.join` is what builds `documents/manifest.json` portably.

- [ ] **Step 5: Run the test to verify it passes**

Run: `npm run build && node --test test/keyring-migrate.test.mjs`
Expected: PASS, 6 tests.

- [ ] **Step 6: Wire the CLI**

In `src/cli.ts`, add the import next to the other local imports:

```ts
import { migrateToKeyring } from "./keyring-migrate.js";
import { detectVaultFormat } from "./keyring.js";
```

Replace the whole `migrate` command at `src/cli.ts:1196` with:

```ts
program
  .command("migrate")
  .description("upgrade this vault to the encrypted keyring format and rewrite key-value files")
  .action(async () => {
    const dir = program.opts().vault;
    const passphrase = await getPassphrase({ vaultDir: dir });
    const report = migrateToKeyring(dir, passphrase);

    if (report.created) {
      console.log(`Wrote ${path.join(dir, "keyring.json")}.`);
      if (report.adopted.length > 0) {
        console.log(`Adopted existing keys: ${report.adopted.join(", ")}.`);
        console.log(`Attachment identities, sync change IDs and the audit chain are unchanged.`);
      }
      console.log(`Generated new keys: ${report.generated.join(", ")}.`);
    } else {
      console.log("This vault already has a keyring.");
    }

    if (report.kvFilesRewritten.length > 0) {
      console.log(`Rewrote ${report.kvFilesRewritten.length} key-value file(s): ${report.kvFilesRewritten.join(", ")}.`);
    }
    if (report.grantsRewritten) console.log("Rewrote grants.enc in the keyed envelope.");
    if (report.manifestTombstoned) {
      console.log("Replaced documents/manifest.json with a version marker; its passphrase verifier is gone.");
    }
    console.log("Desktop builds older than this release cannot open a migrated vault.");
  });
```

Then extend `keychain-status` at `src/cli.ts:1249` by adding one line right after the `Credential store:` line:

```ts
    console.log(`Vault format: ${detectVaultFormat(dir)}`);
```

- [ ] **Step 7: Verify the CLI end to end**

```bash
npm run build
export VBRAIN_PASSPHRASE="cli-check-passphrase"
rm -rf /tmp/vbrain-migrate-check
node dist/cli.js --vault /tmp/vbrain-migrate-check init
node dist/cli.js --vault /tmp/vbrain-migrate-check add health BLOOD_TYPE="0 Rh+" --desc "blood group"
node dist/cli.js --vault /tmp/vbrain-migrate-check keychain-status
node dist/cli.js --vault /tmp/vbrain-migrate-check migrate
node dist/cli.js --vault /tmp/vbrain-migrate-check keychain-status
node dist/cli.js --vault /tmp/vbrain-migrate-check get health BLOOD_TYPE
node dist/cli.js --vault /tmp/vbrain-migrate-check migrate
unset VBRAIN_PASSPHRASE
```

Expected: the first `keychain-status` reports `Vault format: legacy` and `health.kv.enc: envelope v1`; `migrate` reports adopted keys and one rewritten file; the second `keychain-status` reports `Vault format: keyring` and `envelope v2`; `get` still prints `0 Rh+`; the second `migrate` reports `This vault already has a keyring.`

On Windows PowerShell use `$env:VBRAIN_PASSPHRASE = "cli-check-passphrase"` and `$env:TEMP\vbrain-migrate-check` for the path.

- [ ] **Step 8: Run the full suite**

Run: `npm run quality`
Expected: PASS — lint, format check, both TypeScript projects, Node tests, desktop tests and the webview build.

- [ ] **Step 9: Commit**

```bash
git add src/keyring-migrate.ts src/cli.ts test/keyring-migrate.test.mjs package.json
git commit -m "feat: migrate an existing vault to the keyring format"
```

---

### Task 8: Fixture and documentation

**Files:**

- Modify: `scripts/make-fixtures.mjs`
- Create: `test/fixtures/keyring-v2/` (generated, then committed)
- Modify: `test/fixtures/README.md`
- Modify: `test/keyring-migrate.test.mjs`
- Modify: `docs/ROADMAP.md`

**Interfaces:**

- Consumes: `migrateToKeyring` (Task 7), `DocumentVault`.
- Produces: the `keyring-v2` fixture that Phase 7.2's Rust test will open.

- [ ] **Step 1: Write the failing test**

Append to `test/keyring-migrate.test.mjs`:

```js
test("the checked-in keyring fixture still opens", () => {
  const vault = copyFixture("keyring-v2");
  assert.equal(detectVaultFormat(vault), "keyring");

  const documents = new DocumentVault(vault, FIXTURE_PASSPHRASE);
  const notes = documents.list();
  assert.ok(notes.length > 0);
  assert.ok(documents.get(notes[0].id).body.length > 0);

  const attachments = documents.listAttachments();
  assert.ok(attachments.length > 0);
  assert.ok(documents.getAttachment(attachments[0].id).data.length > 0);
  documents.lock();

  assert.deepEqual(loadVaultFile(vault, "health", FIXTURE_PASSPHRASE), [
    { key: "BLOOD_TYPE", value: "0 Rh+", desc: "blood group" },
  ]);
  assert.equal(vaultFileEnvelopeVersion(vault, "health"), 2);
  assert.equal(verifyAudit(vault, FIXTURE_PASSPHRASE).valid, true);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm run build && node --test test/keyring-migrate.test.mjs`
Expected: FAIL — no such directory `test/fixtures/keyring-v2`.

- [ ] **Step 3: Add the fixture generator**

In `scripts/make-fixtures.mjs`, add the imports the new function needs beside the existing `DocumentVault` import:

```js
import { appendAudit } from "../dist/audit.js";
import { migrateToKeyring } from "../dist/keyring-migrate.js";
import { upsertEntry } from "../dist/store.js";
```

Add this function, and call it immediately after the existing `writeCanvasFixture();` call near the end of the script — before the `fs.writeFileSync(path.join(fixtures, "README.md"), ...)` block:

```js
function writeKeyringFixture() {
  const dir = path.join(fixtures, "keyring-v2");
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });

  const vault = new DocumentVault(dir, FIXTURE_PASSPHRASE);
  vault.put({
    path: "Atlas/Keyring contract.md",
    title: "Keyring contract",
    body: "# Keyring contract\n\nThe wrapped keyset must stay openable. #fixture",
    properties: { status: "frozen" },
  });
  vault.putAttachment(Buffer.from("keyring fixture attachment"), "keyring.txt", "text/plain");
  vault.lock();

  upsertEntry(dir, "health", "BLOOD_TYPE", "0 Rh+", "blood group", FIXTURE_PASSPHRASE);
  appendAudit(dir, { actor: "cli-direct-write", file: "health", key: "BLOOD_TYPE" }, FIXTURE_PASSPHRASE);

  migrateToKeyring(dir, FIXTURE_PASSPHRASE);
  fs.rmSync(path.join(dir, ".sbrain.lock"), { force: true });
}
```

- [ ] **Step 4: Generate and inspect the fixture**

```bash
npm run fixtures
git status --short test/fixtures
ls test/fixtures/keyring-v2
```

Expected: only `test/fixtures/keyring-v2/` is new. If `git status` shows a modification to any pre-existing fixture directory, revert it with `git checkout -- test/fixtures/<name>` and fix the generator — overwriting an existing fixture destroys the evidence it exists to provide.

Confirm the tombstone landed and no verifier survives:

```bash
cat test/fixtures/keyring-v2/documents/manifest.json
grep -r "verifier" test/fixtures/keyring-v2 || echo "no verifier, as intended"
```

Expected: `{ "version": 2, "keyring": true }` and the `no verifier, as intended` line.

- [ ] **Step 5: Run the test to verify it passes**

Run: `npm run build && node --test test/keyring-migrate.test.mjs`
Expected: PASS, 7 tests.

- [ ] **Step 6: Document the fixture**

`test/fixtures/README.md` is **generated** by the `fs.writeFileSync(path.join(fixtures, "README.md"), ...)` block at the end of `scripts/make-fixtures.mjs`. Editing the file by hand would be undone by the next `npm run fixtures`, and the checked-in copy has already drifted from the template. Fix both at once by replacing that whole block with a template that reproduces the current checked-in prose and adds the new row:

```js
fs.writeFileSync(
  path.join(fixtures, "README.md"),
  `# Format fixtures

Checked-in vaults written by earlier releases. Vault Brain is the product name,
but these fixtures retain immutable pre-rename storage and cryptographic
identifiers so tests prove upgrades do not orphan existing data.

**Passphrase for every fixture here: \\\`${FIXTURE_PASSPHRASE}\\\`.**

They contain dummy data only. Never point a fixture at a real vault.

| Directory | Format | What it pins |
|---|---|---|
| \\\`kv-envelope-v0/\\\` | key-value envelope, pre-versioning | Unversioned \\\`{salt,iv,authTag,ciphertext}\\\` files still decrypt, and \\\`vbrain migrate\\\` upgrades them in place |
| \\\`documents-v1/\\\` | document vault manifest v1, index v2 | An encrypted note vault written by the current format still opens, searches and resolves links |
| \\\`documents-attachments-v1/\\\` | document vault with chunk-encrypted attachments | Content-addressed attachments written by the TypeScript core still open in the Rust desktop core |
| \\\`documents-canvas-v1/\\\` | document vault with encrypted canvas objects | Canvas objects, identities, references and AAD written by the TypeScript core stay readable |
| \\\`keyring-v2/\\\` | vault keyring v2, keyset v1, key-value envelope v2 | A migrated vault opens through its wrapped keyset, its key-value files use the keyed envelope, and its adopted audit chain still verifies |

Regenerate deliberately (see \\\`scripts/make-fixtures.mjs\\\`) — overwriting a
fixture throws away the evidence it was there to provide. To cover a new
format version, add a new directory instead of editing an old one.
`,
);
```

The backslash-escaped backticks above are the escaping this plan document needs; in `make-fixtures.mjs` each one is a single `\``, exactly as the existing template already writes them.

After the edit, run `npm run fixtures` again and check `git diff test/fixtures/README.md` — the only change should be the added `keyring-v2` row.

- [ ] **Step 6b: Record the new limitation in `SECURITY.md`**

Under **Important limitations**, add:

```markdown
- Upgrading a vault to the keyring format does not strengthen copies that
  already exist. A backup taken before `vbrain migrate` keeps the older
  key-derivation cost and still opens with the passphrase it was written under.
```

- [ ] **Step 7: Record the phase in the roadmap**

In `docs/ROADMAP.md`, append after the Phase 6 section:

```markdown
## Phase 7 — Key wrapping, passphrase change and re-key

- [ ] Encrypted keyring: passphrase-wrapped keyset, adopting migration, keyed key-value envelope
  - [x] Keyring format, vault format detection and cached keyset resolution
  - [x] Key-value and grant files encrypted by the keyset and bound to their file identity
  - [x] Document, attachment-identity and sync-change keys separated
  - [x] `vbrain migrate` upgrades an existing vault without re-encrypting an object
  - [ ] Rust core opens a keyring vault
- [ ] Passphrase change, including the KDF cost upgrade path
- [ ] Full re-key after a compromised passphrase
```

- [ ] **Step 8: Run everything**

Run: `npm run quality && npm run benchmark`
Expected: PASS. Record the benchmark's unlock and key-value numbers; they belong in the pull request per `CONTRIBUTING.md`.

- [ ] **Step 9: Commit**

```bash
git add scripts/make-fixtures.mjs test/fixtures/keyring-v2 test/fixtures/README.md test/keyring-migrate.test.mjs docs/ROADMAP.md SECURITY.md
git commit -m "test: pin the keyring v2 vault format with a fixture"
```

---

## Done when

- `npm run quality` and `npm run benchmark` pass.
- A vault created before this change opens, migrates, and afterwards reports the same attachment content IDs, the same sync change IDs and a still-valid audit chain.
- `documents/manifest.json` in a migrated vault carries no verifier.
- A vault that has not been migrated behaves exactly as it did before, including in the Rust desktop core.
- The pull request states the storage and security impact, the migration and recovery behaviour, and the before/after benchmark numbers.
