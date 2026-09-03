# Phase 7.2 — Rust Read Parity and Keyring-Native Vaults Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Teach the Rust core to open a keyring vault, make a brand-new vault keyring-native in both cores, and pin the format so the two implementations cannot drift.

**Architecture:** A new `src-tauri/src/keyring.rs` owns the Rust side of the format: slot validation, KEK derivation, unwrap, and the wrap/write path a brand-new vault needs. `open_session` in `src-tauri/src/lib.rs` gains a three-branch key resolution — keyring, legacy manifest, brand-new — and `VaultSession` carries the attachment-identity key beside the document key. On the TypeScript side `openVaultKeys` gains a creating counterpart, `openOrCreateVaultKeys`, used only by write paths, so the first write to a fresh vault creates the keyring while a legacy vault keeps every one of its current code paths. A checked-in deterministic test vector plus the existing `keyring-v2` fixture pin the format from both cores.

**Tech Stack:** Rust 2021 (`aes-gcm`, `scrypt`, `hmac`, `serde_json`, `zeroize`, `uuid`, `base64`), TypeScript (ESM, Node 20+, `node:crypto`), `node:test` integration tests against `dist/`, `cargo test --lib` for Rust.

## Global Constraints

- Design contract: `docs/superpowers/specs/2026-09-03-phase-7-2-rust-read-parity-design.md`, which sits under the shared contract `docs/superpowers/specs/2026-09-03-vault-keyring-design.md`. Read both before starting.
- **There is no Rust toolchain on this machine.** `cargo`, `rustc`, `rustup` and any MSVC linker are all absent, and installing them is out of scope for this plan. Rust tasks therefore cannot be compiled, tested, clippy-checked or rustfmt-checked locally. Do not attempt an install, and do not report a Rust task as verified. Instead: write the code and its tests, re-read the diff as a compiler would (every import path, type, move and borrow), and state plainly in your report that it is unverified pending CI. CI's `rust-windows` job runs `cargo fmt -- --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test --lib`.
- Because clippy runs with `-D warnings`, a lint is a build failure. Avoid `return` at the end of a block, `&Vec<u8>` parameters (`&[u8]`), needless borrows and needless clones.
- Write Rust exactly as rustfmt would: 4-space indent, 100-column max width, trailing commas in multi-line lists, `use` items grouped as `src-tauri/src/lib.rs:1-33` already groups them.
- Node.js 20 or newer; CI uses Node.js 22. No new runtime dependencies in `package.json`; `dependencies` stays exactly `@modelcontextprotocol/sdk`, `commander`, `yaml`. No new Rust dependencies: everything needed is already in `src-tauri/Cargo.toml`.
- Keyring version: `2`. Keyset version: `1`. Default KDF on creation: `scrypt`, `N = 2 ** 17` (131072), `r = 8`, `p = 1`, 16-byte salt, 32-byte output.
- Accepted KDF bounds on read, identical in both cores: `N` a power of two in `[2 ** 14, 2 ** 20]`, `r` in `[1, 32]`, `p` in `[1, 16]`, salt 16–64 bytes, every keyset entry exactly 32 bytes. Additionally reject any parameter set whose `128 * N * r` exceeds 256 MiB — the fixed ceiling `scryptMaxmem` applies in `src/keyring.ts:111`.
- Key names, in this exact order, everywhere: `documents`, `kv`, `attachmentId`, `syncChange`, `syncEnvelope`, `audit`.
- The `secondbrain-vault:*` associated-data namespace is immutable. This phase adds no new identifier.
- Never regenerate or hand-edit an existing fixture under `test/fixtures/`. Add new files only.
- TypeScript tests import from `../dist/`, so every test run is `npm run build && node --test <file>`.
- Every vault file write uses `writeFileAtomic` from `src/fs-safe.ts` with `mode: 0o600` on the TypeScript side and `write_atomic` on the Rust side; every read of a vault file calls `assertNotSymlink` / `reject_symlink` first.
- `fs.cpSync` crashes the Node process on this machine (Windows, OneDrive path, Node v24). New tests copy fixtures with the local `copyTree` helper shown in Task 1, never `fs.cpSync`. `test/durability.test.mjs` is red locally for this reason and is out of scope; run the suite without it, as `npm test` minus that file.
- `npm run format:check` fails locally on 10 pre-existing files because `.gitattributes` checks out CRLF while prettier expects LF. It fails identically on the branch base. Do not chase it.
- Commit after every task. The branch is `phase-7-vault-keyring`, already created and already carrying phase 7.1.

---

## File Structure

**Create:**

- `src-tauri/src/keyring.rs` — the Rust side of the keyring format: `KeySet`, `KeyringFile`, `KeyringSlot`, `SlotKdf`, validation, `slot_aad`, `derive_slot_key`, `unwrap_slot`, `unwrap_keyring`, `random_key_set`, `wrap_key_set`, `read`, `write`. Depends only on `serde`, `serde_json`, `aes-gcm`, `scrypt`, `base64`, `rand`, `uuid`, `zeroize` and two `pub(crate)` helpers from `lib.rs`. Nothing in it knows about vaults, sessions or notes.
- `scripts/make-keyring-vector.mjs` — writes the deterministic cross-core vector once. Run deliberately, never on every build.
- `test/fixtures/keyring-vector.json` — the vector itself: fixed passphrase, salt, IV, slot header and keyset, plus the exact associated-data string and the exact keyset plaintext both cores must produce. Frozen on creation like every other fixture.
- `test/keyring-create.test.mjs` — the TypeScript creation rules: a fresh vault becomes keyring-native, a read creates nothing, a legacy vault stays legacy.

**Modify:**

- `src/keyring.ts` — add `openOrCreateVaultKeys`, `openOrCreateVaultKey` and the manifest tombstone writer.
- `src/document-crypto.ts:57` — the document key comes from the creating variant.
- `src/store.ts:41-44,110-122` — the key-value write path uses the creating variant; the read path does not.
- `src/grants.ts:176` — `saveGrants` uses the creating variant.
- `src/audit.ts:98` — `chainKeyForAppend` uses the creating variant.
- `test/keyring.test.mjs` — the vector assertions.
- `src-tauri/src/lib.rs` — `mod keyring;`; `VaultSession` gains `attachment_id_key`; `open_session` delegates to a new `open_vault_keys`; `attachment_id` call sites at `:4460`, `:4522` and the test at `:6205` take the attachment-identity key; `write_atomic` and `reject_symlink` become `pub(crate)`.
- `src-tauri/Cargo.toml` — optimize the KDF crates in the dev/test profile so `cargo test` is not dominated by scrypt.
- `package.json` — add `test/keyring-create.test.mjs` to the `test` script.
- `docs/ARCHITECTURE.md`, `SECURITY.md`, `docs/ROADMAP.md`, `CHANGELOG.md`, `test/fixtures/README.md` — documentation.

`.gitignore` already carries the `!test/fixtures/**/audit.log` negation; nothing to do there.

---

### Task 1: Keyring-native new vaults in TypeScript

**Files:**

- Modify: `src/keyring.ts`
- Modify: `src/document-crypto.ts:57`
- Modify: `src/store.ts:41-44`, `src/store.ts:110-122`
- Modify: `src/grants.ts:176`
- Modify: `src/audit.ts:98`
- Create: `test/keyring-create.test.mjs`
- Modify: `package.json` (test script)

**Interfaces:**

- Consumes: `openVaultKeys`, `detectVaultFormat`, `randomKeySet`, `wrapKeySet`, `writeKeyring`, `copyKeySet`, `zeroKeySet`, `KEY_NAMES`, `KEYRING_VERSION` from `src/keyring.ts`; `withVaultLock` from `src/vault-lock.ts`; `writeFileAtomic`, `assertNotSymlink` from `src/fs-safe.ts`; `resolveInside` from `src/safety.ts`.
- Produces: `openOrCreateVaultKeys(vaultDir: string, passphrase: string): KeySet | null` and `openOrCreateVaultKey(vaultDir: string, passphrase: string, name: KeyName): Buffer | null`, both exported from `src/keyring.ts`.

- [ ] **Step 1: Write the failing test**

Create `test/keyring-create.test.mjs`:

```js
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { appendAudit, verifyAudit } from "../dist/audit.js";
import { DocumentVault } from "../dist/documents.js";
import { detectVaultFormat, forgetVaultKeys, openOrCreateVaultKeys, openVaultKeys } from "../dist/keyring.js";
import { loadVaultFile, upsertEntry, vaultFileEnvelopeVersion } from "../dist/store.js";

const FIXTURES = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "fixtures");
const FIXTURE_PASSPHRASE = "fixture-only-passphrase";
const PASSPHRASE = "create-test-passphrase";

function tempDir(label = "create") {
  return fs.mkdtempSync(path.join(os.tmpdir(), `vault-brain-${label}-`));
}

// fs.cpSync crashes the Node process on this machine; see the plan's constraints.
function copyTree(from, to) {
  fs.mkdirSync(to, { recursive: true });
  for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
    const src = path.join(from, entry.name);
    const dst = path.join(to, entry.name);
    if (entry.isDirectory()) copyTree(src, dst);
    else fs.copyFileSync(src, dst);
  }
}

test("a fresh vault becomes keyring-native on its first key-value write", () => {
  const dir = tempDir();
  upsertEntry(dir, "health", "BLOOD_TYPE", "0 Rh+", "blood group", PASSPHRASE);

  assert.equal(detectVaultFormat(dir), "keyring");
  assert.ok(fs.existsSync(path.join(dir, "keyring.json")));
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(dir, "documents", "manifest.json"), "utf8")), {
    version: 2,
    keyring: true,
  });
  assert.equal(vaultFileEnvelopeVersion(dir, "health"), 2);

  // Not from the process cache: the keyring on disk has to be the one that opens.
  forgetVaultKeys();
  assert.equal(loadVaultFile(dir, "health", PASSPHRASE)[0].value, "0 Rh+");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("a fresh vault becomes keyring-native on its first document write", () => {
  const dir = tempDir();
  const vault = new DocumentVault(dir, PASSPHRASE);
  vault.put({ path: "Atlas/First.md", title: "First", body: "# First\n\nbody" });
  vault.lock();

  assert.equal(detectVaultFormat(dir), "keyring");
  assert.equal(JSON.parse(fs.readFileSync(path.join(dir, "documents", "manifest.json"), "utf8")).version, 2);

  forgetVaultKeys();
  const reopened = new DocumentVault(dir, PASSPHRASE);
  assert.equal(reopened.get("Atlas/First.md").title, "First");
  reopened.lock();
  fs.rmSync(dir, { recursive: true, force: true });
});

test("reading an empty vault creates nothing", () => {
  const dir = tempDir();
  assert.deepEqual(loadVaultFile(dir, "health", PASSPHRASE), []);
  assert.equal(openVaultKeys(dir, PASSPHRASE), null);
  assert.equal(fs.existsSync(path.join(dir, "keyring.json")), false);
  assert.equal(detectVaultFormat(dir), "empty");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("a legacy key-value vault keeps its format and its audit chain when written to", () => {
  const dir = tempDir("legacy-kv");
  copyTree(path.join(FIXTURES, "kv-envelope-v0"), dir);
  appendAudit(dir, { actor: "test", file: "health", key: "BLOOD_TYPE" }, FIXTURE_PASSPHRASE);

  upsertEntry(dir, "health", "ALLERGY", "none", "allergies", FIXTURE_PASSPHRASE);

  assert.equal(fs.existsSync(path.join(dir, "keyring.json")), false);
  assert.equal(detectVaultFormat(dir), "legacy");
  assert.equal(verifyAudit(dir, FIXTURE_PASSPHRASE).valid, true);
  assert.equal(loadVaultFile(dir, "health", FIXTURE_PASSPHRASE).find((e) => e.key === "ALLERGY").value, "none");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("a legacy document vault opens and is written to without gaining a keyring", () => {
  const dir = tempDir("legacy-docs");
  copyTree(path.join(FIXTURES, "documents-v1"), dir);
  const vault = new DocumentVault(dir, FIXTURE_PASSPHRASE);
  assert.ok(vault.list().length > 0);
  vault.put({ path: "Atlas/Added.md", title: "Added", body: "# Added" });
  vault.lock();

  assert.equal(fs.existsSync(path.join(dir, "keyring.json")), false);
  assert.equal(JSON.parse(fs.readFileSync(path.join(dir, "documents", "manifest.json"), "utf8")).version, 1);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("creating a keyring is idempotent and every key is independent", () => {
  const dir = tempDir("idempotent");
  const first = openOrCreateVaultKeys(dir, PASSPHRASE);
  const keyringText = fs.readFileSync(path.join(dir, "keyring.json"), "utf8");
  const second = openOrCreateVaultKeys(dir, PASSPHRASE);

  assert.deepEqual(second.documents, first.documents);
  assert.equal(fs.readFileSync(path.join(dir, "keyring.json"), "utf8"), keyringText);
  const seen = new Set(Object.values(first).map((key) => key.toString("hex")));
  assert.equal(seen.size, 6, "a fresh vault must get six independent random keys");
  fs.rmSync(dir, { recursive: true, force: true });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm run build && node --test test/keyring-create.test.mjs`
Expected: FAIL — `openOrCreateVaultKeys` is not exported from `dist/keyring.js`, so the import is `undefined` and the idempotency test throws `TypeError`. The first two tests fail because a fresh vault still gets the legacy format.

- [ ] **Step 3: Add the creating variants to `src/keyring.ts`**

Add `withVaultLock` to the imports at the top of `src/keyring.ts` (it imports `node:crypto`, `node:fs`, `node:path`, `./fs-safe.js` and `./safety.js` only; `src/vault-lock.ts` imports nothing from this project, so there is no cycle):

```ts
import { withVaultLock } from "./vault-lock.js";
```

Then append, after `forgetVaultKeys`:

```ts
/**
 * The document manifest a keyring-native vault carries, byte-identical to the
 * tombstone `vbrain migrate` leaves behind. Builds from before the keyring
 * refuse any manifest whose version is not 1, so writing this is what makes an
 * older build fail closed instead of mistaking a keyring vault for an empty
 * legacy one and writing notes under a key of its own.
 */
function writeManifestTombstone(vaultDir: string): void {
  const manifestPath = resolveInside(vaultDir, path.join("documents", "manifest.json"));
  if (fs.existsSync(manifestPath)) {
    assertNotSymlink(manifestPath);
    return;
  }
  fs.mkdirSync(path.dirname(manifestPath), { recursive: true, mode: 0o700 });
  writeFileAtomic(manifestPath, `${JSON.stringify({ version: 2, keyring: true }, null, 2)}\n`, {
    mode: 0o600,
  });
}

/**
 * Returns the vault's keyset, creating one when the vault is brand new.
 *
 * `openVaultKeys` deliberately never writes — reading a vault must not bring
 * one into existence — so this is its write-path counterpart, and the only
 * place outside `vbrain migrate` that a keyring is created. A vault holding
 * legacy material still returns `null`: a fresh keyring written beside an
 * existing `audit.meta.json` would put a random audit key in front of a chain
 * signed with the key derived from that file, and `vbrain audit verify` would
 * stop validating a chain that is in fact intact. Adopting legacy keys so that
 * cannot happen is migration's job, not this function's.
 */
export function openOrCreateVaultKeys(vaultDir: string, passphrase: string): KeySet | null {
  const existing = openVaultKeys(vaultDir, passphrase);
  if (existing) return existing;
  if (!passphrase) throw new Error("A non-empty vault passphrase is required.");
  if (detectVaultFormat(vaultDir) === "legacy") return null;

  fs.mkdirSync(vaultDir, { recursive: true, mode: 0o700 });
  return withVaultLock(vaultDir, () => {
    // Re-checked under the lock: two processes racing on the same fresh vault
    // must not each write a keyset of their own, or whichever lost the race
    // would have encrypted its first write under keys nobody keeps.
    const raced = openVaultKeys(vaultDir, passphrase);
    if (raced) return raced;
    if (detectVaultFormat(vaultDir) === "legacy") return null;

    const keys = randomKeySet();
    try {
      writeKeyring(vaultDir, { version: KEYRING_VERSION, slots: [wrapKeySet(keys, passphrase)] });
    } finally {
      zeroKeySet(keys);
    }
    writeManifestTombstone(vaultDir);

    // Read back rather than returning what we just generated: this proves the
    // keyring on disk really unwraps before one byte is encrypted under it,
    // and it populates the process cache every other caller expects.
    const created = openVaultKeys(vaultDir, passphrase);
    if (!created) throw new Error("Failed to create a vault keyring.");
    return created;
  });
}

/**
 * `openOrCreateVaultKeys` for a caller that needs one key, zeroizing the five
 * it did not ask for — the same contract as `openVaultKey`.
 */
export function openOrCreateVaultKey(
  vaultDir: string,
  passphrase: string,
  name: KeyName,
): Buffer | null {
  const keys = openOrCreateVaultKeys(vaultDir, passphrase);
  if (!keys) return null;
  const wanted = keys[name];
  for (const other of KEY_NAMES) {
    if (other !== name) keys[other].fill(0);
  }
  return wanted;
}
```

- [ ] **Step 4: Route the four write paths through it**

`src/document-crypto.ts` — change the import and the call:

```ts
import { openOrCreateVaultKeys } from "./keyring.js";
```

```ts
  const vaultKeys = openOrCreateVaultKeys(vaultDir, passphrase);
```

`src/store.ts` — add the write-side accessor beside `kvKey` and use it in `saveVaultFile`:

```ts
import { openOrCreateVaultKey, openVaultKey } from "./keyring.js";
```

```ts
/** The keyed key-value key when this vault has a keyring, otherwise null. */
function kvKey(vaultDir: string, passphrase: string): Buffer | null {
  return openVaultKey(vaultDir, passphrase, "kv");
}

/**
 * The key-value key for a write. A vault with neither a keyring nor legacy
 * material becomes keyring-native here: the first write to a fresh vault is
 * what creates the keyring. A legacy vault still gets `null` and keeps writing
 * its per-file envelope exactly as before.
 */
function kvKeyForWrite(vaultDir: string, passphrase: string): Buffer | null {
  return openOrCreateVaultKey(vaultDir, passphrase, "kv");
}
```

In `saveVaultFile`, replace `const key = kvKey(vaultDir, passphrase);` with:

```ts
  const key = kvKeyForWrite(vaultDir, passphrase);
```

Leave `requireKvKey` and `migrateVaultFile` on `kvKey`: a read must not create anything, and a migration report must describe the format the vault already has.

`src/grants.ts` — in `saveGrants` only (not `requireGrantsKey`):

```ts
import { openOrCreateVaultKey, openVaultKey } from "./keyring.js";
```

```ts
  const key = openOrCreateVaultKey(vaultDir, passphrase, "kv");
```

`src/audit.ts` — in `chainKeyForAppend` only (not `verifyAudit`, which reads):

```ts
import { openOrCreateVaultKey, openVaultKey } from "./keyring.js";
```

```ts
function chainKeyForAppend(vaultDir: string, passphrase: string): Buffer {
  const key = openOrCreateVaultKey(vaultDir, passphrase, "audit");
  if (key) return key;
  return auditKey(vaultDir, passphrase, loadOrCreateMeta(vaultDir));
}
```

The order matters: asking for the keyring key first means a fresh vault never gets an `audit.meta.json`, because `loadOrCreateMeta` is not reached.

- [ ] **Step 5: Add the test file to the test script**

In `package.json`, append ` test/keyring-create.test.mjs` to the end of the `test` script's file list.

- [ ] **Step 6: Run the new test, then the whole suite**

Run: `npm run build && node --test test/keyring-create.test.mjs`
Expected: PASS, 6/6.

Run: `node --test test/package.test.mjs test/core.test.mjs test/documents.test.mjs test/workflows.test.mjs test/canvas.test.mjs test/grants.test.mjs test/plugins.test.mjs test/obsidian-import.test.mjs test/semantic.test.mjs test/sync.test.mjs test/sync-protocol.test.mjs test/sync-transaction.test.mjs test/sync-apply.test.mjs test/keyring.test.mjs test/keyring-migrate.test.mjs test/keyring-create.test.mjs`
Expected: PASS. Every existing test that builds a vault from scratch now builds a keyring vault, which is the point of the phase; any failure here is a real incompatibility, not a test that needs relaxing. Report it rather than editing an assertion to match.

Run: `npm run lint && npm run typecheck`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add src/keyring.ts src/document-crypto.ts src/store.ts src/grants.ts src/audit.ts test/keyring-create.test.mjs package.json
git commit -m "feat: create new vaults in the keyring format"
```

---

### Task 2: The deterministic cross-core vector

**Files:**

- Create: `scripts/make-keyring-vector.mjs`
- Create: `test/fixtures/keyring-vector.json`
- Modify: `test/keyring.test.mjs`
- Modify: `test/fixtures/README.md`

**Interfaces:**

- Consumes: `unwrapSlot`, `KEY_NAMES` from `dist/keyring.js`.
- Produces: `test/fixtures/keyring-vector.json` with the fields `note`, `passphrase`, `aad`, `keysetPlaintext`, `keys` (six base64 strings) and `slot` (a complete `KeyringSlot`). Task 3's Rust tests read all five.

The vector is what makes the write direction provable without a Rust toolchain. If Rust unwraps this slot, its associated data and its keyset parser agree with TypeScript byte-for-byte, because the AAD is authenticated. If Rust's own keyset serializer reproduces `keysetPlaintext` exactly, then what Rust writes is a plaintext TypeScript demonstrably parses. Together those two assertions close both directions.

- [ ] **Step 1: Write the generator**

Create `scripts/make-keyring-vector.mjs`:

```js
/**
 * Writes the deterministic cross-core keyring vector. Run once, deliberately:
 *
 *   npm run build && node scripts/make-keyring-vector.mjs
 *
 * The output is a frozen fixture. Regenerating it destroys the evidence that
 * both cores agree on the bytes, so only ever regenerate it alongside a
 * deliberate format version bump, and add a new file instead when you can.
 *
 * Everything here is fixed: a vector with random inputs proves nothing twice.
 * N is the lowest accepted cost (2**14) so a debug-profile Rust test stays fast.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PASSPHRASE = "vector-only-passphrase";
const SALT = Buffer.alloc(16, 0x11);
const IV = Buffer.alloc(12, 0x22);
const KDF = { name: "scrypt", N: 2 ** 14, r: 8, p: 1, salt: SALT.toString("base64") };
const HEADER = {
  id: "00000000-0000-4000-8000-000000000001",
  type: "passphrase",
  label: "primary",
  kdf: KDF,
  createdAt: "2026-09-03T00:00:00.000Z",
};
const KEY_BYTES = {
  documents: 0x01,
  kv: 0x02,
  attachmentId: 0x03,
  syncChange: 0x04,
  syncEnvelope: 0x05,
  audit: 0x06,
};

const keys = {};
for (const [name, byte] of Object.entries(KEY_BYTES)) keys[name] = Buffer.alloc(32, byte);

// Mirrors slotAad in src/keyring.ts. The test below proves the mirror is exact:
// unwrapSlot only succeeds when the production builder produces these bytes.
const aad = JSON.stringify({
  context: "secondbrain-vault:keyring-slot:v1",
  version: 2,
  id: HEADER.id,
  type: HEADER.type,
  kdf: { name: KDF.name, N: KDF.N, r: KDF.r, p: KDF.p, salt: KDF.salt },
});

const keysetPlaintext = JSON.stringify({
  version: 1,
  keys: Object.fromEntries(Object.keys(KEY_BYTES).map((name) => [name, keys[name].toString("base64")])),
});

const kek = crypto.scryptSync(PASSPHRASE, SALT, 32, {
  N: KDF.N,
  r: KDF.r,
  p: KDF.p,
  maxmem: 256 * 1024 * 1024,
});
const cipher = crypto.createCipheriv("aes-256-gcm", kek, IV);
cipher.setAAD(Buffer.from(aad, "utf8"));
const ciphertext = Buffer.concat([cipher.update(keysetPlaintext, "utf8"), cipher.final()]);

const vector = {
  note: "Deterministic cross-core keyring vector. Both cores must unwrap this slot to these keys and must serialize this keyset to keysetPlaintext byte-for-byte. Dummy key material; never a real vault.",
  passphrase: PASSPHRASE,
  aad,
  keysetPlaintext,
  keys: Object.fromEntries(Object.keys(KEY_BYTES).map((name) => [name, keys[name].toString("base64")])),
  slot: {
    ...HEADER,
    wrapped: {
      iv: IV.toString("base64"),
      authTag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    },
  },
};

const target = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "test",
  "fixtures",
  "keyring-vector.json",
);
if (fs.existsSync(target) && !process.argv.includes("--force")) {
  console.error(`Refusing to overwrite ${target}. Pass --force only for a deliberate format bump.`);
  process.exit(1);
}
fs.writeFileSync(target, `${JSON.stringify(vector, null, 2)}\n`);
console.log(`Cross-core keyring vector written to ${target}`);
```

- [ ] **Step 2: Generate the vector**

Run: `npm run build && node scripts/make-keyring-vector.mjs`
Expected: `Cross-core keyring vector written to .../test/fixtures/keyring-vector.json`.

- [ ] **Step 3: Add the TypeScript side of the contract**

Append to `test/keyring.test.mjs` (it already imports `assert`, `fs`, `path`, `test` and from `../dist/keyring.js`; add `KEY_NAMES` and `unwrapSlot` to that import if they are not there, and add the two `node:url`/`fixtures` constants if the file lacks them):

```js
const VECTOR = JSON.parse(
  fs.readFileSync(
    path.resolve(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "keyring-vector.json"),
    "utf8",
  ),
);

test("the cross-core vector unwraps to its recorded keyset", () => {
  const keys = unwrapSlot(VECTOR.slot, VECTOR.passphrase);
  for (const name of KEY_NAMES) {
    assert.deepEqual(keys[name], Buffer.from(VECTOR.keys[name], "base64"), name);
  }
});

test("the cross-core vector records the keyset plaintext in key order", () => {
  const parsed = JSON.parse(VECTOR.keysetPlaintext);
  assert.equal(parsed.version, 1);
  assert.deepEqual(Object.keys(parsed.keys), [...KEY_NAMES]);
});

test("the cross-core vector fails closed when its slot header is rewritten", () => {
  for (const rewrite of [
    { id: "00000000-0000-4000-8000-000000000002" },
    { type: "recovery" },
    { kdf: { ...VECTOR.slot.kdf, N: 2 ** 15 } },
  ]) {
    assert.throws(() => unwrapSlot({ ...VECTOR.slot, ...rewrite }, VECTOR.passphrase));
  }
});
```

- [ ] **Step 4: Run the tests**

Run: `npm run build && node --test test/keyring.test.mjs`
Expected: PASS, including the three new tests. The first one passing is the proof that the generator's hand-written AAD matches `slotAad` in production code.

- [ ] **Step 5: Document the fixture**

Add a row to the table in `test/fixtures/README.md`:

```markdown
| `keyring-vector.json` | keyring slot v2, keyset v1, deterministic | Both cores unwrap one fixed slot to the same six keys and serialize that keyset to the same plaintext bytes, so the Rust and TypeScript implementations of the format cannot drift |
```

And, under the regeneration note, add:

```markdown
`keyring-vector.json` is written by `scripts/make-keyring-vector.mjs` and
refuses to overwrite itself without `--force`. Its passphrase is
`vector-only-passphrase`, not the shared fixture passphrase, because it is a
format vector rather than a vault.
```

- [ ] **Step 6: Commit**

```bash
git add scripts/make-keyring-vector.mjs test/fixtures/keyring-vector.json test/keyring.test.mjs test/fixtures/README.md
git commit -m "test: pin the keyring format with a cross-core vector"
```

---

### Task 3: The Rust keyring module

**Files:**

- Create: `src-tauri/src/keyring.rs`
- Modify: `src-tauri/src/lib.rs` (add `mod keyring;`; make `write_atomic` and `reject_symlink` `pub(crate)`)
- Modify: `src-tauri/Cargo.toml` (dev-profile optimization for the KDF crates)

**Interfaces:**

- Consumes: `crate::reject_symlink`, `crate::write_atomic`.
- Produces, all `pub(crate)`: `KEYRING_VERSION: u8`, `KEYSET_VERSION: u8`, `DEFAULT_SCRYPT_LOG_N: u8`, `KeySet { documents, kv, attachment_id, sync_change, sync_envelope, audit: Zeroizing<[u8; 32]> }`, `KeyringFile { version: u8, slots: Vec<KeyringSlot> }`, `KeyringSlot`, `SlotKdf`, `keyring_path(&Path) -> PathBuf`, `read(&Path) -> Result<Option<KeyringFile>, String>`, `write(&Path, &KeyringFile) -> Result<(), String>`, `unwrap_keyring(&KeyringFile, &str) -> Result<KeySet, String>`, `random_key_set() -> KeySet`, `wrap_key_set(&KeySet, &str, u8) -> Result<KeyringSlot, String>`. Task 4 consumes every one of them.

**This task cannot be verified locally — there is no Rust toolchain.** Write the tests anyway; they are what CI runs.

- [ ] **Step 1: Speed up the KDF crates in the test profile**

Without this, `cargo test` in the debug profile runs scrypt at `N = 2**17` unoptimized, which is tens of seconds per vault creation and would dominate the Rust suite. Optimizing only these five dependency crates leaves the release profile and the crate's own debug info untouched.

Append to `src-tauri/Cargo.toml`, after the `[profile.release]` block:

```toml
# scrypt is unusably slow unoptimized, and the test profile inherits dev, so a
# debug `cargo test` would spend minutes deriving keys. Only dependencies are
# optimized; this crate itself still compiles with full debug info.
[profile.dev.package.scrypt]
opt-level = 3

[profile.dev.package.salsa20]
opt-level = 3

[profile.dev.package.pbkdf2]
opt-level = 3

[profile.dev.package.sha2]
opt-level = 3

[profile.dev.package.aes]
opt-level = 3
```

- [ ] **Step 2: Expose the two filesystem helpers to the new module**

In `src-tauri/src/lib.rs`, change two signatures (line 785 and line 844):

```rust
pub(crate) fn write_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
```

```rust
pub(crate) fn reject_symlink(path: &Path) -> Result<(), String> {
```

And declare the module immediately after the `type HmacSha256 = Hmac<Sha256>;` line:

```rust
mod keyring;
```

- [ ] **Step 3: Write the module**

Create `src-tauri/src/keyring.rs`:

```rust
//! The vault keyring: the passphrase-wrapped keyset that holds every data key.
//!
//! The format is defined by `docs/superpowers/specs/2026-09-03-vault-keyring-design.md`
//! and implemented on the other side by `src/keyring.ts`. Every constant, bound
//! and byte of associated data here has a counterpart there, and
//! `test/fixtures/keyring-vector.json` is what proves the two agree.
//!
//! This module reads a keyring and, for a brand-new vault, creates one. It
//! never migrates a legacy vault: adopting legacy keys so that attachment IDs,
//! sync change IDs and the audit chain keep verifying is `vbrain migrate`'s
//! job, and doing it here would silently orphan an audit chain.

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce, Tag,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{SecondsFormat, Utc};
use rand::{rngs::OsRng, RngCore};
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::fs;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{reject_symlink, write_atomic};

pub(crate) const KEYRING_FILENAME: &str = "keyring.json";
pub(crate) const KEYRING_VERSION: u8 = 2;
pub(crate) const KEYSET_VERSION: u8 = 1;
/// The cost a vault created today is wrapped at. Read is never restricted to it.
pub(crate) const DEFAULT_SCRYPT_LOG_N: u8 = 17;

const KEY_LENGTH: usize = 32;
const SLOT_AAD_CONTEXT: &str = "secondbrain-vault:keyring-slot:v1";
const MIN_LOG_N: u8 = 14;
const MAX_LOG_N: u8 = 20;
const MAX_SLOTS: usize = 16;
/// Deliberately fixed rather than derived from the file's own parameters: `N`
/// and `r` can each be in range while their product implies a multi-gigabyte
/// allocation. A tampered keyring must not get to dictate its memory budget.
/// The same ceiling `scryptMaxmem` enforces in `src/keyring.ts`.
const MAX_SCRYPT_MEMORY: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SlotKdf {
    pub(crate) name: String,
    #[serde(rename = "N")]
    pub(crate) n: u32,
    pub(crate) r: u32,
    pub(crate) p: u32,
    pub(crate) salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WrappedKeySet {
    pub(crate) iv: String,
    pub(crate) auth_tag: String,
    pub(crate) ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyringSlot {
    pub(crate) id: String,
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) label: String,
    pub(crate) kdf: SlotKdf,
    pub(crate) created_at: String,
    pub(crate) wrapped: WrappedKeySet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct KeyringFile {
    pub(crate) version: u8,
    pub(crate) slots: Vec<KeyringSlot>,
}

/// The wrapped plaintext. Field order is the format's key order.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeySetKeys {
    documents: String,
    kv: String,
    attachment_id: String,
    sync_change: String,
    sync_envelope: String,
    audit: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeySetFile {
    version: u8,
    keys: KeySetKeys,
}

/// Associated data for the wrap: the slot's identity and its declared cost.
/// Serialized in this exact field order, compactly, so it is byte-identical to
/// `JSON.stringify` over the same object in `src/keyring.ts`.
#[derive(Debug, Serialize)]
struct SlotAad<'a> {
    context: &'a str,
    version: u8,
    id: &'a str,
    #[serde(rename = "type")]
    kind: &'a str,
    kdf: &'a SlotKdf,
}

#[derive(Debug, Clone)]
pub(crate) struct KeySet {
    pub(crate) documents: Zeroizing<[u8; KEY_LENGTH]>,
    pub(crate) kv: Zeroizing<[u8; KEY_LENGTH]>,
    pub(crate) attachment_id: Zeroizing<[u8; KEY_LENGTH]>,
    pub(crate) sync_change: Zeroizing<[u8; KEY_LENGTH]>,
    pub(crate) sync_envelope: Zeroizing<[u8; KEY_LENGTH]>,
    pub(crate) audit: Zeroizing<[u8; KEY_LENGTH]>,
}

pub(crate) fn keyring_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join(KEYRING_FILENAME)
}

/// The keyring, or `None` when this vault has none — which means the caller
/// must fall back to the legacy manifest derivation.
pub(crate) fn read(vault_dir: &Path) -> Result<Option<KeyringFile>, String> {
    let path = keyring_path(vault_dir);
    if !path.exists() {
        return Ok(None);
    }
    reject_symlink(&path)?;
    let raw = fs::read(&path).map_err(|error| error.to_string())?;
    let file: KeyringFile = serde_json::from_slice(&raw).map_err(|error| error.to_string())?;
    if file.version != KEYRING_VERSION {
        return Err(format!(
            "This vault keyring uses version {}; this build understands {}. Upgrade Vault Brain to open it.",
            file.version, KEYRING_VERSION
        ));
    }
    if file.slots.is_empty() || file.slots.len() > MAX_SLOTS {
        return Err("Vault keyring has no usable slots.".into());
    }
    for slot in &file.slots {
        validate_slot(slot)?;
    }
    Ok(Some(file))
}

pub(crate) fn write(vault_dir: &Path, file: &KeyringFile) -> Result<(), String> {
    let mut data = serde_json::to_vec_pretty(file).map_err(|error| error.to_string())?;
    data.push(b'\n');
    write_atomic(&keyring_path(vault_dir), &data)
}

fn decode_base64(value: &str, min: usize, max: usize, label: &str) -> Result<Vec<u8>, String> {
    let bytes = BASE64
        .decode(value)
        .map_err(|_| format!("invalid base64 in vault keyring {label}"))?;
    if bytes.len() < min || bytes.len() > max {
        return Err(format!("vault keyring {label} has an unsupported length"));
    }
    Ok(bytes)
}

fn validate_slot(slot: &KeyringSlot) -> Result<(), String> {
    if slot.kind != "passphrase" {
        return Err(format!("unsupported vault keyring slot type: {}", slot.kind));
    }
    if slot.id.is_empty() {
        return Err("vault keyring slot has no id".into());
    }
    validate_kdf(&slot.kdf)?;
    decode_base64(&slot.wrapped.iv, 12, 12, "iv")?;
    decode_base64(&slot.wrapped.auth_tag, 16, 16, "authentication tag")?;
    if slot.wrapped.ciphertext.is_empty() {
        return Err("vault keyring slot has no ciphertext".into());
    }
    Ok(())
}

fn validate_kdf(kdf: &SlotKdf) -> Result<u8, String> {
    if kdf.name != "scrypt" {
        return Err(format!(
            "unsupported key-derivation function in vault keyring: {}",
            kdf.name
        ));
    }
    if !kdf.n.is_power_of_two() {
        return Err("vault keyring cost N must be a power of two".into());
    }
    let log_n = kdf.n.trailing_zeros() as u8;
    if !(MIN_LOG_N..=MAX_LOG_N).contains(&log_n) {
        return Err(format!("vault keyring cost N is out of range: {}", kdf.n));
    }
    if !(1..=32).contains(&kdf.r) || !(1..=16).contains(&kdf.p) {
        return Err("vault keyring KDF parameters are out of range".into());
    }
    if 128 * u64::from(kdf.n) * u64::from(kdf.r) > MAX_SCRYPT_MEMORY {
        return Err("vault keyring KDF parameters exceed the memory limit".into());
    }
    decode_base64(&kdf.salt, 16, 64, "salt")?;
    Ok(log_n)
}

fn slot_aad(slot: &KeyringSlot) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&SlotAad {
        context: SLOT_AAD_CONTEXT,
        version: KEYRING_VERSION,
        id: &slot.id,
        kind: &slot.kind,
        kdf: &slot.kdf,
    })
    .map_err(|error| error.to_string())
}

fn derive_slot_key(passphrase: &str, kdf: &SlotKdf) -> Result<Zeroizing<[u8; KEY_LENGTH]>, String> {
    let log_n = validate_kdf(kdf)?;
    let salt = decode_base64(&kdf.salt, 16, 64, "salt")?;
    let params = ScryptParams::new(log_n, kdf.r, kdf.p, KEY_LENGTH)
        .map_err(|error| error.to_string())?;
    let mut key = Zeroizing::new([0u8; KEY_LENGTH]);
    scrypt(passphrase.as_bytes(), &salt, &params, key.as_mut())
        .map_err(|error| format!("key derivation failed: {error}"))?;
    Ok(key)
}

fn key_bytes(value: &str, label: &str) -> Result<Zeroizing<[u8; KEY_LENGTH]>, String> {
    let decoded = Zeroizing::new(decode_base64(value, KEY_LENGTH, KEY_LENGTH, label)?);
    let mut key = Zeroizing::new([0u8; KEY_LENGTH]);
    key.copy_from_slice(&decoded);
    Ok(key)
}

fn parse_key_set(plaintext: &[u8]) -> Result<KeySet, String> {
    let parsed: KeySetFile =
        serde_json::from_slice(plaintext).map_err(|_| "unreadable vault keyset".to_string())?;
    if parsed.version != KEYSET_VERSION {
        return Err(format!(
            "Unsupported vault keyset version: {}",
            parsed.version
        ));
    }
    Ok(KeySet {
        documents: key_bytes(&parsed.keys.documents, "documents key")?,
        kv: key_bytes(&parsed.keys.kv, "kv key")?,
        attachment_id: key_bytes(&parsed.keys.attachment_id, "attachmentId key")?,
        sync_change: key_bytes(&parsed.keys.sync_change, "syncChange key")?,
        sync_envelope: key_bytes(&parsed.keys.sync_envelope, "syncEnvelope key")?,
        audit: key_bytes(&parsed.keys.audit, "audit key")?,
    })
}

fn serialize_key_set(keys: &KeySet) -> Result<Zeroizing<String>, String> {
    let file = KeySetFile {
        version: KEYSET_VERSION,
        keys: KeySetKeys {
            documents: BASE64.encode(keys.documents.as_ref()),
            kv: BASE64.encode(keys.kv.as_ref()),
            attachment_id: BASE64.encode(keys.attachment_id.as_ref()),
            sync_change: BASE64.encode(keys.sync_change.as_ref()),
            sync_envelope: BASE64.encode(keys.sync_envelope.as_ref()),
            audit: BASE64.encode(keys.audit.as_ref()),
        },
    };
    Ok(Zeroizing::new(
        serde_json::to_string(&file).map_err(|error| error.to_string())?,
    ))
}

/// A wrong passphrase fails as an authentication error. There is deliberately
/// no verifier field: publishing one hands an offline attacker a free
/// passphrase-guessing oracle.
fn unwrap_slot(slot: &KeyringSlot, passphrase: &str) -> Result<KeySet, String> {
    validate_slot(slot)?;
    let derived = derive_slot_key(passphrase, &slot.kdf)?;
    let aad = slot_aad(slot)?;
    let iv = decode_base64(&slot.wrapped.iv, 12, 12, "iv")?;
    let tag = decode_base64(&slot.wrapped.auth_tag, 16, 16, "authentication tag")?;
    let mut buffer = Zeroizing::new(
        BASE64
            .decode(&slot.wrapped.ciphertext)
            .map_err(|_| "invalid base64 in vault keyring ciphertext")?,
    );
    let cipher =
        Aes256Gcm::new_from_slice(derived.as_ref()).map_err(|_| "invalid AES key".to_string())?;
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&iv),
            &aad,
            &mut *buffer,
            Tag::from_slice(&tag),
        )
        .map_err(|_| "vault keyring slot did not authenticate".to_string())?;
    parse_key_set(&buffer)
}

/// Every slot wraps the same keyset, so the first one that opens wins.
pub(crate) fn unwrap_keyring(file: &KeyringFile, passphrase: &str) -> Result<KeySet, String> {
    if passphrase.is_empty() {
        return Err("passphrase cannot be empty".into());
    }
    for slot in &file.slots {
        if let Ok(keys) = unwrap_slot(slot, passphrase) {
            return Ok(keys);
        }
    }
    Err("Unable to unlock this vault: wrong passphrase, or the keyring is damaged.".into())
}

/// Six independent random keys. A created vault adopts nothing: adoption is
/// migration's business, and only a migrated vault needs it.
pub(crate) fn random_key_set() -> KeySet {
    let mut new_key = || {
        let mut key = Zeroizing::new([0u8; KEY_LENGTH]);
        OsRng.fill_bytes(key.as_mut());
        key
    };
    KeySet {
        documents: new_key(),
        kv: new_key(),
        attachment_id: new_key(),
        sync_change: new_key(),
        sync_envelope: new_key(),
        audit: new_key(),
    }
}

pub(crate) fn wrap_key_set(
    keys: &KeySet,
    passphrase: &str,
    log_n: u8,
) -> Result<KeyringSlot, String> {
    if passphrase.is_empty() {
        return Err("passphrase cannot be empty".into());
    }
    if !(MIN_LOG_N..=MAX_LOG_N).contains(&log_n) {
        return Err("vault keyring cost N is out of range".into());
    }
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let mut slot = KeyringSlot {
        id: Uuid::new_v4().to_string(),
        kind: "passphrase".into(),
        label: "primary".into(),
        kdf: SlotKdf {
            name: "scrypt".into(),
            n: 1u32 << log_n,
            r: 8,
            p: 1,
            salt: BASE64.encode(salt),
        },
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        wrapped: WrappedKeySet {
            iv: BASE64.encode(iv),
            auth_tag: String::new(),
            ciphertext: String::new(),
        },
    };
    let derived = derive_slot_key(passphrase, &slot.kdf)?;
    let aad = slot_aad(&slot)?;
    let plaintext = serialize_key_set(keys)?;
    let mut buffer = Zeroizing::new(plaintext.as_bytes().to_vec());
    let cipher =
        Aes256Gcm::new_from_slice(derived.as_ref()).map_err(|_| "invalid AES key".to_string())?;
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&iv), &aad, &mut *buffer)
        .map_err(|_| "wrapping the vault keyset failed".to_string())?;
    slot.wrapped.auth_tag = BASE64.encode(tag);
    slot.wrapped.ciphertext = BASE64.encode(&*buffer);
    Ok(slot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Vector {
        passphrase: String,
        aad: String,
        keyset_plaintext: String,
        keys: std::collections::HashMap<String, String>,
        slot: KeyringSlot,
    }

    fn vector() -> Vector {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .join("test")
            .join("fixtures")
            .join("keyring-vector.json");
        serde_json::from_slice(&fs::read(path).expect("read the keyring vector"))
            .expect("parse the keyring vector")
    }

    #[test]
    fn associated_data_matches_the_typescript_core_byte_for_byte() {
        let vector = vector();
        assert_eq!(
            String::from_utf8(slot_aad(&vector.slot).unwrap()).unwrap(),
            vector.aad
        );
    }

    #[test]
    fn the_cross_core_vector_unwraps_to_its_recorded_keyset() {
        let vector = vector();
        let keys = unwrap_keyring(
            &KeyringFile {
                version: KEYRING_VERSION,
                slots: vec![vector.slot.clone()],
            },
            &vector.passphrase,
        )
        .unwrap();
        for (name, expected) in [
            ("documents", &keys.documents),
            ("kv", &keys.kv),
            ("attachmentId", &keys.attachment_id),
            ("syncChange", &keys.sync_change),
            ("syncEnvelope", &keys.sync_envelope),
            ("audit", &keys.audit),
        ] {
            assert_eq!(
                BASE64.encode(expected.as_ref()),
                vector.keys[name],
                "key {name}"
            );
        }
    }

    #[test]
    fn the_serialized_keyset_matches_what_the_typescript_core_parses() {
        let vector = vector();
        let keys = unwrap_slot(&vector.slot, &vector.passphrase).unwrap();
        assert_eq!(*serialize_key_set(&keys).unwrap(), vector.keyset_plaintext);
    }

    #[test]
    fn a_rewritten_slot_header_fails_closed() {
        let vector = vector();
        let mut lowered = vector.slot.clone();
        lowered.kdf.n = 1 << 14;
        lowered.kdf.salt = vector.slot.kdf.salt.clone();
        let mut retyped = vector.slot.clone();
        retyped.id = "00000000-0000-4000-8000-000000000002".into();
        let mut corrupted = vector.slot.clone();
        corrupted.ciphertext_corrupted();

        for slot in [lowered, retyped, corrupted] {
            assert!(
                unwrap_slot(&slot, &vector.passphrase).is_err(),
                "a tampered slot must not open"
            );
        }
    }

    #[test]
    fn out_of_policy_costs_are_refused() {
        let vector = vector();
        for (n, r, p) in [(1u32 << 13, 8u32, 1u32), (100_000, 8, 1), (1 << 20, 32, 1), (1 << 15, 0, 1)] {
            let mut slot = vector.slot.clone();
            slot.kdf.n = n;
            slot.kdf.r = r;
            slot.kdf.p = p;
            assert!(
                validate_kdf(&slot.kdf).is_err(),
                "accepted N={n} r={r} p={p}"
            );
        }
    }

    #[test]
    fn a_wrapped_keyset_round_trips_and_rejects_the_wrong_passphrase() {
        let keys = random_key_set();
        let slot = wrap_key_set(&keys, "correct horse battery staple", MIN_LOG_N).unwrap();
        let file = KeyringFile {
            version: KEYRING_VERSION,
            slots: vec![slot],
        };
        // Through JSON, so a serde rename or a field-order mistake is caught here
        // rather than by a user whose other core cannot read the file.
        let round_tripped: KeyringFile =
            serde_json::from_str(&serde_json::to_string(&file).unwrap()).unwrap();
        let opened = unwrap_keyring(&round_tripped, "correct horse battery staple").unwrap();
        assert_eq!(opened.documents.as_ref(), keys.documents.as_ref());
        assert_eq!(opened.audit.as_ref(), keys.audit.as_ref());
        assert!(unwrap_keyring(&round_tripped, "wrong passphrase").is_err());
    }

    #[test]
    fn a_keyring_file_survives_a_write_and_a_read() {
        let dir = std::env::temp_dir().join(format!("vault-brain-keyring-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let keys = random_key_set();
        let file = KeyringFile {
            version: KEYRING_VERSION,
            slots: vec![wrap_key_set(&keys, "pass", MIN_LOG_N).unwrap()],
        };
        write(&dir, &file).unwrap();
        let read_back = read(&dir).unwrap().expect("a keyring was written");
        assert_eq!(
            unwrap_keyring(&read_back, "pass").unwrap().kv.as_ref(),
            keys.kv.as_ref()
        );
        assert!(read(&dir.join("missing")).unwrap().is_none());
        fs::remove_dir_all(&dir).unwrap();
    }
}
```

Note on the `corrupted` slot in `a_rewritten_slot_header_fails_closed`: `ciphertext_corrupted()` is a placeholder that does not exist. Replace that line with:

```rust
        let mut corrupted = vector.slot.clone();
        corrupted.wrapped.ciphertext = BASE64.encode(b"not the original ciphertext");
```

- [ ] **Step 4: Re-read the module as a compiler would**

There is no compiler here, so this step is the substitute. Check, line by line:

- every `use` path resolves against the crate's dependency list in `src-tauri/Cargo.toml`;
- `Zeroizing<[u8; 32]>` is passed as `&[u8]` via `.as_ref()` and as `&mut [u8]` via `.as_mut()`, never moved by accident;
- `&mut *buffer` gives `&mut Vec<u8>` from `Zeroizing<Vec<u8>>`, which is what `decrypt_in_place_detached` and `encrypt_in_place_detached` take, exactly as `src-tauri/src/lib.rs:773` and `:745` do it;
- no `return` on a final expression, no `&Vec<_>` parameters, no needless clone — clippy runs as `-D warnings`;
- `serde_json::to_vec` on `SlotAad` yields compact JSON in declaration order: `context`, `version`, `id`, `type`, `kdf` with `name`, `N`, `r`, `p`, `salt`. Compare it character by character against the `aad` field of `test/fixtures/keyring-vector.json`;
- the `KeySetKeys` field names, after `rename_all = "camelCase"`, are `documents`, `kv`, `attachmentId`, `syncChange`, `syncEnvelope`, `audit`. Compare against `keysetPlaintext` in the vector.

Record the result of this reading in your task report, including anything you changed.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/keyring.rs src-tauri/src/lib.rs src-tauri/Cargo.toml
git commit -m "feat: add the rust vault keyring module"
```

---

### Task 4: The Rust core opens, and creates, a keyring vault

**Files:**

- Modify: `src-tauri/src/lib.rs:90-95` (`VaultSession`), `:1400-1447` (`open_session`), `:4460`, `:4522`, `:6205`

**Interfaces:**

- Consumes: everything Task 3 produced from `crate::keyring`.
- Produces: `VaultSession.attachment_id_key: Zeroizing<[u8; 32]>`, and the new `fn open_vault_keys(vault_dir: &Path, root_dir: &Path, passphrase: &str) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>), String>` returning `(documents key, attachment identity key)`. Task 5's tests read `session.attachment_id_key`.

**This task cannot be verified locally.** Same rule as Task 3.

- [ ] **Step 1: Write the failing tests**

Add to the existing `mod tests` in `src-tauri/src/lib.rs`, after `vault_reopens_and_rejects_the_wrong_passphrase`:

```rust
    #[test]
    fn a_fresh_vault_is_created_keyring_native() {
        let path = temporary_vault("keyring-native");
        let path_text = path.to_string_lossy().into_owned();
        let session = open_session(&path_text, "correct horse battery staple").unwrap();
        let vault_dir = session.vault_dir.clone();
        drop(session);

        assert!(vault_dir.join("keyring.json").exists());
        assert_eq!(
            fs::read_to_string(vault_dir.join("documents").join("manifest.json")).unwrap(),
            "{\n  \"version\": 2,\n  \"keyring\": true\n}\n"
        );
        // The keyring on disk is the one that opens: no cached key material here.
        assert!(open_session(&path_text, "correct horse battery staple").is_ok());
        assert!(open_session(&path_text, "wrong passphrase").is_err());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn a_keyring_vault_missing_its_keyring_explains_itself() {
        let path = temporary_vault("keyring-lost");
        let path_text = path.to_string_lossy().into_owned();
        let session = open_session(&path_text, "correct horse battery staple").unwrap();
        let vault_dir = session.vault_dir.clone();
        drop(session);
        fs::remove_file(vault_dir.join("keyring.json")).unwrap();

        let error = open_session(&path_text, "correct horse battery staple").unwrap_err();
        assert!(
            error.contains("upgraded to a keyring"),
            "unhelpful refusal: {error}"
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn a_legacy_key_value_vault_does_not_gain_a_keyring() {
        let path = temporary_vault("legacy-kv");
        fs::create_dir_all(&path).unwrap();
        // What a pre-keyring release leaves behind for a key-value-only vault.
        fs::write(path.join("health.kv.enc"), "{}").unwrap();
        fs::write(
            path.join("audit.meta.json"),
            "{\"version\":1,\"salt\":\"AAAAAAAAAAAAAAAAAAAAAA==\"}",
        )
        .unwrap();
        let path_text = path.to_string_lossy().into_owned();

        let session = open_session(&path_text, "correct horse battery staple").unwrap();
        let vault_dir = session.vault_dir.clone();
        drop(session);

        assert!(
            !vault_dir.join("keyring.json").exists(),
            "a keyring beside a legacy audit chain would orphan it"
        );
        let manifest: Manifest = serde_json::from_slice(
            &fs::read(vault_dir.join("documents").join("manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest.version, 1);
        fs::remove_dir_all(path).unwrap();
    }
```

- [ ] **Step 2: Note that these cannot be run**

There is no `cargo`. Write down in the task report that Steps 1 and 3 are unverified and that CI's `rust-windows` job is the gate.

- [ ] **Step 3: Widen the session**

At `src-tauri/src/lib.rs:90`:

```rust
struct VaultSession {
    vault_dir: PathBuf,
    root_dir: PathBuf,
    /// The `documents` key: every object under `documents/` is encrypted with it.
    key: Zeroizing<[u8; 32]>,
    /// The `attachmentId` key: permanent, because attachment content addresses
    /// are HMACs under it and every reference already written uses them. Equal
    /// to `key` on a legacy vault, which is what the legacy format means.
    attachment_id_key: Zeroizing<[u8; 32]>,
    index: DocumentIndex,
}
```

Add the manifest-version probe and the tombstone constant beside `Manifest` at `:123`:

```rust
/// Just enough of a manifest to learn its version. A v2 manifest carries no
/// `kdf` and no `verifier`, so deserializing into `Manifest` fails on a missing
/// field and reports that instead of what actually happened to the vault.
#[derive(Debug, Deserialize)]
struct ManifestVersion {
    version: u8,
}

/// Byte-identical to what `vbrain migrate` writes, so a created vault and a
/// migrated vault are the same shape on disk.
const MANIFEST_TOMBSTONE: &str = "{\n  \"version\": 2,\n  \"keyring\": true\n}\n";
```

- [ ] **Step 4: Replace the key resolution in `open_session`**

Add this function immediately above `open_session`:

```rust
/// The `documents` key and the `attachmentId` key for this vault.
///
/// Three branches, in this order. A keyring is authoritative when present. A
/// legacy manifest keeps every check it has today, including the cost the
/// legacy format fixed at 32768 — that constant is legacy-only now, and no
/// keyring cost is ever compared against a compiled-in value. A directory with
/// neither is a brand-new vault and is created keyring-native.
///
/// "No manifest" is not "empty vault": a vault used only through the key-value
/// commands has no document manifest but does have `audit.meta.json` and
/// `*.kv.enc`. Writing a keyring beside those would put a random audit key in
/// front of a chain signed with the key derived from `audit.meta.json`, so a
/// vault holding any legacy marker keeps the legacy path and waits for
/// `vbrain migrate`.
fn open_vault_keys(
    vault_dir: &Path,
    root_dir: &Path,
    passphrase: &str,
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>), String> {
    if let Some(file) = keyring::read(vault_dir)? {
        let keys = keyring::unwrap_keyring(&file, passphrase)?;
        return Ok((keys.documents.clone(), keys.attachment_id.clone()));
    }

    let manifest_path = root_dir.join("manifest.json");
    if manifest_path.exists() {
        reject_symlink(&manifest_path)?;
        let raw = fs::read(&manifest_path).map_err(|error| error.to_string())?;
        let probe: ManifestVersion =
            serde_json::from_slice(&raw).map_err(|error| error.to_string())?;
        if probe.version == 2 {
            return Err(
                "This vault was upgraded to a keyring, but keyring.json is missing or unreadable."
                    .into(),
            );
        }
        let manifest: Manifest = serde_json::from_slice(&raw).map_err(|error| error.to_string())?;
        if manifest.version != 1 || manifest.kdf.name != "scrypt" || manifest.kdf.n != 32768 {
            return Err("unsupported document vault manifest".into());
        }
        let salt = BASE64
            .decode(&manifest.kdf.salt)
            .map_err(|_| "invalid manifest salt")?;
        let key = derive_key(passphrase, &salt)?;
        if verifier(key.as_ref())? != manifest.verifier {
            return Err("wrong passphrase or damaged manifest".into());
        }
        let attachment_id_key = key.clone();
        return Ok((key, attachment_id_key));
    }

    if vault_holds_legacy_material(vault_dir) {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let key = derive_key(passphrase, &salt)?;
        let manifest = Manifest {
            version: 1,
            kdf: KdfManifest {
                name: "scrypt".into(),
                n: 32768,
                salt: BASE64.encode(salt),
            },
            verifier: verifier(key.as_ref())?,
        };
        write_atomic(
            &manifest_path,
            &serde_json::to_vec_pretty(&manifest).map_err(|error| error.to_string())?,
        )?;
        let attachment_id_key = key.clone();
        return Ok((key, attachment_id_key));
    }

    let keys = keyring::random_key_set();
    let slot = keyring::wrap_key_set(&keys, passphrase, keyring::DEFAULT_SCRYPT_LOG_N)?;
    keyring::write(
        vault_dir,
        &keyring::KeyringFile {
            version: keyring::KEYRING_VERSION,
            slots: vec![slot],
        },
    )?;
    write_atomic(&manifest_path, MANIFEST_TOMBSTONE.as_bytes())?;
    // Read back rather than trusting what we just generated: this proves the
    // keyring on disk unwraps before one object is encrypted under it.
    let written = keyring::read(vault_dir)?.ok_or("failed to create a vault keyring")?;
    let opened = keyring::unwrap_keyring(&written, passphrase)?;
    Ok((opened.documents.clone(), opened.attachment_id.clone()))
}

/// The legacy markers `detectVaultFormat` in `src/keyring.ts` looks for, minus
/// the document manifest, which the caller has already ruled out.
fn vault_holds_legacy_material(vault_dir: &Path) -> bool {
    for marker in ["audit.meta.json", "grants.enc", "schema.json"] {
        if vault_dir.join(marker).exists() {
            return true;
        }
    }
    fs::read_dir(vault_dir).is_ok_and(|entries| {
        entries.flatten().any(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".kv.enc"))
        })
    })
}
```

Then replace the whole `let (key, _manifest) = if manifest_path.exists() { ... };` block in `open_session` (`src-tauri/src/lib.rs:1412-1447`) with:

```rust
    let (key, attachment_id_key) = open_vault_keys(&vault_dir, &root_dir, passphrase)?;
```

and delete the now-unused `let manifest_path = ...` line above it, since `open_vault_keys` computes its own. Update the session construction below it:

```rust
    let mut session = VaultSession {
        vault_dir,
        root_dir,
        key,
        attachment_id_key,
        index: DocumentIndex::empty(),
    };
```

- [ ] **Step 5: Move the attachment identity onto its own key**

Three call sites, all currently `session.key.as_ref()`:

`src-tauri/src/lib.rs:4460`:

```rust
    let id = attachment_id(session.attachment_id_key.as_ref(), data)?;
```

`src-tauri/src/lib.rs:4522`:

```rust
    if data.len() != info.size || attachment_id(session.attachment_id_key.as_ref(), &data)? != info.id {
```

`src-tauri/src/lib.rs:6205` (inside `mod tests`):

```rust
            attachment_id(session.attachment_id_key.as_ref(), &binary).unwrap(),
```

Search for any other `session.key` use that concerns attachment identity rather than encryption: `grep -n "session.key" src-tauri/src/lib.rs`. Every remaining one must be an encrypt/decrypt call, which correctly stays on the document key. List them in your report.

- [ ] **Step 6: Re-read the diff as a compiler would**

`Zeroizing<[u8; 32]>` is `Clone`, so `key.clone()` is fine; check that the clone happens before `key` is moved into the return tuple. Check that `keyring::read` errors propagate with `?` and that `open_session`'s existing `VaultWriteGuard` is still acquired before any of this runs, so two processes cannot both create a keyring. Confirm `OsRng`, `BASE64`, `derive_key`, `verifier`, `Manifest` and `KdfManifest` are all in scope in `lib.rs` (they are; the legacy branch is moved code, not new code).

- [ ] **Step 7: Commit**

```bash
git add src-tauri/src/lib.rs
git commit -m "feat: open and create keyring vaults in the rust core"
```

---

### Task 5: The Rust core reads the checked-in keyring fixture

**Files:**

- Modify: `src-tauri/src/lib.rs` (`mod tests`)

**Interfaces:**

- Consumes: `open_session`, `attachment_id`, `read_attachment_manifest`, `VaultSession.attachment_id_key` from Task 4.
- Produces: nothing. This task is evidence.

`test/fixtures/keyring-v2` was written by the TypeScript core in phase 7.1 and contains one note, one attachment whose content is exactly `keyring fixture attachment`, and a keyring wrapped at `N = 2**17` under the passphrase `fixture-only-passphrase`. The attachment's content address is its directory name, `11eda91fda11ea24f0063a23a63c7e2b1570b139a14fc42eb5a5e4a745e1e4ca`. Reproducing that hex string from the Rust core proves the slot AAD, the KDF parameters, the keyset parse and the `attachmentId` key all agree with the core that wrote it.

**This task cannot be verified locally.** Same rule as Task 3.

- [ ] **Step 1: Write the test**

Add to `mod tests` in `src-tauri/src/lib.rs`:

```rust
    fn copy_tree(from: &Path, to: &Path) {
        fs::create_dir_all(to).unwrap();
        for entry in fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let target = to.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), &target).unwrap();
            }
        }
    }

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .join("test")
            .join("fixtures")
            .join(name)
    }

    /// The fixture is copied rather than opened in place: opening a vault takes
    /// the write lock and would leave a lock file inside a checked-in fixture.
    #[test]
    fn the_rust_core_opens_the_typescript_keyring_fixture() {
        let path = temporary_vault("keyring-fixture");
        copy_tree(&fixture("keyring-v2"), &path);
        let path_text = path.to_string_lossy().into_owned();

        let session = open_session(&path_text, "fixture-only-passphrase").unwrap();

        // The documents key: the note object decrypts and indexes.
        let titles: Vec<&str> = session
            .index
            .notes
            .values()
            .map(|indexed| indexed.note.title.as_str())
            .collect();
        assert_eq!(titles, ["Keyring contract"]);

        // The attachmentId key: the content address the TypeScript core wrote.
        const FIXTURE_ATTACHMENT_ID: &str =
            "11eda91fda11ea24f0063a23a63c7e2b1570b139a14fc42eb5a5e4a745e1e4ca";
        assert_eq!(
            attachment_id(
                session.attachment_id_key.as_ref(),
                b"keyring fixture attachment"
            )
            .unwrap(),
            FIXTURE_ATTACHMENT_ID
        );

        // And the manifest of that attachment decrypts under the documents key.
        let info = read_attachment_manifest(&session, FIXTURE_ATTACHMENT_ID).unwrap();
        assert_eq!(info.name, "keyring.txt");
        assert_eq!(info.size, "keyring fixture attachment".len());

        assert!(open_session(&path_text, "wrong passphrase").is_err());
        drop(session);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn the_rust_core_still_opens_a_legacy_document_vault() {
        let path = temporary_vault("legacy-docs");
        copy_tree(&fixture("documents-v1"), &path);
        let path_text = path.to_string_lossy().into_owned();

        let session = open_session(&path_text, "fixture-only-passphrase").unwrap();
        let vault_dir = session.vault_dir.clone();
        assert!(!session.index.notes.is_empty());
        drop(session);

        assert!(
            !vault_dir.join("keyring.json").exists(),
            "opening a legacy vault must not change its format"
        );
        fs::remove_dir_all(path).unwrap();
    }
```

- [ ] **Step 2: Check the two facts the test hard-codes**

The literal attachment ID and the note title come from the fixture, not from memory. Confirm both without a Rust toolchain:

Run: `ls test/fixtures/keyring-v2/documents/attachments`
Expected: the single directory `11eda91fda11ea24f0063a23a63c7e2b1570b139a14fc42eb5a5e4a745e1e4ca`.

Run: `node -e "const {DocumentVault}=require('./dist/documents.js')" 2>/dev/null; node --input-type=module -e "import {DocumentVault} from './dist/documents.js'; import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path'; const t=fs.mkdtempSync(path.join(os.tmpdir(),'kv2-')); const c=(f,d)=>{fs.mkdirSync(d,{recursive:true}); for(const e of fs.readdirSync(f,{withFileTypes:true})){const s=path.join(f,e.name),y=path.join(d,e.name); e.isDirectory()?c(s,y):fs.copyFileSync(s,y);}}; c('test/fixtures/keyring-v2',t); const v=new DocumentVault(t,'fixture-only-passphrase'); console.log(v.list().map(n=>n.title)); console.log(v.attachments().map(a=>[a.id,a.name,a.size])); v.lock();"`
Expected: `[ 'Keyring contract' ]` and one attachment whose id is that same hex string, name `keyring.txt`, size 26.

If either differs, fix the test's literals to match the fixture — never the fixture.

- [ ] **Step 3: Commit**

```bash
git add src-tauri/src/lib.rs
git commit -m "test: prove the rust core opens the typescript keyring fixture"
```

---

### Task 6: Documentation, changelog and benchmark

**Files:**

- Modify: `docs/ARCHITECTURE.md`
- Modify: `SECURITY.md`
- Modify: `docs/ROADMAP.md`
- Modify: `CHANGELOG.md`

**Interfaces:** none.

- [ ] **Step 1: Record the vault layout and the key hierarchy**

In `docs/ARCHITECTURE.md`, find the vault layout listing and the section that describes key derivation. Add `keyring.json` to the layout with a one-line description, and replace any claim that the document key is derived from the passphrase with what the code now does:

```markdown
`keyring.json` — the passphrase-wrapped keyset. A memory-hard KDF (scrypt,
N=2^17) derives a wrapping key from the passphrase; the wrapping key unwraps six
independent 32-byte data keys: `documents`, `kv`, `attachmentId`, `syncChange`,
`syncEnvelope` and `audit`. No data key is derived from the passphrase, which is
what makes changing the passphrase cheap and re-keying possible. Both cores read
this file; only the TypeScript core migrates a legacy vault into it.
```

Do not restate the whole key hierarchy here — link to `docs/superpowers/specs/2026-09-03-vault-keyring-design.md` for it.

- [ ] **Step 2: Record the two limitations in `SECURITY.md`**

```markdown
Losing `keyring.json` loses the vault. Every data key exists only inside it, so
a backup that omits it is not a backup. Nothing about the passphrase recovers a
vault whose keyring is gone.

Migrating a vault does not strengthen copies that already exist. A backup taken
before migration still opens with the old passphrase at the old KDF cost.
```

- [ ] **Step 3: Tick the roadmap and write the changelog entry**

In `docs/ROADMAP.md`, change `- [ ] Rust core opens a keyring vault` to `- [x] Rust core opens a keyring vault`, and add the sub-item this phase also delivered:

```markdown
  - [x] Rust core opens a keyring vault, and both cores create new vaults keyring-native
```

In `CHANGELOG.md`, follow the existing entry format and record: the Rust core opens keyring vaults; new vaults are created keyring-native by both cores, with the version tombstone that makes older builds fail closed; a lost keyring is now explained rather than reported as a missing field; the format is pinned by a deterministic cross-core vector.

- [ ] **Step 4: Take the benchmark numbers**

Run: `npm run benchmark`
Expected: passes its gates. New vaults are keyring-native from Task 1, so this run exercises the keyring path for the first time — unlock should rise by roughly 0.2 s against a 2,000 ms gate, and key-value writes should fall because scrypt no longer runs per write.

Record the before and after numbers in the task report; `CONTRIBUTING.md` requires them in the pull request. The "before" numbers are in the phase 7.1 ledger at `.superpowers/sdd/progress.md` (~285 ms unlock).

- [ ] **Step 5: Run the whole TypeScript suite and the linters**

Run: `npm run lint && npm run typecheck && node --test test/package.test.mjs test/core.test.mjs test/documents.test.mjs test/workflows.test.mjs test/canvas.test.mjs test/grants.test.mjs test/plugins.test.mjs test/obsidian-import.test.mjs test/semantic.test.mjs test/sync.test.mjs test/sync-protocol.test.mjs test/sync-transaction.test.mjs test/sync-apply.test.mjs test/keyring.test.mjs test/keyring-migrate.test.mjs test/keyring-create.test.mjs`
Expected: clean, all tests passing.

- [ ] **Step 6: Commit**

```bash
git add docs/ARCHITECTURE.md SECURITY.md docs/ROADMAP.md CHANGELOG.md
git commit -m "docs: record the keyring in the architecture and security notes"
```

---

## Self-Review

**Spec coverage.** Rust reads a keyring — Tasks 3 and 4. Stops comparing the KDF cost against a constant — Task 4, `open_vault_keys`, where the legacy 32768 check survives only in the legacy branch. Explains a v2 manifest with no keyring — Task 4, `ManifestVersion`. New vaults keyring-native in both cores — Task 1 (TypeScript) and Task 4 branch 3 (Rust). Version tombstone on creation — Tasks 1 and 4. Ported format detection — Task 1's `detectVaultFormat` reuse and Task 4's `vault_holds_legacy_material`. Cross-core tests in both directions — Task 2's vector (write direction, by proving Rust's serializer produces a plaintext TypeScript parses and its AAD authenticates TypeScript's ciphertext) and Task 5 (read direction, against a real vault). Fail-closed tests — Task 3's tamper and bounds tests plus Task 4's missing-keyring test. `ARCHITECTURE.md`, `SECURITY.md`, roadmap, changelog, benchmark — Task 6.

Two spec items are deliberately delivered differently, both because no Rust toolchain exists on this machine: the spec's `test/fixtures/keyring-v2-rust/` fixture, which would have to be generated by running Rust, is replaced by the deterministic vector of Task 2, which proves the same property offline and more precisely; and the spec's `.gitignore` negation is already present, added during 7.1.

**Placeholders.** One deliberate placeholder is called out and corrected inline: `ciphertext_corrupted()` in Task 3's tamper test, with its replacement given immediately below the code block. There are no others; every step that changes code shows the code.

**Type consistency.** `KeySet` fields are `documents`, `kv`, `attachment_id`, `sync_change`, `sync_envelope`, `audit` in Task 3 and are read as `keys.documents` / `keys.attachment_id` in Task 4. `keyring::read` returns `Result<Option<KeyringFile>, String>` in Task 3 and is consumed with `if let Some(file) = keyring::read(vault_dir)?` in Task 4. `wrap_key_set(&KeySet, &str, u8)` takes `log_n`, and Task 4 passes `keyring::DEFAULT_SCRYPT_LOG_N`, not an `N`. `openOrCreateVaultKeys` returns `KeySet | null` in Task 1 and is consumed as such by `document-crypto.ts`; `openOrCreateVaultKey` returns `Buffer | null` and is consumed as such by `store.ts`, `grants.ts` and `audit.ts`.
