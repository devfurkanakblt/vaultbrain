# Phase 7.3 — Passphrase Change Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `vbrain passphrase change`, which re-wraps the vault keyset under a new passphrase at the current default KDF cost without re-encrypting a single object.

**Architecture:** A pure library function `changeVaultPassphrase` in a new `src/keyring-passphrase.ts` reads `keyring.json`, unwraps the keyset with the current passphrase, re-wraps every slot that passphrase opens under the new one at `DEFAULT_SCRYPT_N`, writes the file atomically, verifies it re-opens, and drops the in-process key cache — all inside `withVaultLock`. `src/keychain.ts` gains one helper that refreshes a remembered credential. `src/cli.ts` adds a `passphrase` parent command with a `change` subcommand that does the prompting, the printing and the keychain call.

**Tech Stack:** TypeScript (ESM, compiled to `dist/` by `tsc`), Node's `node:crypto` scrypt and AES-256-GCM, `commander` for the CLI, `node --test` with `node:assert/strict` for tests.

## Global Constraints

- Design spec: `docs/superpowers/specs/2026-09-04-phase-7-3-passphrase-change-design.md`. Shared format contract: `docs/superpowers/specs/2026-09-03-vault-keyring-design.md`.
- Branch: `phase-7-3-passphrase-change`, already created. Commit after every task.
- No on-disk format changes. `keyring.json` stays `version: 2`, the keyset stays `version: 1`, `KEY_NAMES` order is untouched. No fixture is added, edited or regenerated.
- `src/keyring.ts` is not modified by this phase. Everything it needs is already exported: `DEFAULT_SCRYPT_N`, `KEYRING_VERSION`, `KEY_NAMES`, `readKeyring`, `writeKeyring`, `unwrapSlot`, `unwrapKeyring`, `wrapKeySet`, `zeroKeySet`, `forgetVaultKeys`, `detectVaultFormat`, and the types `KeySet`, `KeyringSlot`.
- No Rust change. Since 7.2 the Rust core reads `N` from the slot; a re-wrapped keyring at a different cost opens unchanged.
- Minimum new-passphrase length is 12 characters. It applies to the new passphrase only, never to the existing one.
- Tests import from `../dist/*.js`, never from `src/`. `npm test` builds first.
- `fs.cpSync` crashes Node on the development machine — copy trees with the `copyTree` helper the existing tests use.
- Every command in this plan runs from the repository root: `C:\Users\bekircan\OneDrive\Masaüstü\yazilim\vaultbrain`.
- Commit message trailers, on every commit:

```
Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0117aYpsscAmKUx8LtubpHyi
```

---

## File Structure

- Create `src/keyring-passphrase.ts` — the whole passphrase-change operation as one pure function. No prompting, no printing, no credential store.
- Modify `src/keychain.ts` — add `updateRememberedPassphrase`, so the credential refresh is testable in-process through the existing `setKeychainBackend` seam. (The design spec puts the keychain call "in `src/cli.ts`"; the call site stays there, but the logic lives beside the rest of the credential code, which is what makes it testable, since a CLI subprocess cannot be handed a fake backend.)
- Modify `src/cli.ts` — the `passphrase change` command: prompting, output, keychain call.
- Create `test/keyring-passphrase.test.mjs` — library, keychain helper and CLI end-to-end tests.
- Modify `package.json` — add the new test file to the `test` script.
- Modify `README.md`, `SECURITY.md`, `docs/ROADMAP.md`, `docs/ARCHITECTURE.md`, `CHANGELOG.md`.

---

### Task 1: `changeVaultPassphrase`

**Files:**
- Create: `src/keyring-passphrase.ts`
- Create: `test/keyring-passphrase.test.mjs`
- Modify: `package.json:34` (the `test` script's file list)

**Interfaces:**
- Consumes: from `./keyring.js` — `DEFAULT_SCRYPT_N: number`, `KEYRING_VERSION: number`, `KEY_NAMES: readonly KeyName[]`, `detectVaultFormat(vaultDir): "keyring" | "legacy" | "empty"`, `readKeyring(vaultDir): KeyringFile | null`, `writeKeyring(vaultDir, file): void`, `unwrapSlot(slot, passphrase): KeySet`, `unwrapKeyring(file, passphrase): KeySet`, `wrapKeySet(keys, passphrase, N?): KeyringSlot`, `zeroKeySet(keys): void`, `forgetVaultKeys(vaultDir?): void`; from `./vault-lock.js` — `withVaultLock(vaultDir, operation, options?)`.
- Produces: `MIN_PASSPHRASE_LENGTH: number`, `PassphraseChangeReport { slotsRewritten: number; slotsPreserved: number; previousN: number; newN: number }`, and `changeVaultPassphrase(vaultDir: string, currentPassphrase: string, newPassphrase: string, options?: { allowSamePassphrase?: boolean }): PassphraseChangeReport`. Task 3 calls exactly this.

- [ ] **Step 1: Write the failing tests**

Create `test/keyring-passphrase.test.mjs`:

```js
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { appendAudit, verifyAudit } from "../dist/audit.js";
import { DocumentVault } from "../dist/documents.js";
import {
  DEFAULT_SCRYPT_N,
  forgetVaultKeys,
  openVaultKeys,
  randomKeySet,
  wrapKeySet,
  writeKeyring,
} from "../dist/keyring.js";
import { changeVaultPassphrase, MIN_PASSPHRASE_LENGTH } from "../dist/keyring-passphrase.js";
import { loadVaultFile, upsertEntry } from "../dist/store.js";

const PASSPHRASE = "phase-73-current-passphrase";
const NEW_PASSPHRASE = "phase-73-replacement-passphrase";

function tempDir(label = "passphrase") {
  return fs.mkdtempSync(path.join(os.tmpdir(), `vault-brain-${label}-`));
}

/** A keyring-native vault holding one note, one attachment and one key-value entry. */
function seedVault(passphrase = PASSPHRASE) {
  const dir = tempDir();
  const vault = new DocumentVault(dir, passphrase);
  vault.put({ path: "Atlas/First.md", title: "First", body: "# First\n\nbody" });
  const attachment = vault.putAttachment(Buffer.from("phase 7.3 attachment"), "note.bin");
  vault.lock();
  upsertEntry(dir, "health", "BLOOD_TYPE", "0 Rh+", "blood group", passphrase);
  appendAudit(dir, { actor: "cli-direct-write", file: "health", key: "BLOOD_TYPE" }, passphrase);
  return { dir, attachmentId: attachment.id };
}

function readSlots(dir) {
  return JSON.parse(fs.readFileSync(path.join(dir, "keyring.json"), "utf8")).slots;
}

test("the new passphrase opens the vault and the old one no longer does", () => {
  const { dir } = seedVault();

  // Warm the in-process keyset cache under the old passphrase first, so this
  // also proves the change drops it rather than serving a stale keyset.
  assert.ok(openVaultKeys(dir, PASSPHRASE));

  const report = changeVaultPassphrase(dir, PASSPHRASE, NEW_PASSPHRASE);
  assert.equal(report.slotsRewritten, 1);
  assert.equal(report.slotsPreserved, 0);

  assert.throws(() => openVaultKeys(dir, PASSPHRASE), /wrong passphrase/iu);
  assert.ok(openVaultKeys(dir, NEW_PASSPHRASE));

  // And again from disk, with nothing cached at all.
  forgetVaultKeys();
  assert.ok(openVaultKeys(dir, NEW_PASSPHRASE));
  assert.throws(() => openVaultKeys(dir, PASSPHRASE), /wrong passphrase/iu);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("no object is re-encrypted: notes, attachments and key-value entries survive unchanged", () => {
  const { dir, attachmentId } = seedVault();

  changeVaultPassphrase(dir, PASSPHRASE, NEW_PASSPHRASE);
  forgetVaultKeys();

  const vault = new DocumentVault(dir, NEW_PASSPHRASE);
  assert.deepEqual(
    vault.list().map((note) => note.path),
    ["Atlas/First.md"],
  );
  assert.deepEqual(
    vault.listAttachments().map((info) => info.id),
    [attachmentId],
    "the attachment content address must not move",
  );
  vault.lock();
  assert.equal(loadVaultFile(dir, "health", NEW_PASSPHRASE)[0].value, "0 Rh+");
  assert.equal(
    verifyAudit(dir, NEW_PASSPHRASE).valid,
    true,
    "the audit key is permanent, so the pre-change chain must still verify",
  );

  fs.rmSync(dir, { recursive: true, force: true });
});

test("the change raises an old vault's KDF cost to the current default", () => {
  const dir = tempDir("cost");
  const keys = randomKeySet();
  // 2**14 is the lowest cost the format accepts, which keeps this test fast.
  writeKeyring(dir, { version: 2, slots: [wrapKeySet(keys, PASSPHRASE, 2 ** 14)] });
  const oldSalt = readSlots(dir)[0].kdf.salt;

  const report = changeVaultPassphrase(dir, PASSPHRASE, NEW_PASSPHRASE);

  assert.equal(report.previousN, 2 ** 14);
  assert.equal(report.newN, DEFAULT_SCRYPT_N);
  const [slot] = readSlots(dir);
  assert.equal(slot.kdf.N, DEFAULT_SCRYPT_N);
  assert.notEqual(slot.kdf.salt, oldSalt, "a re-wrap must draw a fresh salt");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("a slot the current passphrase cannot open is preserved untouched", () => {
  const dir = tempDir("slots");
  const keys = randomKeySet();
  const recovery = wrapKeySet(keys, "recovery-slot-passphrase", 2 ** 14);
  writeKeyring(dir, { version: 2, slots: [wrapKeySet(keys, PASSPHRASE, 2 ** 14), recovery] });

  const report = changeVaultPassphrase(dir, PASSPHRASE, NEW_PASSPHRASE);

  assert.equal(report.slotsRewritten, 1);
  assert.equal(report.slotsPreserved, 1);
  const slots = readSlots(dir);
  assert.deepEqual(
    slots.find((slot) => slot.id === recovery.id),
    recovery,
    "the foreign slot must survive byte for byte",
  );
  forgetVaultKeys();
  assert.ok(openVaultKeys(dir, "recovery-slot-passphrase"));

  fs.rmSync(dir, { recursive: true, force: true });
});

test("every refusal leaves keyring.json byte-identical", () => {
  const { dir } = seedVault();
  const before = fs.readFileSync(path.join(dir, "keyring.json"));

  assert.throws(() => changeVaultPassphrase(dir, PASSPHRASE, "short"), /at least 12 characters/iu);
  assert.throws(
    () => changeVaultPassphrase(dir, PASSPHRASE, PASSPHRASE),
    /same as the current one/iu,
  );
  assert.throws(
    () => changeVaultPassphrase(dir, "wrong-current-passphrase", NEW_PASSPHRASE),
    /wrong passphrase/iu,
  );

  assert.deepEqual(fs.readFileSync(path.join(dir, "keyring.json")), before);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("a legacy vault is refused and pointed at vbrain migrate", () => {
  const dir = tempDir("legacy");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "schema.json"), '{"version":1,"files":{}}\n');

  assert.throws(() => changeVaultPassphrase(dir, PASSPHRASE, NEW_PASSPHRASE), /vbrain migrate/u);
  assert.ok(!fs.existsSync(path.join(dir, "keyring.json")), "a refusal must not create a keyring");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("--allow-same-passphrase re-wraps at the current cost without changing the passphrase", () => {
  const dir = tempDir("same");
  const keys = randomKeySet();
  writeKeyring(dir, { version: 2, slots: [wrapKeySet(keys, PASSPHRASE, 2 ** 14)] });

  const report = changeVaultPassphrase(dir, PASSPHRASE, PASSPHRASE, { allowSamePassphrase: true });

  assert.equal(report.newN, DEFAULT_SCRYPT_N);
  assert.equal(readSlots(dir)[0].kdf.N, DEFAULT_SCRYPT_N);
  forgetVaultKeys();
  assert.ok(openVaultKeys(dir, PASSPHRASE));

  fs.rmSync(dir, { recursive: true, force: true });
});

test("the minimum length is the documented one", () => {
  assert.equal(MIN_PASSPHRASE_LENGTH, 12);
});
```

- [ ] **Step 2: Add the test file to the test script**

In `package.json:34`, append ` test/keyring-passphrase.test.mjs` to the end of the `test` script's file list, directly after `test/keyring-create.test.mjs`.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `npm test`
Expected: the build succeeds and `test/keyring-passphrase.test.mjs` fails with `Cannot find module .../dist/keyring-passphrase.js`.

- [ ] **Step 4: Write the implementation**

Create `src/keyring-passphrase.ts`:

```ts
import crypto from "node:crypto";
import {
  DEFAULT_SCRYPT_N,
  KEYRING_VERSION,
  KEY_NAMES,
  detectVaultFormat,
  forgetVaultKeys,
  readKeyring,
  unwrapKeyring,
  unwrapSlot,
  wrapKeySet,
  writeKeyring,
  zeroKeySet,
  type KeyringSlot,
  type KeySet,
} from "./keyring.js";
import { withVaultLock } from "./vault-lock.js";

/**
 * NIST SP 800-63B's floor for a user-chosen secret. It applies to the new
 * passphrase only: an existing vault whose passphrase is shorter still opens,
 * because refusing it would lock its owner out rather than protect them.
 */
export const MIN_PASSPHRASE_LENGTH = 12;

export interface PassphraseChangeReport {
  /** Slots re-wrapped under the new passphrase. */
  slotsRewritten: number;
  /** Slots the current passphrase could not open, carried across untouched. */
  slotsPreserved: number;
  /** The scrypt cost of the first slot that opened, before the change. */
  previousN: number;
  /** The cost every rewritten slot now carries. */
  newN: number;
}

function sameKeySet(a: KeySet, b: KeySet): boolean {
  return KEY_NAMES.every(
    (name) => a[name].length === b[name].length && crypto.timingSafeEqual(a[name], b[name]),
  );
}

/**
 * Re-wraps the vault keyset under a new passphrase. Nothing under
 * `documents/`, no attachment, no sync change and no audit entry is read or
 * rewritten: only the wrapping layer changes, so attachment identities, sync
 * change IDs and the audit chain all survive untouched. Because every slot is
 * written at `DEFAULT_SCRYPT_N` with a fresh salt, this is also how a vault
 * created at a lower cost raises its work factor.
 *
 * A slot the current passphrase cannot open — the recovery slot the format
 * reserves — is carried across byte for byte rather than discarded.
 */
export function changeVaultPassphrase(
  vaultDir: string,
  currentPassphrase: string,
  newPassphrase: string,
  options: { allowSamePassphrase?: boolean } = {},
): PassphraseChangeReport {
  if (!currentPassphrase) throw new Error("A non-empty vault passphrase is required.");
  if (newPassphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(`The new passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters.`);
  }
  if (newPassphrase === currentPassphrase && !options.allowSamePassphrase) {
    throw new Error(
      "The new passphrase is the same as the current one. Pass --allow-same-passphrase to re-wrap the keyring at the current cost without changing it.",
    );
  }

  return withVaultLock(vaultDir, () => {
    if (detectVaultFormat(vaultDir) !== "keyring") {
      throw new Error("This vault is not in the keyring format yet. Run 'vbrain migrate' first.");
    }
    const file = readKeyring(vaultDir);
    if (!file) throw new Error("This vault has no keyring to change.");

    let opened: KeySet | undefined;
    let previousN = 0;
    let slotsPreserved = 0;
    const slots: KeyringSlot[] = [];

    for (const slot of file.slots) {
      let keys: KeySet;
      try {
        keys = unwrapSlot(slot, currentPassphrase);
      } catch {
        // Not this passphrase's slot. Preserving it is what keeps a recovery
        // slot alive across a passphrase change.
        slots.push(slot);
        slotsPreserved += 1;
        continue;
      }
      if (opened) zeroKeySet(keys);
      else {
        opened = keys;
        previousN = slot.kdf.N;
      }
      slots.push(wrapKeySet(opened, newPassphrase));
    }

    if (!opened) {
      throw new Error("Unable to unlock this vault: wrong passphrase, or the keyring is damaged.");
    }

    writeKeyring(vaultDir, { version: KEYRING_VERSION, slots });
    forgetVaultKeys(vaultDir);

    // Prove the file on disk opens under the passphrase the user was just
    // given, and carries the same keyset, before reporting success. A keyring
    // that does not open is an unrecoverable vault.
    const written = readKeyring(vaultDir);
    if (!written) throw new Error("The new keyring could not be read back.");
    const verified = unwrapKeyring(written, newPassphrase);
    try {
      if (!sameKeySet(verified, opened)) {
        throw new Error("The new keyring does not carry the vault's keyset; the vault was not changed correctly.");
      }
    } finally {
      zeroKeySet(verified);
    }

    const rewritten = slots.length - slotsPreserved;
    zeroKeySet(opened);
    return { slotsRewritten: rewritten, slotsPreserved, previousN, newN: DEFAULT_SCRYPT_N };
  });
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `npm test`
Expected: every test in `test/keyring-passphrase.test.mjs` passes, and no existing test regresses.

- [ ] **Step 6: Lint and typecheck**

Run: `npm run lint && npm run typecheck`
Expected: both clean, no warnings.

- [ ] **Step 7: Commit**

```bash
git add src/keyring-passphrase.ts test/keyring-passphrase.test.mjs package.json
git commit -F- <<'MSG'
feat: re-wrap the vault keyset under a new passphrase

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0117aYpsscAmKUx8LtubpHyi
MSG
```

---

### Task 2: Refresh the remembered credential

**Files:**
- Modify: `src/keychain.ts` (append after `forgetPassphrase`, around line 193)
- Modify: `test/keyring-passphrase.test.mjs` (append)

**Interfaces:**
- Consumes: `keychain(): KeychainBackend`, `accountFor(vaultDir): string`, `setKeychainBackend(backend | undefined): void` — all already exported from `src/keychain.ts`.
- Produces: `updateRememberedPassphrase(vaultDir: string, passphrase: string): { updated: boolean; backend: string; error?: string }`. Task 3 calls exactly this. `updated` is false with no `error` when the store simply held nothing for this vault; `updated` is false with an `error` when a stored credential could not be replaced.

- [ ] **Step 1: Write the failing tests**

Append to `test/keyring-passphrase.test.mjs`:

```js
import { setKeychainBackend, updateRememberedPassphrase } from "../dist/keychain.js";

/** A fake credential store. `failOnStore` makes writes throw, as a locked keychain does. */
function fakeKeychain({ failOnStore = false } = {}) {
  const entries = new Map();
  return {
    entries,
    backend: {
      name: "fake",
      available: () => true,
      store(account, secret) {
        if (failOnStore) throw new Error("credential store is locked");
        entries.set(account, secret);
      },
      lookup: (account) => entries.get(account),
      forget: (account) => entries.delete(account),
    },

  };
}

test("a remembered passphrase is replaced with the new one", () => {
  const { dir } = seedVault();
  const fake = fakeKeychain();
  setKeychainBackend(fake.backend);
  try {
    fake.backend.store(accountFor(dir), PASSPHRASE);

    const result = updateRememberedPassphrase(dir, NEW_PASSPHRASE);

    assert.equal(result.updated, true);
    assert.equal(result.backend, "fake");
    assert.equal(result.error, undefined);
    assert.equal(fake.entries.get(accountFor(dir)), NEW_PASSPHRASE);
  } finally {
    setKeychainBackend(undefined);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a vault with nothing remembered is left alone", () => {
  const { dir } = seedVault();
  const fake = fakeKeychain();
  setKeychainBackend(fake.backend);
  try {
    const result = updateRememberedPassphrase(dir, NEW_PASSPHRASE);

    assert.equal(result.updated, false);
    assert.equal(result.error, undefined);
    assert.equal(fake.entries.size, 0, "nothing may be stored for a vault that had nothing");
  } finally {
    setKeychainBackend(undefined);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a store that refuses the write is reported rather than thrown", () => {
  const { dir } = seedVault();
  const fake = fakeKeychain({ failOnStore: true });
  setKeychainBackend(fake.backend);
  try {
    fake.entries.set(accountFor(dir), PASSPHRASE);

    const result = updateRememberedPassphrase(dir, NEW_PASSPHRASE);

    assert.equal(result.updated, false);
    assert.match(result.error ?? "", /locked/u);
  } finally {
    setKeychainBackend(undefined);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
```

Add `accountFor` to that same import: the import line becomes

```js
import { accountFor, setKeychainBackend, updateRememberedPassphrase } from "../dist/keychain.js";
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npm run build && node --test test/keyring-passphrase.test.mjs`
Expected: FAIL — `updateRememberedPassphrase is not a function`.

- [ ] **Step 3: Write the implementation**

Append to `src/keychain.ts`:

```ts
/**
 * Replaces this vault's remembered passphrase after it has changed. A vault
 * with nothing remembered is left alone: storing a credential the user never
 * asked to store is `vbrain unlock --remember`'s job, not a side effect of a
 * passphrase change. A store that refuses the write is reported rather than
 * thrown, because by the time this runs the vault has already changed and the
 * caller must not report failure for an operation that completed.
 */
export function updateRememberedPassphrase(
  vaultDir: string,
  passphrase: string,
): { updated: boolean; backend: string; error?: string } {
  const backend = keychain();
  const account = accountFor(vaultDir);
  try {
    if (!backend.lookup(account)) return { updated: false, backend: backend.name };
    backend.store(account, passphrase);
    return { updated: true, backend: backend.name };
  } catch (error) {
    return {
      updated: false,
      backend: backend.name,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm test`
Expected: all three new tests pass; nothing else regresses.

- [ ] **Step 5: Lint and typecheck**

Run: `npm run lint && npm run typecheck`
Expected: both clean.

- [ ] **Step 6: Commit**

```bash
git add src/keychain.ts test/keyring-passphrase.test.mjs
git commit -F- <<'MSG'
feat: refresh a remembered credential after a passphrase change

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0117aYpsscAmKUx8LtubpHyi
MSG
```

---

### Task 3: The `vbrain passphrase change` command

**Files:**
- Modify: `src/cli.ts` (imports near lines 17-19; new command block immediately after the `migrate` command, which ends around line 1222)
- Modify: `test/keyring-passphrase.test.mjs` (append)

**Interfaces:**
- Consumes: `changeVaultPassphrase`, `MIN_PASSPHRASE_LENGTH` (Task 1); `updateRememberedPassphrase` (Task 2); `getPassphrase({ vaultDir })` and `readSecret(prompt)` from `./passphrase.js`, both already imported by `src/cli.ts`.
- Produces: the CLI surface `vbrain --vault <dir> passphrase change [--allow-same-passphrase]`, reading the new passphrase from `VBRAIN_NEW_PASSPHRASE` when set.

- [ ] **Step 1: Write the failing test**

Append to `test/keyring-passphrase.test.mjs` (and add `import { spawnSync } from "node:child_process";` and `import { fileURLToPath } from "node:url";` to the top of the file):

```js
const cliPath = fileURLToPath(new URL("../dist/cli.js", import.meta.url));

function runCli(args, env) {
  return spawnSync(process.execPath, [cliPath, ...args], {
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
}

test("the CLI changes the passphrase end to end", () => {
  const { dir } = seedVault();

  const result = runCli(["--vault", dir, "passphrase", "change"], {
    VBRAIN_PASSPHRASE: PASSPHRASE,
    VBRAIN_NEW_PASSPHRASE: NEW_PASSPHRASE,
  });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Passphrase changed/u);
  assert.match(result.stdout, /does not re-encrypt/u);
  assert.match(result.stdout, /vbrain rekey/u);

  forgetVaultKeys();
  assert.ok(openVaultKeys(dir, NEW_PASSPHRASE));
  assert.throws(() => openVaultKeys(dir, PASSPHRASE), /wrong passphrase/iu);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("the CLI refuses a short new passphrase and leaves the vault alone", () => {
  const { dir } = seedVault();
  const before = fs.readFileSync(path.join(dir, "keyring.json"));

  const result = runCli(["--vault", dir, "passphrase", "change"], {
    VBRAIN_PASSPHRASE: PASSPHRASE,
    VBRAIN_NEW_PASSPHRASE: "short",
  });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /at least 12 characters/u);
  assert.deepEqual(fs.readFileSync(path.join(dir, "keyring.json")), before);

  forgetVaultKeys();
  assert.ok(openVaultKeys(dir, PASSPHRASE), "the old passphrase must still work");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("the CLI refuses a legacy vault and names vbrain migrate", () => {
  const dir = tempDir("cli-legacy");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "schema.json"), '{"version":1,"files":{}}\n');

  const result = runCli(["--vault", dir, "passphrase", "change"], {
    VBRAIN_PASSPHRASE: PASSPHRASE,
    VBRAIN_NEW_PASSPHRASE: NEW_PASSPHRASE,
  });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /vbrain migrate/u);

  fs.rmSync(dir, { recursive: true, force: true });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npm run build && node --test test/keyring-passphrase.test.mjs`
Expected: FAIL — commander reports `unknown command 'passphrase'` and the exit status is non-zero for the first test.

- [ ] **Step 3: Add the imports**

In `src/cli.ts`, extend the existing keychain import (line 17) and add one import beside the `keyring-migrate` import (line 19):

```ts
import {
  forgetPassphrase,
  keychain,
  recallPassphrase,
  rememberPassphrase,
  updateRememberedPassphrase,
} from "./keychain.js";
import { changeVaultPassphrase, MIN_PASSPHRASE_LENGTH } from "./keyring-passphrase.js";
```

- [ ] **Step 4: Write the command**

In `src/cli.ts`, immediately after the `migrate` command's `.action(...)` block and before the `unlock` command, insert:

```ts
const passphraseCommand = program.command("passphrase").description("manage the passphrase that wraps this vault's keys");

passphraseCommand
  .command("change")
  .description("change the vault passphrase and re-wrap the keyring at the current KDF cost")
  .option("--allow-same-passphrase", "re-wrap the keyring at the current cost without changing the passphrase")
  .action(async (opts) => {
    const dir = program.opts().vault;
    const current = await getPassphrase({ vaultDir: dir, prompt: "Current vault passphrase: " });
    const next = process.env.VBRAIN_NEW_PASSPHRASE ?? (await readNewPassphrase());

    const report = changeVaultPassphrase(dir, current, next, {
      allowSamePassphrase: Boolean(opts.allowSamePassphrase),
    });

    console.log(`Passphrase changed for ${dir}.`);
    console.log(`Re-wrapped ${report.slotsRewritten} keyring slot(s) at scrypt N=${report.newN}.`);
    if (report.previousN !== report.newN) {
      console.log(`Key-derivation cost raised from N=${report.previousN}.`);
    }
    if (report.slotsPreserved > 0) {
      console.log(`Left ${report.slotsPreserved} slot(s) this passphrase does not open untouched.`);
    }

    const keychainResult = updateRememberedPassphrase(dir, next);
    if (keychainResult.updated) {
      console.log(`Updated the remembered passphrase in the OS credential store (${keychainResult.backend}).`);
    } else if (keychainResult.error) {
      console.error(
        `Warning: this vault has a remembered passphrase but it could not be updated (${keychainResult.backend}: ${keychainResult.error}). ` +
          "It is now stale — run 'vbrain unlock --remember' to store the new one.",
      );
    }

    console.log("This does not re-encrypt anything: every note, attachment and sync change keeps its key.");
    console.log("If the old passphrase leaked, run 'vbrain rekey' once it ships.");
  });

/** Two masked entries that have to agree, so a typo cannot become the new passphrase. */
async function readNewPassphrase(): Promise<string> {
  const first = await readSecret("New vault passphrase: ");
  if (first.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(`The new passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters.`);
  }
  const second = await readSecret("Repeat new vault passphrase: ");
  if (first !== second) throw new Error("The two entries did not match; nothing was changed.");
  return first;
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `npm test`
Expected: the three CLI tests pass; nothing else regresses.

- [ ] **Step 6: Check the help text by hand**

Run: `node dist/cli.js passphrase change --help`
Expected: the description and `--allow-same-passphrase` are listed, and the process exits 0.

- [ ] **Step 7: Lint and typecheck**

Run: `npm run lint && npm run typecheck`
Expected: both clean.

- [ ] **Step 8: Commit**

```bash
git add src/cli.ts test/keyring-passphrase.test.mjs
git commit -F- <<'MSG'
feat: add vbrain passphrase change

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0117aYpsscAmKUx8LtubpHyi
MSG
```

---

### Task 4: Documentation and the full gate

**Files:**
- Modify: `docs/ROADMAP.md` (Phase 7, the "Passphrase change" line)
- Modify: `README.md` (the command list)
- Modify: `SECURITY.md`
- Modify: `docs/ARCHITECTURE.md` (the keyring paragraph added in 7.2)
- Modify: `CHANGELOG.md` (the unreleased section)

**Interfaces:**
- Consumes: the shipped command from Task 3. Produces: no code.

- [ ] **Step 1: Tick the roadmap**

In `docs/ROADMAP.md`, under Phase 7, change

```markdown
- [ ] Passphrase change, including the KDF cost upgrade path
```

to

```markdown
- [x] Passphrase change, including the KDF cost upgrade path
```

- [ ] **Step 2: Document the command in README.md**

Find the command list that already contains `vbrain migrate` and add, in the same style as its neighbours:

```markdown
- `vbrain passphrase change` — change the vault passphrase. The keyring is
  re-wrapped at the current key-derivation cost, so this is also how a vault
  created under an older, cheaper setting raises its work factor. Nothing is
  re-encrypted, and it takes the same time on a 100,000-note vault as on an
  empty one. Add `--allow-same-passphrase` to raise the cost without changing
  the passphrase. Set `VBRAIN_NEW_PASSPHRASE` to run it unattended.
```

- [ ] **Step 3: Document the limitation in SECURITY.md**

Add, beside the migration limitations that phase 7.1 put there:

```markdown
Changing the passphrase does not re-encrypt content. It replaces the wrapping
around the vault's keys, nothing more. Anyone who already knew the old
passphrase and holds a copy of the vault reads what that copy contains, before
and after. `vbrain rekey` is the answer to a leaked passphrase.

A vault created before the default key-derivation cost rose keeps its old cost
until its passphrase is changed once. `vbrain passphrase change` writes every
slot at the current default, so one run raises the work factor without touching
a single note.
```

- [ ] **Step 4: One line in docs/ARCHITECTURE.md**

In the paragraph describing `keyring.json`, add:

```markdown
A passphrase change re-wraps the keyset in place: the slot gets a fresh salt at
the current cost, the keys inside it do not move, and no object is rewritten.
```

- [ ] **Step 5: Add the changelog entry**

Add to the unreleased section of `CHANGELOG.md`, matching the surrounding style:

```markdown
- `vbrain passphrase change`: re-wraps the vault keyring under a new passphrase
  at the current key-derivation cost, without re-encrypting any object.
```

- [ ] **Step 6: Run the full gate**

Run: `npm run lint && npm run typecheck && npm run format:check && npm test`
Expected: all clean. If `format:check` fails on a file this phase touched, run `npm run format` and re-run the gate. `cargo fmt` inside `format:check` will fail if no Rust toolchain is installed on this machine; that is the known environment constraint from 7.2 and is not this phase's failure — note it and rely on CI's `rust-windows` job.

- [ ] **Step 7: Commit**

```bash
git add docs/ROADMAP.md README.md SECURITY.md docs/ARCHITECTURE.md CHANGELOG.md
git commit -F- <<'MSG'
docs: document the passphrase change command and its limits

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0117aYpsscAmKUx8LtubpHyi
MSG
```

---

## Verification

After Task 4, the branch should show, from `git diff --stat main`:

- `src/keyring-passphrase.ts` created;
- `src/keychain.ts` and `src/cli.ts` modified;
- `test/keyring-passphrase.test.mjs` created and listed in `package.json`;
- five documentation files touched;
- no change under `src-tauri/`, no change to `src/keyring.ts`, and no fixture touched.
