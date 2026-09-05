# Phase 7.7 — What 7.4 and 7.5 left behind Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the three gaps Phase 7.4 and 7.5 left open where they touch each
other and Phase 8: the Rust core silently destroying `legacyChangeIdentity` on
every re-wrap, `vbrain rekey` writing nothing to the audit chain, and two
documents that name behaviour the code does not have.

**Architecture:** Nothing here changes a format, a key derivation, or an AAD.
Task 1 teaches the Rust core to carry one optional keyset field it currently
drops, proved by a second frozen cross-core vector alongside the existing one.
Task 2 wraps `rekeyVault`'s existing mutation window in the paired
pending/allowed/denied audit events every other key-material command already
writes, using the pinned `audit` key that is identical on both sides of a
re-key. Task 3 corrects the documentation and replaces one misleading Rust
error string.

**Tech Stack:** TypeScript, Node.js `node:test`, Rust (`serde`, `zeroize`,
`aes-gcm`), Commander.

**Spec:** none. This plan is derived directly from the gap analysis against
`docs/superpowers/plans/2026-09-04-phase-7-4-full-rekey.md`,
`docs/superpowers/plans/2026-09-04-phase-7-5-survivable-keyrings.md` and
`docs/ROADMAP.md` §Phase 7 / §Phase 8.

## Global Constraints

- **No format change.** `KEYSET_VERSION` stays `1`, `KEYRING_VERSION` stays `2`,
  `VAULT_FORMAT_VERSION` stays `"1.0"`. `legacyChangeIdentity` is already a
  specified optional field of a version 1 keyset (`docs/FORMAT-1.0.md:330`);
  this plan makes the Rust core honour the field it already has, and adds
  nothing to the format.
- **Byte-identical serialization across cores.** `serialize_key_set` in
  `src-tauri/src/keyring.rs` must keep producing exactly what `serializeKeySet`
  in `src/keyring.ts` produces for the same inputs. TypeScript's order for a
  version 1 keyset is `{version, keys, legacyChangeIdentity?}` — the optional
  field comes **after** `keys` and is **absent**, not `null`, when there is
  none.
- **`test/fixtures/keyring-vector.json` is frozen.** Do not regenerate it and do
  not add fields to it. `scripts/make-keyring-vector.mjs` says so in its own
  header: "add a new file instead when you can." This plan adds a new file.
- **The `audit` key is pinned across a re-key.** `rekeyVault` copies it from the
  old keyset (`src/keyring-rekey.ts:827-830`, `PINNED_KEYS`), so
  `oldKeys.audit` and `newKeys.audit` are the same bytes and one chain spans the
  operation. Never derive an audit key from a passphrase inside `rekeyVault`:
  which passphrase is in force depends on `--keep-passphrase` and on whether the
  commit succeeded.
- **`audit.log` and `audit.meta.json` are `ROOT_PLAINTEXT`**
  (`src/keyring-rekey.ts:79-85`), so they are outside the re-key plan and
  appending to them cannot trip `assertPlanUnchanged`.
- **`withVaultLock` is reentrant** (`src/vault-lock.ts:108-114`), so calling
  `appendKeyringAuditWithKey` from inside `rekeyVault`'s lock is safe and does
  not deadlock.
- **Never log or store a passphrase, a recovery code, or a kit path in an audit
  entry.** An entry carries `actor`, `file`, `key` and `outcome` only; `key` is
  `"<operation>:<uuid>"`.
- **Two tests fail in an OneDrive-backed checkout for environmental reasons.**
  `test/durability.test.mjs` and `test/format-conformance.test.mjs` both call
  `fs.cpSync` on `test/fixtures`, which hard-crashes Node (exit 127, no
  catchable error) under OneDrive. Baseline before this plan is **337/339**. If
  you need a clean 339/339, run the suite from a worktree outside the OneDrive
  tree. Do not "fix" these two.
- All production changes follow failing-test-first development, and each task
  ends with its own commit.

---

## File Structure

**Task 1 — Rust keyset field passthrough**
- Modify `src-tauri/src/keyring.rs`: `KeySet`, `KeySetFile`, `parse_key_set`,
  `serialize_key_set`, `random_key_set`, plus tests.
- Create `scripts/make-keyring-legacy-vector.mjs`: writes the second frozen
  cross-core vector, one that carries `legacyChangeIdentity`.
- Create `test/fixtures/keyring-legacy-vector.json`: that vector.
- Modify `test/keyring.test.mjs`: the TypeScript half of the vector.
- Modify `test/fixtures/README.md`: name the new fixture.

**Task 2 — `rekey` audit events**
- Modify `src/keyring-rekey.ts`: paired events around the mutation window.
- Modify `test/rekey-vault.test.mjs`: the tests for them.

**Task 3 — Documentation and the misleading unlock error**
- Modify `src-tauri/src/keyring.rs`: `unwrap_keyring`'s error for a keyset the
  core cannot parse.
- Modify `docs/FORMAT-1.0.md`, `docs/ROADMAP.md`, `CHANGELOG.md`, `SECURITY.md`.

---

### Task 1: The Rust core carries `legacyChangeIdentity` across a re-wrap

**Why this is first and why it matters:** `legacyChangeIdentity` holds the
`documents` key a completed `vbrain rekey` replaced. It is the only thing that
can recompute the ids of sync changes an older build derived from that key
(`src/sync.ts:1346`, `src/sync.ts:2328`). The TypeScript core threads it through
every re-wrap — `changeVaultPassphrase` (`src/keyring-passphrase.ts:143`) and
`restoreVaultKeyring` (`src/keyring-recovery.ts:289`) both had this exact bug and
both were fixed. The Rust core never learned the field: `KeySetFile`
(`src-tauri/src/keyring.rs:113-117`) does not declare it, serde has no
`deny_unknown_fields`, so it parses fine and is dropped on the floor. Then
`serialize_key_set` writes a keyset without it, and both
`change_passphrase_locked` (`:528`) and `create_recovery_kit_locked` (`:705`)
publish that. **Consequence today: re-key a vault with the CLI, then change its
passphrase from the desktop application, and the only copy of that key is gone —
along with the ability to name any sync change written before the re-key.**

**Files:**
- Modify: `src-tauri/src/keyring.rs:113-117` (`KeySetFile`), `:132-140`
  (`KeySet`), `:273-292` (`parse_key_set`), `:292-307` (`serialize_key_set`),
  `:351-366` (`random_key_set`), tests from `:745`
- Create: `scripts/make-keyring-legacy-vector.mjs`
- Create: `test/fixtures/keyring-legacy-vector.json` (generated by that script)
- Modify: `test/keyring.test.mjs`
- Modify: `test/fixtures/README.md`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `keyring::KeySet` gains a public field
  `legacy_change_identity: Option<Zeroizing<[u8; KEY_LENGTH]>>`. Every existing
  construction site must set it. No function signature changes.

---

- [ ] **Step 1: Write the failing Rust test**

Add to the `mod tests` block in `src-tauri/src/keyring.rs`, after
`changing_the_passphrase_keeps_the_keyset_and_preserves_a_recovery_slot`:

```rust
    /// The field this core does not use but must never destroy. It holds the
    /// `documents` key a completed `vbrain rekey` replaced, and it is the only
    /// thing that can recompute the ids of sync changes an older build derived
    /// from that key. A desktop passphrase change that dropped it would leave
    /// the vault openable and those ids unrecoverable.
    #[test]
    fn a_re_wrap_carries_the_legacy_change_identity_key_across() {
        let dir = std::env::temp_dir().join(format!("vbrain-legacy-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let mut keys = random_key_set();
        let legacy = Zeroizing::new([0x5au8; KEY_LENGTH]);
        keys.legacy_change_identity = Some(legacy.clone());
        write(
            &dir,
            &KeyringFile {
                version: KEYRING_VERSION,
                slots: vec![wrap_key_set(&keys, "the original passphrase", 14).unwrap()],
            },
        )
        .unwrap();

        change_passphrase_locked(&dir, "the original passphrase", "a replacement passphrase")
            .unwrap();

        let after = read(&dir).unwrap().expect("a keyring on disk");
        let opened = unwrap_keyring(&after, "a replacement passphrase").unwrap();
        // Compared as base64 rather than as slices: `Zeroizing<[u8; 32]>` and a
        // bare `&[u8]` do not unify, and a mismatch prints readably this way.
        assert_eq!(
            opened
                .legacy_change_identity
                .as_ref()
                .map(|key| BASE64.encode(key.as_ref())),
            Some(BASE64.encode(legacy.as_ref())),
            "the legacy change identity key must survive a re-wrap"
        );

        fs::remove_dir_all(&dir).ok();
    }

    /// A vault that has never been re-keyed carries no such key, and the field
    /// must be absent from the serialized keyset rather than present as null —
    /// `serializeKeySet` in src/keyring.ts spreads an empty object when there is
    /// none, and the two cores' bytes have to match.
    #[test]
    fn a_keyset_without_a_legacy_key_serializes_without_the_field() {
        let keys = random_key_set();
        assert!(keys.legacy_change_identity.is_none());
        let plaintext = serialize_key_set(&keys).unwrap();
        assert!(
            !plaintext.contains("legacyChangeIdentity"),
            "the field must be omitted, not written as null: {}",
            &*plaintext
        );
    }

    /// The refusal `parseKeySet` in src/keyring.ts makes for the same input. A
    /// reader that ignored a `retiring` block on a version 1 keyset would report
    /// success and then fail to open every object an interrupted re-key had not
    /// reached.
    #[test]
    fn a_version_one_keyset_carrying_retiring_keys_is_refused() {
        let keys = random_key_set();
        let plaintext = serialize_key_set(&keys).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&plaintext).unwrap();
        value["retiring"] = serde_json::json!({
            "documents": BASE64.encode([0x07u8; KEY_LENGTH]),
            "kv": BASE64.encode([0x08u8; KEY_LENGTH]),
            "syncEnvelope": BASE64.encode([0x09u8; KEY_LENGTH]),
        });
        let tampered = serde_json::to_vec(&value).unwrap();

        let error = parse_key_set(&tampered).unwrap_err();
        assert!(
            error.contains("retiring"),
            "the refusal must name what it refused: {error}"
        );
    }
```

- [ ] **Step 2: Run the Rust tests to verify they fail**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml --lib keyring
```

Expected: compile error — `KeySet` has no field `legacy_change_identity`, and
`parse_key_set` is not in scope under that name from the test module (it is; the
error you should see is the missing field). All three new tests must fail to
build or fail at runtime before Step 3.

- [ ] **Step 3: Add the field to `KeySet`**

In `src-tauri/src/keyring.rs`, replace the `KeySet` struct (currently at
`:132-140`):

```rust
#[derive(Debug, Clone)]
pub(crate) struct KeySet {
    pub(crate) documents: Zeroizing<[u8; KEY_LENGTH]>,
    pub(crate) kv: Zeroizing<[u8; KEY_LENGTH]>,
    pub(crate) attachment_id: Zeroizing<[u8; KEY_LENGTH]>,
    pub(crate) sync_change: Zeroizing<[u8; KEY_LENGTH]>,
    pub(crate) sync_envelope: Zeroizing<[u8; KEY_LENGTH]>,
    pub(crate) audit: Zeroizing<[u8; KEY_LENGTH]>,
    /// The `documents` key a completed re-key replaced. This core never uses
    /// it — recomputing the ids of sync changes an older build derived from
    /// that key is `src/sync.ts`'s job — but it must survive every re-wrap
    /// performed here, because `keyring.json` holds the only copy. It is
    /// absent on a vault that has never been re-keyed.
    pub(crate) legacy_change_identity: Option<Zeroizing<[u8; KEY_LENGTH]>>,
}
```

- [ ] **Step 4: Teach `KeySetFile` the field, and the `retiring` refusal**

Replace `KeySetFile` (currently at `:113-117`) with:

```rust
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeySetFile {
    version: u8,
    keys: KeySetKeys,
    /// Deserialize-only, and never written back. A version 1 keyset must not
    /// carry retiring keys; refusing here is what `parseKeySet` in
    /// `src/keyring.ts` does for the same input, and for the same reason.
    #[serde(default, skip_serializing)]
    retiring: Option<serde_json::Value>,
    /// Optional at version 1, and serialized after `keys` — the field order
    /// `serializeKeySet` in `src/keyring.ts` produces. Omitted entirely when
    /// there is none, because that is what a spread of an empty object does on
    /// the TypeScript side and the two must agree byte for byte.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    legacy_change_identity: Option<String>,
}

/// The base64 here is a directly reversible copy of a real vault key, for the
/// same reason `KeySetKeys` scrubs itself: serde has to own the `String`, and
/// `String`'s ordinary drop leaves it in freed heap memory.
impl Drop for KeySetFile {
    fn drop(&mut self) {
        if let Some(value) = self.legacy_change_identity.as_mut() {
            value.zeroize();
        }
    }
}
```

- [ ] **Step 5: Parse and re-serialize the field**

Replace `parse_key_set` (currently at `:273-292`):

```rust
fn parse_key_set(plaintext: &[u8]) -> Result<KeySet, String> {
    let parsed: KeySetFile =
        serde_json::from_slice(plaintext).map_err(|_| "unreadable vault keyset".to_string())?;
    if parsed.version != KEYSET_VERSION {
        return Err(format!(
            "Unsupported vault keyset version: {}",
            parsed.version
        ));
    }
    if parsed.retiring.is_some() {
        return Err("A version 1 vault keyset must not carry retiring keys.".into());
    }
    let legacy_change_identity = match parsed.legacy_change_identity.as_deref() {
        Some(value) => Some(key_bytes(value, "legacy change identity key")?),
        None => None,
    };
    Ok(KeySet {
        documents: key_bytes(&parsed.keys.documents, "documents key")?,
        kv: key_bytes(&parsed.keys.kv, "kv key")?,
        attachment_id: key_bytes(&parsed.keys.attachment_id, "attachmentId key")?,
        sync_change: key_bytes(&parsed.keys.sync_change, "syncChange key")?,
        sync_envelope: key_bytes(&parsed.keys.sync_envelope, "syncEnvelope key")?,
        audit: key_bytes(&parsed.keys.audit, "audit key")?,
        legacy_change_identity,
    })
}
```

Then, in `serialize_key_set` (currently at `:292-307`), replace the `let file = …`
binding — keep the `Ok(Zeroizing::new(serde_json::to_string(&file)…))` tail
exactly as it is:

```rust
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
        retiring: None,
        legacy_change_identity: keys
            .legacy_change_identity
            .as_ref()
            .map(|key| BASE64.encode(key.as_ref())),
    };
```

- [ ] **Step 6: Set the new field at the one other construction site**

In `random_key_set` (currently at `:351-366`), add the field to the returned
struct literal — a created vault has never been re-keyed:

```rust
    KeySet {
        documents: new_key(),
        kv: new_key(),
        attachment_id: new_key(),
        sync_change: new_key(),
        sync_envelope: new_key(),
        audit: new_key(),
        legacy_change_identity: None,
    }
```

- [ ] **Step 7: Run the Rust tests to verify they pass**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml --lib keyring
```

Expected: PASS, including the three new tests and every existing keyring test —
`the_serialized_keyset_matches_what_the_typescript_core_parses` in particular,
which proves the existing frozen vector's bytes did not move.

- [ ] **Step 8: Commit the Rust half**

```bash
git add src-tauri/src/keyring.rs
git commit -m "fix(desktop): stop destroying the legacy change identity key on a re-wrap"
```

- [ ] **Step 9: Write the generator for the second cross-core vector**

Create `scripts/make-keyring-legacy-vector.mjs`. Deliberately different slot id,
salt and iv from `keyring-vector.json`, so the two can never be confused for one
another:

```js
/**
 * Writes the second deterministic cross-core keyring vector: a version 1
 * keyset that carries `legacyChangeIdentity`. Run once, deliberately:
 *
 *   npm run build && node scripts/make-keyring-legacy-vector.mjs
 *
 * The first vector (scripts/make-keyring-vector.mjs) pins the keyset a vault
 * that has never been re-keyed carries. This one pins the only other shape the
 * format allows at version 1, and exists because the Rust core used to parse it
 * successfully and then silently drop the field on the next re-wrap.
 *
 * The output is a frozen fixture: regenerating it destroys the evidence that
 * both cores agree on the bytes.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PASSPHRASE = "legacy-vector-only-passphrase";
const SALT = Buffer.alloc(16, 0x33);
const IV = Buffer.alloc(12, 0x44);
const KDF = { name: "scrypt", N: 2 ** 14, r: 8, p: 1, salt: SALT.toString("base64") };
const HEADER = {
  id: "00000000-0000-4000-8000-000000000003",
  type: "passphrase",
  label: "primary",
  kdf: KDF,
  createdAt: "2026-09-05T00:00:00.000Z",
};
const KEY_BYTES = {
  documents: 0x01,
  kv: 0x02,
  attachmentId: 0x03,
  syncChange: 0x04,
  syncEnvelope: 0x05,
  audit: 0x06,
};
const LEGACY_BYTE = 0x5a;

const keys = {};
for (const [name, byte] of Object.entries(KEY_BYTES)) keys[name] = Buffer.alloc(32, byte);
const legacyChangeIdentity = Buffer.alloc(32, LEGACY_BYTE);

// Mirrors slotAad in src/keyring.ts, exactly as the first vector's script does.
const aad = JSON.stringify({
  context: "secondbrain-vault:keyring-slot:v1",
  version: 2,
  id: HEADER.id,
  type: HEADER.type,
  kdf: { name: KDF.name, N: KDF.N, r: KDF.r, p: KDF.p, salt: KDF.salt },
});

// The field order src/keyring.ts produces: version, keys, then the optional
// legacyChangeIdentity spread in last.
const keysetPlaintext = JSON.stringify({
  version: 1,
  keys: Object.fromEntries(Object.keys(KEY_BYTES).map((name) => [name, keys[name].toString("base64")])),
  legacyChangeIdentity: legacyChangeIdentity.toString("base64"),
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
  note: "Deterministic cross-core keyring vector for a version 1 keyset carrying legacyChangeIdentity. Both cores must unwrap this slot to these keys, recover this legacy key, and serialize the result to keysetPlaintext byte-for-byte. Dummy key material; never a real vault.",
  passphrase: PASSPHRASE,
  aad,
  keysetPlaintext,
  keys: Object.fromEntries(Object.keys(KEY_BYTES).map((name) => [name, keys[name].toString("base64")])),
  legacyChangeIdentity: legacyChangeIdentity.toString("base64"),
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
  "keyring-legacy-vector.json",
);
if (fs.existsSync(target) && !process.argv.includes("--force")) {
  console.error(`Refusing to overwrite ${target}. Pass --force only for a deliberate format bump.`);
  process.exit(1);
}
fs.writeFileSync(target, `${JSON.stringify(vector, null, 2)}\n`);
console.log(`Legacy-carrying cross-core keyring vector written to ${target}`);
```

- [ ] **Step 10: Generate the fixture**

Run:

```bash
npm run build && node scripts/make-keyring-legacy-vector.mjs
```

Expected: `Legacy-carrying cross-core keyring vector written to …/test/fixtures/keyring-legacy-vector.json`

- [ ] **Step 11: Write the failing TypeScript vector test**

Add to `test/keyring.test.mjs`, beside the existing `VECTOR` constant near
`:34`:

```js
const LEGACY_VECTOR = JSON.parse(
  fs.readFileSync(path.resolve(FIXTURES, "keyring-legacy-vector.json"), "utf8"),
);
```

and add these two tests after the existing
`"the cross-core vector records the keyset plaintext in key order"` test:

```js
test("the legacy cross-core vector unwraps to its recorded keys and legacy key", () => {
  const opened = unwrapSlotKeySet(LEGACY_VECTOR.slot, LEGACY_VECTOR.passphrase);
  try {
    for (const name of KEY_NAMES) {
      assert.deepEqual(opened.keys[name], Buffer.from(LEGACY_VECTOR.keys[name], "base64"), name);
    }
    assert.equal(opened.retiring, null, "a version 1 keyset carries no retiring keys");
    assert.deepEqual(
      opened.legacyChangeIdentity,
      Buffer.from(LEGACY_VECTOR.legacyChangeIdentity, "base64"),
    );
  } finally {
    zeroKeySet(opened.keys);
    opened.legacyChangeIdentity?.fill(0);
  }
});

test("the legacy cross-core vector records the plaintext the real serializer writes", () => {
  // Drive the production write path rather than re-parsing the recorded string:
  // wrap the vector's own keys with `wrapKeySet`, then peel the slot open by
  // hand (mirroring scripts/make-keyring-legacy-vector.mjs) to recover what was
  // actually encrypted. This fails if `serializeKeySet` moves the optional
  // field, renames it, or emits it as null when it is absent.
  const keys = {};
  for (const name of KEY_NAMES) keys[name] = Buffer.from(LEGACY_VECTOR.keys[name], "base64");
  const legacy = Buffer.from(LEGACY_VECTOR.legacyChangeIdentity, "base64");

  const slot = wrapKeySet(keys, PASSPHRASE, undefined, null, legacy);

  const kek = crypto.scryptSync(PASSPHRASE, Buffer.from(slot.kdf.salt, "base64"), 32, {
    N: slot.kdf.N,
    r: slot.kdf.r,
    p: slot.kdf.p,
    maxmem: 256 * 1024 * 1024,
  });
  const aad = JSON.stringify({
    context: "secondbrain-vault:keyring-slot:v1",
    version: 2,
    id: slot.id,
    type: slot.type,
    kdf: { name: slot.kdf.name, N: slot.kdf.N, r: slot.kdf.r, p: slot.kdf.p, salt: slot.kdf.salt },
  });
  const decipher = crypto.createDecipheriv("aes-256-gcm", kek, Buffer.from(slot.wrapped.iv, "base64"));
  decipher.setAAD(Buffer.from(aad, "utf8"));
  decipher.setAuthTag(Buffer.from(slot.wrapped.authTag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(slot.wrapped.ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");

  assert.equal(plaintext, LEGACY_VECTOR.keysetPlaintext);
});
```

If `unwrapSlotKeySet` or `zeroKeySet` is not already imported in
`test/keyring.test.mjs`, add them to the existing `from "../dist/keyring.js"`
import list.

- [ ] **Step 12: Run the TypeScript vector tests**

Run:

```bash
npm run build && node --test test/keyring.test.mjs
```

Expected: PASS. If `"the legacy cross-core vector records the plaintext the real
serializer writes"` fails on the plaintext comparison, the generator's field
order and `serializeKeySet`'s disagree — fix the generator, not the serializer,
and regenerate with `--force`.

- [ ] **Step 13: Read the new vector from the Rust side**

Add to the `mod tests` block in `src-tauri/src/keyring.rs`, after the existing
`the_serialized_keyset_matches_what_the_typescript_core_parses`:

```rust
    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct LegacyVector {
        passphrase: String,
        keyset_plaintext: String,
        keys: std::collections::HashMap<String, String>,
        legacy_change_identity: String,
        slot: KeyringSlot,
    }

    fn legacy_vector() -> LegacyVector {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .join("test")
            .join("fixtures")
            .join("keyring-legacy-vector.json");
        serde_json::from_slice(&fs::read(path).expect("read the legacy keyring vector"))
            .expect("parse the legacy keyring vector")
    }

    /// The round trip that was broken: unwrap a keyset carrying
    /// `legacyChangeIdentity`, re-serialize it, and get the same bytes back.
    #[test]
    fn the_legacy_vector_round_trips_through_this_core_byte_for_byte() {
        let vector = legacy_vector();
        let keys = unwrap_slot(&vector.slot, &vector.passphrase).unwrap();
        for (name, expected) in [
            ("documents", &keys.documents),
            ("kv", &keys.kv),
            ("attachmentId", &keys.attachment_id),
            ("syncChange", &keys.sync_change),
            ("syncEnvelope", &keys.sync_envelope),
            ("audit", &keys.audit),
        ] {
            assert_eq!(BASE64.encode(expected.as_ref()), vector.keys[name], "key {name}");
        }
        assert_eq!(
            BASE64.encode(
                keys.legacy_change_identity
                    .as_ref()
                    .expect("the legacy change identity key")
                    .as_ref()
            ),
            vector.legacy_change_identity
        );
        assert_eq!(*serialize_key_set(&keys).unwrap(), vector.keyset_plaintext);
    }
```

- [ ] **Step 14: Run the Rust tests to verify they pass**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml --lib keyring
```

Expected: PASS, all keyring tests including the new legacy vector round trip.

- [ ] **Step 15: Name the fixture in the fixtures README**

Append to `test/fixtures/README.md`, beside the existing `keyring-vector.json`
paragraph:

```markdown
`keyring-legacy-vector.json` is written by
`scripts/make-keyring-legacy-vector.mjs` and pins the other shape a version 1
keyset can take: one carrying `legacyChangeIdentity`, the `documents` key a
completed re-key replaced. Both cores must unwrap it to the same keys and
re-serialize it to the same bytes. The Rust core used to parse this shape
successfully and then drop the field on the next re-wrap, which is what the
vector exists to prevent recurring.
```

- [ ] **Step 16: Commit**

```bash
git add scripts/make-keyring-legacy-vector.mjs test/fixtures/keyring-legacy-vector.json test/fixtures/README.md test/keyring.test.mjs src-tauri/src/keyring.rs
git commit -m "test: pin the legacy-carrying keyset with a second cross-core vector"
```

---

### Task 2: `vbrain rekey` writes to the audit chain

**Why:** `KeyringAuditOperation` in `src/keyring-audit.ts:4-10` already lists
`"rekey"`, and nothing emits it — `src/keyring-rekey.ts` does not import
`./keyring-audit.js` at all. `migrate`, `passphrase change` and all three
recovery mutations write paired `pending` → `allowed`/`denied` events; the one
command that replaces every key in the vault writes nothing, so "when were this
vault's keys last replaced" has no answer. Phase 7.5's own plan (Task 4) asked
for this and it did not land.

**Files:**
- Modify: `src/keyring-rekey.ts` — imports, and three points inside `rekeyVault`
- Test: `test/rekey-vault.test.mjs`

**Interfaces:**
- Consumes: `appendKeyringAuditWithKey(vaultDir: string, auditKey: Buffer, key:
  string, outcome: "pending" | "allowed" | "denied"): void` and
  `newKeyringAuditKey(operation: KeyringAuditOperation): string` from
  `src/keyring-audit.ts`. Both already exist and are unchanged by this plan.
- Produces: nothing new is exported. `RekeyReport` does not change.

**Design decisions, so the implementer does not have to re-derive them:**

1. **Use the key, not the passphrase.** `appendKeyringAudit` (the passphrase
   form) is wrong here: which passphrase opens the vault depends on
   `--keep-passphrase` and on whether the commit landed. Use
   `appendKeyringAuditWithKey` with `oldKeys.audit`, which `PINNED_KEYS`
   guarantees is byte-identical to `newKeys.audit`. One chain spans the whole
   operation and verifies from both sides.
2. **`pending` goes after every non-mutating refusal.** Place it immediately
   after the `prepareRecoveryForRekey` block resolves — that is the last point at
   which the function can still refuse with nothing on disk touched, and it is
   before `randomKeySet()`. A refusal for a wrong passphrase, a missing recovery
   kit, or a non-keyring vault writes nothing, exactly as
   `changeVaultPassphrase` behaves.
3. **`allowed` goes after the read-back verification, before `return`.** The
   settle write is best-effort and past the point of no return; a re-key with
   `settled: false` still succeeded and must be recorded as `allowed`.
4. **`denied` goes in the existing outer `catch`, before the rethrow, guarded so
   it fires at most once.** It has `oldKeys` in scope there.
5. **`resumeRekey` and the `recoverRekey(...) === "finished"` early return write
   nothing.** Neither has a passphrase or a key: a resume is deliberately
   passphrase-free (`src/cli.ts:2091` and the doc comment at
   `src/keyring-rekey.ts:1007`). Document this in the code rather than inventing
   a key to write with.

---

- [ ] **Step 1: Write the failing tests**

Add to `test/rekey-vault.test.mjs`. `readAudit` needs adding to the existing
`from "../dist/audit.js"` import (which currently brings in `appendAudit` and
`verifyAudit`):

```js
test("a re-key appends a paired, secret-free audit event and the chain still verifies", () => {
  const { dir } = seedVault();
  const next = "phase-77-rekeyed-passphrase";

  const before = readAudit(dir).filter((entry) => entry.actor === "cli-keyring");
  assert.equal(before.length, 0, "the seeded vault has no keyring events yet");

  const report = rekeyVault(dir, PASSPHRASE, next);
  assert.equal(report.passphraseChanged, true);

  const events = readAudit(dir).filter((entry) => entry.actor === "cli-keyring");
  assert.deepEqual(
    events.map(({ outcome }) => outcome),
    ["pending", "allowed"],
  );
  assert.equal(events[0].key, events[1].key, "a pair shares one operation key");
  assert.match(events[0].key, /^rekey:[0-9a-f-]{36}$/u);
  assert.equal(events[0].file, "keyring");

  // No secret and no path may reach the chain.
  const serialized = JSON.stringify(events);
  assert.equal(serialized.includes(PASSPHRASE), false);
  assert.equal(serialized.includes(next), false);
  assert.equal(serialized.includes(dir), false);

  // The audit key is pinned, so the entry written before the commit and the
  // entry written after it verify in one chain under the new passphrase.
  assert.equal(verifyAudit(dir, next).valid, true);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("a re-key that fails before it commits records a denied event and nothing else", () => {
  const { dir } = seedVault();

  // A recovery slot with no kit supplied: the refusal `prepareRecoveryForRekey`
  // raises, which lands after `pending` is written and before anything on disk
  // is touched.
  const kit = path.join(tempDir("kit"), "kit.json");
  createRecoveryKit(dir, PASSPHRASE, kit);

  assert.throws(
    () => rekeyVault(dir, PASSPHRASE, "phase-77-rekeyed-passphrase"),
    /recovery kit and code/iu,
  );

  const events = readAudit(dir).filter((entry) => entry.actor === "cli-keyring");
  // createRecoveryKit wrote its own pair; the refused re-key adds exactly one more.
  const rekeyEvents = events.filter((entry) => entry.key.startsWith("rekey:"));
  assert.deepEqual(
    rekeyEvents.map(({ outcome }) => outcome),
    ["pending", "denied"],
  );
  assert.equal(rekeyEvents[0].key, rekeyEvents[1].key);
  assert.equal(verifyAudit(dir, PASSPHRASE).valid, true);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("a re-key refused before it can open the vault writes nothing to the chain", () => {
  const { dir } = seedVault();

  assert.throws(() => rekeyVault(dir, "the wrong passphrase", "phase-77-rekeyed-passphrase"));

  const events = readAudit(dir).filter((entry) => entry.actor === "cli-keyring");
  assert.deepEqual(events, [], "a wrong passphrase must not be able to append to the chain");

  fs.rmSync(dir, { recursive: true, force: true });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```bash
npm run build && node --test test/rekey-vault.test.mjs
```

Expected: the first two tests FAIL — the first with
`AssertionError: [] deepStrictEqual [ 'pending', 'allowed' ]`, the second
similarly. The third test PASSES already (nothing is written today); it is the
regression guard for Step 3's placement, so keep it.

- [ ] **Step 3: Import the audit helpers**

In `src/keyring-rekey.ts`, add beside the existing imports:

```ts
import { appendKeyringAuditWithKey, newKeyringAuditKey } from "./keyring-audit.js";
```

- [ ] **Step 4: Declare the operation key beside the other per-run state**

In `rekeyVault`, immediately after the existing `let recoveryKitRewritten = false;`
declaration (currently `src/keyring-rekey.ts:790`), add:

```ts
      // Set once the operation has been announced to the chain, so the catch
      // below can close the pair exactly once and a refusal that happened
      // before the announcement stays silent.
      let auditOperation: string | undefined;
      let auditCompleted = false;
```

- [ ] **Step 5: Write the `pending` entry**

In `rekeyVault`, immediately after the `if (preparedRecovery) { … droppedSlots.splice … }`
block and **before** `newKeys = randomKeySet();` (currently
`src/keyring-rekey.ts:826-827`), insert:

```ts
        // The last point at which this function can still refuse with nothing
        // on disk touched — a wrong passphrase, a legacy vault, or a recovery
        // slot with no matching kit have all already thrown above, and they
        // write nothing. `oldKeys.audit` rather than a passphrase-derived key:
        // `audit` is pinned across a re-key, so this entry and the `allowed`
        // that closes it after the commit verify in one chain no matter which
        // passphrase ends up in force. `audit.log` is ROOT_PLAINTEXT, so it is
        // outside the plan `assertPlanUnchanged` compares.
        auditOperation = newKeyringAuditKey("rekey");
        appendKeyringAuditWithKey(vaultDir, oldKeys.audit, auditOperation, "pending");
```

- [ ] **Step 6: Write the `allowed` entry**

In `rekeyVault`, immediately after the read-back verification line
`zeroKeySet(unwrapKeyring(written, wrapPassphrase));` and **before** the
`return { rotated: … }` statement (currently `src/keyring-rekey.ts:936-938`),
insert:

```ts
        // After the read-back proves the vault on disk opens, and deliberately
        // regardless of `settled`: settling is best-effort cleanup past the
        // point of no return, so a re-key that could not settle still replaced
        // every key and is not a denial.
        appendKeyringAuditWithKey(vaultDir, oldKeys.audit, auditOperation, "allowed");
        auditCompleted = true;
```

`auditOperation` is `string | undefined` at its declaration, but it is assigned
unconditionally in Step 5 on the only path that reaches here, so TypeScript's
control-flow analysis narrows it to `string`. If your editor disagrees, the
assignment in Step 5 was placed inside a branch — move it back out rather than
reaching for `!`.

- [ ] **Step 7: Write the `denied` entry**

In `rekeyVault`'s outer `catch (error) {` block, insert as its **first**
statements, before the existing `const precommit = …` line (currently
`src/keyring-rekey.ts:958`):

```ts
        // Close the pair with the same operation key, so the chain never shows
        // a `pending` with no terminal outcome. `oldKeys` is in scope here
        // whenever `auditOperation` is set, because the announcement above
        // happens strictly after `oldKeys` is established.
        if (auditOperation && oldKeys && !auditCompleted) {
          auditCompleted = true;
          appendKeyringAuditWithKey(vaultDir, oldKeys.audit, auditOperation, "denied");
        }
```

- [ ] **Step 8: Say in the code why a resume writes nothing**

In `rekeyVault`, extend the comment on the early return for a recovered run
(currently `src/keyring-rekey.ts:772-779`) — replace the existing comment block
above `if (recoverRekey(vaultDir) === "finished") {` with:

```ts
      // An interrupted earlier run is finished or discarded before anything
      // else looks at the vault, so the rest of this function only ever sees a
      // consistent one.
      //
      // Recovery appends nothing to the audit chain, and cannot: it runs
      // without a passphrase by design, so no audit key is available to sign an
      // entry with. The interrupted run that created the journal already
      // announced itself as `pending`, and its outcome is the journal on disk
      // rather than a chain entry.
```

Add the same note to `resumeRekey`'s doc comment (currently
`src/keyring-rekey.ts:997-1006`), appended as a final paragraph:

```ts
 * Appends nothing to the audit chain, for the same reason it asks for no
 * passphrase: there is no audit key to sign an entry with. The run that left
 * the journal behind is the one the chain records.
```

- [ ] **Step 9: Run the tests to verify they pass**

Run:

```bash
npm run build && node --test test/rekey-vault.test.mjs test/keyring-recovery.test.mjs
```

Expected: PASS, all three new tests plus the existing recovery suite — including
`"key material changes append paired, secret-free audit events"`, whose expected
outcome sequence must be unchanged by this task.

- [ ] **Step 10: Run lint and typecheck**

```bash
npm run lint && npm run typecheck
```

Expected: clean.

- [ ] **Step 11: Commit**

```bash
git add src/keyring-rekey.ts test/rekey-vault.test.mjs
git commit -m "feat(rekey): record every key replacement in the audit chain"
```

---

### Task 3: Say what the code actually does

Three documents name behaviour that does not exist, and one Rust error string
misdescribes the failure it reports.

**Files:**
- Modify: `src-tauri/src/keyring.rs` (`unwrap_keyring`, currently `:337-348`)
- Modify: `docs/FORMAT-1.0.md:92-94`
- Modify: `docs/ROADMAP.md` (Phase 7 section)
- Modify: `SECURITY.md` (Keyring and recovery limits)
- Modify: `CHANGELOG.md` (Unreleased)

**Interfaces:**
- Consumes: Task 1's `parse_key_set`, which now returns a distinguishable error
  for a keyset this core cannot read; Task 2's `rekey` audit event, which the
  changelog and roadmap describe.
- Produces: nothing code depends on.

---

- [ ] **Step 1: Write the failing Rust test for the unlock error**

`unwrap_keyring` swallows every per-slot failure and reports one message:
"Unable to unlock this vault: wrong passphrase, or the keyring is damaged." A
vault caught mid-re-key carries a version 2 keyset, which `parse_key_set`
correctly refuses — and the user is then told their passphrase is wrong. Add to
`mod tests` in `src-tauri/src/keyring.rs`:

```rust
    /// A mid-re-key vault is refused on purpose (docs/FORMAT-1.0.md §2), but
    /// telling its owner their passphrase is wrong sends them looking for the
    /// one problem they do not have. The correct passphrase opening a slot this
    /// core cannot parse is a different failure and has to say so.
    #[test]
    fn a_keyset_this_core_cannot_read_is_not_reported_as_a_wrong_passphrase() {
        let vector = vector();
        // Re-wrap the vector's own keyset as a version this core does not know,
        // under a passphrase that is unquestionably correct.
        let keys = unwrap_slot(&vector.slot, &vector.passphrase).unwrap();
        let mut slot = wrap_key_set(&keys, "a definitely correct passphrase", 14).unwrap();
        // Rebuild the wrapped payload around a bumped version. The AAD is
        // unchanged, so this authenticates and fails only in `parse_key_set`.
        let plaintext = serialize_key_set(&keys).unwrap().replace(
            "{\"version\":1,",
            "{\"version\":2,",
        );
        let derived = derive_slot_key("a definitely correct passphrase", &slot.kdf).unwrap();
        let aad = slot_aad(&slot).unwrap();
        let iv = decode_base64(&slot.wrapped.iv, 12, 12, "iv").unwrap();
        let mut buffer = Zeroizing::new(plaintext.as_bytes().to_vec());
        let cipher = Aes256Gcm::new_from_slice(derived.as_ref()).unwrap();
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&iv), &aad, &mut buffer)
            .unwrap();
        slot.wrapped.auth_tag = BASE64.encode(tag);
        slot.wrapped.ciphertext = BASE64.encode(&*buffer);

        let error = unwrap_keyring(
            &KeyringFile {
                version: KEYRING_VERSION,
                slots: vec![slot],
            },
            "a definitely correct passphrase",
        )
        .unwrap_err();

        assert!(
            !error.contains("wrong passphrase"),
            "a keyset version failure must not be reported as a wrong passphrase: {error}"
        );
        assert!(
            error.contains("vbrain rekey"),
            "the message must name the command that finishes an interrupted re-key: {error}"
        );
    }
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cargo test --manifest-path src-tauri/Cargo.toml --lib a_keyset_this_core_cannot_read
```

Expected: FAIL — the error is "Unable to unlock this vault: wrong passphrase, or
the keyring is damaged."

- [ ] **Step 3: Distinguish the two failures in `unwrap_keyring`**

Replace `unwrap_keyring` (currently `src-tauri/src/keyring.rs:337-348`):

```rust
/// Every slot wraps the same keyset, so the first one that opens wins.
///
/// A slot that authenticates but whose keyset this core cannot parse is a
/// different failure from a slot that did not authenticate, and is reported
/// separately: the passphrase was right. The case that reaches this in practice
/// is a vault caught mid-re-key, whose keyset is at version 2 until the run
/// finishes — refused on purpose (see `docs/FORMAT-1.0.md` §2), but not because
/// anything is wrong with the passphrase or the file.
pub(crate) fn unwrap_keyring(file: &KeyringFile, passphrase: &str) -> Result<KeySet, String> {
    if passphrase.is_empty() {
        return Err("passphrase cannot be empty".into());
    }
    let mut unreadable: Option<String> = None;
    for slot in &file.slots {
        match unwrap_slot(slot, passphrase) {
            Ok(keys) => return Ok(keys),
            Err(error) if error.starts_with("Unsupported vault keyset version") => {
                unreadable.get_or_insert(error);
            }
            Err(_) => {}
        }
    }
    if let Some(error) = unreadable {
        return Err(format!(
            "{error}. This passphrase is correct, but the vault's keys are mid-replacement: \
             run 'vbrain rekey' against it from the command line to finish or roll back the \
             interrupted run, then open it here again."
        ));
    }
    Err("Unable to unlock this vault: wrong passphrase, or the keyring is damaged.".into())
}
```

- [ ] **Step 4: Run the Rust tests to verify they pass**

```bash
cargo test --manifest-path src-tauri/Cargo.toml --lib keyring
```

Expected: PASS, all keyring tests.

- [ ] **Step 5: Fix `docs/FORMAT-1.0.md`**

There is no `--resume` flag. `vbrain rekey` detects a journal and settles it
itself (`src/cli.ts:2091-2110`); that is the entire recovery interface. Replace
the sentence at `docs/FORMAT-1.0.md:93-94`:

```markdown
mid-re-key must not be opened by a reader that would report success and then
fail to decrypt every object the interrupted run had not reached. Running
`vbrain rekey` against such a vault again is the migration path out of it: it
finds the journal, finishes or rolls back the interrupted run, and reports which
of the two it did without rotating anything or asking for a passphrase.
```

- [ ] **Step 6: Add Phase 7.7 to the roadmap**

In `docs/ROADMAP.md`, remove the third bullet from the 7.6 list — the one
reading "An audit entry for `rekey`. `migrate` and `passphrase change` now
append to the chain; …" — and insert a new phase immediately after the 7.6 list,
before `## Phase 8`:

```markdown
- [ ] 7.7 What 7.4 and 7.5 left behind
  - [ ] The Rust core carries `legacyChangeIdentity` across a re-wrap. The
        field is a specified part of a version 1 keyset and holds the
        `documents` key a completed re-key replaced — the only thing that can
        recompute the ids of sync changes an older build derived from that key.
        The desktop core parses it, ignores it, and writes it back out missing,
        so re-keying with the CLI and then changing the passphrase from the
        application destroys the only copy. A second frozen cross-core vector
        pins the shape, the way `keyring-vector.json` pins the other one.
  - [ ] An audit entry for `rekey`. `migrate`, `passphrase change` and all three
        recovery mutations append paired events to the chain; the command that
        replaces every key appends nothing, so "when were this vault's keys last
        replaced" has no answer. The `audit` key is pinned across a re-key, so
        the entry written before the commit and the one written after it verify
        in the same chain.
  - [ ] Two documents corrected to what the code does: `docs/FORMAT-1.0.md`
        names a `vbrain rekey --resume` flag that does not exist, and the
        application reports a vault caught mid-re-key as a wrong passphrase.
  - [ ] `documents/retention.enc` is classified by the re-key walk. Phase 10
        added the artifact and did not teach `classifyDocument` about it, so
        `vbrain rekey` refuses outright on any vault carrying a retention
        policy — it fails closed on an artifact it cannot classify, which is
        the guard working, but the command that answers a leaked passphrase
        does not run. Nothing tests the seam from either side. The wider rule
        this broke should be stated somewhere a phase author will read it: an
        encrypted artifact is not shipped until the re-key walk classifies it.
  - [ ] `verifyRecoveryKeySet` takes the re-key's object inventory and its
        retiring fallback. `src/keyring-recovery-verify.ts` says in its own
        comment that Phase 7.4's inventory "can extend this same boundary with
        its full current/retiring scan when that branch is merged"; 7.4 merged
        and the extension never happened. It still walks a hand-written list and
        tries only the keys in force, so a restore against a vault caught
        mid-re-key fails verification — precisely the moment recovery exists
        for. It is also the second implementation of the walk `planRekey`
        already owns, which is what Phase 13 is about.
  - [ ] A decision on the personal-memory work merged from `phase-7-6`.
        `src/memory/` is 278 lines of stub — an in-memory `Map` for a queue the
        commit message calls durable, no `src-tauri/src/memory/`, no `vbrain
        memory` command, no MCP tools, no desktop panel — against a plan
        (`docs/superpowers/plans/2026-09-05-phase-7-6-personal-memory.md`) that
        appears under no phase here. `tsconfig.json` compiles `src/**/*.ts` and
        `package.json` ships `dist/**`, so it is published to npm and its three
        test files run in `npm test`, while nothing in the product reaches it.
        Either it becomes a phase or the stubs come back out; leaving it
        unowned is the one option that is not a decision.
  - [ ] The accepted limits of the re-key move somewhere a reader will find
        them. Four findings were reviewed during 7.4 and deliberately accepted —
        a hostile journal whose `slotId` is rewritten mid-install steers
        recovery down the roll-back branch, `resolveInside` is lexical so a
        symlink at a staged path passes the completeness check,
        `allowSamePassphrase` and `--keep-passphrase` report the identical
        on-disk outcome differently, and two slots opening under one passphrase
        with different keysets are not refused. All need vault write access and
        all fail closed, which is why they were accepted. But they live only in
        `.superpowers/sdd/final-findings.md`, a branch's working notes; a
        permanent known limit belongs in `SECURITY.md`.
```

- [ ] **Step 7: Record the re-key event in `SECURITY.md`**

In the "Keyring and recovery limits" section of `SECURITY.md`, after the bullet
beginning "A re-key keeps exactly one keyring slot", add:

```markdown
- A re-key appends a paired record to the authenticated audit chain: one entry
  when the operation is announced and one when it is allowed or denied, sharing
  one operation id. Neither carries a passphrase, a recovery code, a kit path or
  a vault path. The `audit` key is not rotated, so entries written before and
  after a re-key verify in one chain. An interrupted run that is later settled by
  a plain `vbrain rekey` adds nothing further: settling runs without a
  passphrase and so has no key to sign an entry with.
```

- [ ] **Step 8: Write the changelog entries**

Add to the `## Unreleased` section of `CHANGELOG.md`:

```markdown
- The desktop core no longer destroys a re-keyed vault's `legacyChangeIdentity`
  key. That key holds the `documents` key a completed `vbrain rekey` replaced,
  and it is the only thing that can recompute the ids of sync changes an older
  build derived from that key. The Rust core parsed the field, ignored it, and
  wrote the keyset back out without it — so re-keying from the command line and
  then changing the passphrase or creating a recovery kit from the application
  silently threw it away. A second committed cross-core vector,
  `keyring-legacy-vector.json`, pins the shape so the two cores cannot drift
  again. A version 1 keyset carrying `retiring` keys is now refused in the Rust
  core as well, matching the TypeScript reader.
- `vbrain rekey` now appends to the passphrase-authenticated audit chain, the
  way `migrate`, `passphrase change` and the recovery commands already did. It
  writes a paired record — announced, then allowed or denied — carrying no
  passphrase, recovery code or path. The `audit` key is pinned across a re-key,
  so both halves verify in one chain regardless of which passphrase ends up in
  force. Settling an interrupted run adds nothing: it deliberately runs without
  a passphrase and has no key to sign with.
- A vault caught mid-re-key is no longer reported by the desktop application as
  a wrong passphrase. It was already refused on purpose — its keyset is at
  version 2 until the run finishes — but the message sent its owner looking for
  a problem they did not have. It now says the passphrase is correct and names
  the command that finishes or rolls back the interrupted run.
- `docs/FORMAT-1.0.md` named a `vbrain rekey --resume` flag that has never
  existed. Re-running `vbrain rekey` is itself the recovery path, and the
  document now says so.
```

- [ ] **Step 9: Run the full quality gate**

```bash
npm run quality && npm run quality:rust
```

Expected: lint, format, typecheck and the desktop build clean. `npm test` in an
OneDrive-backed checkout reports **337/339** with `test/durability.test.mjs` and
`test/format-conformance.test.mjs` failing on the pre-existing `fs.cpSync`
crash — that is the unchanged baseline, not a regression from this plan. Confirm
it by checking that no other test file is in the failure list. `cargo clippy`
must be clean with `-D warnings`.

- [ ] **Step 10: Regenerate the graph**

```bash
graphify update .
```

- [ ] **Step 11: Commit**

```bash
git add src-tauri/src/keyring.rs docs/FORMAT-1.0.md docs/ROADMAP.md SECURITY.md CHANGELOG.md graphify-out
git commit -m "docs: record what a re-key leaves behind, and stop misnaming a mid-re-key vault"
```

---

## Out of scope, deliberately

These stay where they are and are **not** part of Phase 7.7:

- **Attachment identity migration** (ROADMAP 7.6). Rotating `attachmentId` and
  `syncChange` renames every attachment directory and rewrites every canvas
  object, canvas history revision, index reference and descendant change in the
  DAG, and every peer must run it at the same time. It is its own phase-sized
  plan, roughly the size of 7.4.
- **A deliberate lock-break path** (ROADMAP 7.6). Still wanted, still small, but
  it is a new command with its own safety argument rather than a correction to
  shipped work.
- **The personal-memory work on `src/memory/`.** Task 3 adds it to the roadmap
  as a decision to make; it is not something this plan's tasks resolve, and it
  is not a bug to fix. Whoever takes it decides between writing it up as a phase
  and removing the stubs, and both are larger than a correction to shipped work.

## Found while rebasing onto Phase 10: `vbrain rekey` is refusing today

**This is a live defect on `main`, not a gap in shipped 7.4 work, and it is the
most urgent item in this document.** Phase 10 added a new encrypted in-vault
artifact — `documents/retention.enc`, sealed under the `documents` key with AAD
`secondbrain-vault:retention-policy:v1`, catalogued in `src/format-version.ts`
as `retentionPolicy` — and did not touch `src/keyring-rekey.ts`.

`classifyDocument` matches single-segment paths under `documents/` against
`DOCUMENT_PLAINTEXT`, then `index.enc`, then `plugin-policy.enc`, and every
unmatched path falls through to its closing
`throw new Error("Refusing to re-key: cannot classify documents/…")`.
`retention.enc` matches none of them. **So on any vault where a retention policy
has been written, `vbrain rekey` now refuses outright** — the command that exists
to answer a leaked passphrase does not run at all.

It fails closed, which is the guard working exactly as 7.4 designed it: an
unclassifiable artifact stops the re-key rather than being silently left sealed
under a key that is about to be retired. Nothing is lost or corrupted. But the
refusal is total, and nothing reports why to a user who did not write the walk.

Nothing tests the seam in either direction: `test/retention.test.mjs` and
`test/purge.test.mjs` never mention `rekey`, and `test/rekey-vault.test.mjs`
never mentions retention. `seedVault` writes no retention policy, which is why
the suite is green.

The fix is one classify branch beside the two that are already there, returning
a `document` item under `AAD.retentionPolicy`, plus a `seedVault` that writes a
retention policy so the walk's own tests cover it. It is small, but it is a
behaviour change to the re-key walk and it needs its own task written the way
Tasks 1–3 are written, with the failing test first. **Do it before Tasks 1–3, or
at least before 7.7 is checked off** — the two documentation tasks here describe
a command that a class of vaults cannot currently run.

The wider point belongs on the roadmap rather than in this plan: any phase that
adds an encrypted artifact has to teach the re-key walk about it, and there is
no test that fails when one does not.

## Known gap in this plan

Task 3 adds a `verifyRecoveryKeySet` bullet to ROADMAP 7.7, and **Tasks 1–3 do
not implement it.** It is recorded there because it belongs to this phase's
subject — what 7.4 left behind in 7.5's code — and because its own source
comment has been promising it since before 7.4 merged. It needs its own task,
written the way Tasks 1–3 are written, before 7.7 can be checked off:

- Decide whether the verification walk should call `planRekey` directly or
  whether the two should share an extracted inventory. `planRekey` classifies
  by AAD for re-encryption; verification only needs to prove each key opens
  something. They are not obviously the same list, and collapsing them wrongly
  would weaken a security check to save duplication.
- Decide what a restore against a mid-re-key vault should do: verify against the
  retiring keys as well and proceed, or refuse with a message naming `vbrain
  rekey`. Refusing is the smaller change and may be the right one — a keyring
  being restored while a re-key is half-committed is two recovery operations
  racing each other.
- Whichever is chosen, the test that matters is a restore against a vault
  deliberately left in the retiring state, which `test/rekey-vault.test.mjs`
  already knows how to produce.

Nothing else in this plan depends on that task, so Tasks 1–3 can land first.
