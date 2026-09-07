import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { DocumentVault } from "../dist/documents.js";
import { readAudit, verifyAudit } from "../dist/audit.js";
import {
  DEFAULT_SCRYPT_N,
  KEY_NAMES,
  KEYRING_VERSION,
  forgetVaultKeys,
  openOrCreateVaultKeys,
  randomKeySet,
  readKeyring,
  unwrapSlot,
  wrapKeySet,
  wrapKeySetSlot,
  writeKeyring,
  zeroKeySet,
  zeroRetiringKeys,
} from "../dist/keyring.js";
import {
  createRecoveryKit,
  generateRecoveryCode,
  parseRecoveryCode,
  prepareRecoveryForRekey,
  removeRecoverySlot,
  restoreVaultKeyring,
  rewriteRecoveryKitForRekey,
} from "../dist/keyring-recovery.js";
import { readKeyringStatus } from "../dist/keyring-status.js";
import { changeVaultPassphrase } from "../dist/keyring-passphrase.js";
import { loadVaultFile, upsertEntry } from "../dist/store.js";

const PASSPHRASE = "correct horse battery staple";
const NEW_PASSPHRASE = "new correct horse battery staple";
const CLI = fileURLToPath(new URL("../dist/cli.js", import.meta.url));

function tempLayout() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "vbrain-recovery-"));
  return { root, vault: path.join(root, "vault"), kit: path.join(root, "recovery-kit.json") };
}

function sameKeySet(left, right) {
  return KEY_NAMES.every((name) => left[name].equals(right[name]));
}

function runCli(args, env = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
}

function rotateRecoveryKit(vault, kit, recoveryCode, current) {
  const keyring = readKeyring(vault);
  assert.ok(keyring);
  const prepared = prepareRecoveryForRekey(keyring, current, { kitPath: kit, code: recoveryCode });
  assert.ok(prepared);

  const rotated = randomKeySet();
  for (const name of ["attachmentId", "syncChange", "audit"]) {
    rotated[name].fill(0);
    rotated[name] = Buffer.from(current[name]);
  }
  const retiring = {
    documents: Buffer.from(current.documents),
    kv: Buffer.from(current.kv),
    syncEnvelope: Buffer.from(current.syncEnvelope),
  };
  const recoverySlot = wrapKeySetSlot(rotated, recoveryCode, {
    label: "recovery",
    id: prepared.slot.id,
    createdAt: prepared.slot.createdAt,
    N: prepared.slot.kdf.N,
    retiring,
  });
  fs.writeFileSync(
    kit,
    `${JSON.stringify({ version: 1, kind: "vaultbrain-recovery-kit", createdAt: prepared.kitCreatedAt, slot: recoverySlot })}\n`,
    "utf8",
  );
  writeKeyring(vault, {
    version: KEYRING_VERSION,
    slots: [wrapKeySet(rotated, PASSPHRASE, DEFAULT_SCRYPT_N, retiring), recoverySlot],
  });
  forgetVaultKeys(vault);
  zeroKeySet(rotated);
  zeroRetiringKeys(retiring);
}

test("recovery codes carry 256 random bits and reject transcription errors", () => {
  const first = generateRecoveryCode();
  const second = generateRecoveryCode();
  assert.match(first, /^vbr1_[A-Za-z0-9_-]{43}_[a-f0-9]{8}$/u);
  assert.notEqual(first, second);
  assert.equal(parseRecoveryCode(first).length, 32);
  const badChecksum = `${first.slice(0, -8)}${first.endsWith("00000000") ? "11111111" : "00000000"}`;
  assert.throws(() => parseRecoveryCode(badChecksum), /checksum/iu);
});

test("a recovery kit adds one compatible slot without storing its code", () => {
  const { vault, kit } = tempLayout();
  const primary = openOrCreateVaultKeys(vault, PASSPHRASE);
  assert.ok(primary);

  const report = createRecoveryKit(vault, PASSPHRASE, kit);
  const file = readKeyring(vault);
  assert.ok(file);
  assert.equal(file.slots.length, 2);
  assert.equal(file.slots[1].id, report.slotId);
  assert.equal(file.slots[1].label, "recovery");

  const stored = fs.readFileSync(kit, "utf8");
  assert.doesNotMatch(stored, new RegExp(report.recoveryCode.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
  const recovered = unwrapSlot(file.slots[1], report.recoveryCode);
  assert.equal(sameKeySet(primary, recovered), true);
  zeroKeySet(primary);
  zeroKeySet(recovered);
});

test("keyring status exposes headers and cost health but no salt or ciphertext", () => {
  const { vault, kit } = tempLayout();
  const keys = openOrCreateVaultKeys(vault, PASSPHRASE);
  assert.ok(keys);
  zeroKeySet(keys);
  createRecoveryKit(vault, PASSPHRASE, kit);

  const status = readKeyringStatus(vault);
  assert.equal(status.format, "keyring");
  assert.equal(status.recoveryConfigured, true);
  assert.equal(status.slots.length, 2);
  assert.deepEqual(Object.keys(status.slots[0].kdf).sort(), ["N", "cost", "name", "p", "r"]);
  assert.equal(JSON.stringify(status).includes("ciphertext"), false);
  assert.equal(JSON.stringify(status).includes("salt"), false);
});

test("a recovery kit restores a damaged keyring under a new primary passphrase", () => {
  const { vault, kit } = tempLayout();
  const documentVault = new DocumentVault(vault, PASSPHRASE);
  const note = documentVault.put({ path: "Recovery.md", title: "Recovery", body: "survives" });
  documentVault.lock();
  const created = createRecoveryKit(vault, PASSPHRASE, kit);
  forgetVaultKeys(vault);
  fs.writeFileSync(path.join(vault, "keyring.json"), "{damaged", "utf8");

  const restored = restoreVaultKeyring(vault, kit, created.recoveryCode, NEW_PASSPHRASE);
  assert.equal(restored.backupCreated, true);
  assert.ok(restored.backupPath);
  assert.equal(new DocumentVault(vault, NEW_PASSPHRASE).get(note.id).body, "survives");
  assert.throws(() => new DocumentVault(vault, PASSPHRASE).list());
});

test("a rotated recovery kit restores ciphertext under its current keys", () => {
  const { vault, kit } = tempLayout();
  const current = openOrCreateVaultKeys(vault, PASSPHRASE);
  assert.ok(current);
  const created = createRecoveryKit(vault, PASSPHRASE, kit);
  rotateRecoveryKit(vault, kit, created.recoveryCode, current);
  zeroKeySet(current);
  upsertEntry(vault, "current", "state", "current ciphertext", "rotation test", PASSPHRASE);

  const report = restoreVaultKeyring(vault, kit, created.recoveryCode, NEW_PASSPHRASE);
  assert.ok(report.verifiedObjects > 0);
  assert.equal(loadVaultFile(vault, "current", NEW_PASSPHRASE)[0].value, "current ciphertext");
});

test("a rotated recovery kit restores ciphertext under its retiring keys", () => {
  const { vault, kit } = tempLayout();
  const current = openOrCreateVaultKeys(vault, PASSPHRASE);
  assert.ok(current);
  upsertEntry(vault, "retiring", "state", "retiring ciphertext", "rotation test", PASSPHRASE);
  const created = createRecoveryKit(vault, PASSPHRASE, kit);
  rotateRecoveryKit(vault, kit, created.recoveryCode, current);
  zeroKeySet(current);

  const report = restoreVaultKeyring(vault, kit, created.recoveryCode, NEW_PASSPHRASE);
  assert.ok(report.verifiedObjects > 0);
  assert.equal(loadVaultFile(vault, "retiring", NEW_PASSPHRASE)[0].value, "retiring ciphertext");
});

test("a rotated recovery kit verifies mixed current and retiring ciphertext", () => {
  const { vault, kit } = tempLayout();
  const current = openOrCreateVaultKeys(vault, PASSPHRASE);
  assert.ok(current);
  upsertEntry(vault, "retiring", "state", "retiring ciphertext", "rotation test", PASSPHRASE);
  const created = createRecoveryKit(vault, PASSPHRASE, kit);
  rotateRecoveryKit(vault, kit, created.recoveryCode, current);
  zeroKeySet(current);
  upsertEntry(vault, "current", "state", "current ciphertext", "rotation test", PASSPHRASE);

  const report = restoreVaultKeyring(vault, kit, created.recoveryCode, NEW_PASSPHRASE);
  assert.ok(report.verifiedObjects >= 2);
  assert.equal(loadVaultFile(vault, "retiring", NEW_PASSPHRASE)[0].value, "retiring ciphertext");
  assert.equal(loadVaultFile(vault, "current", NEW_PASSPHRASE)[0].value, "current ciphertext");
});

test("wrong recovery input is non-mutating and a recovery slot can be removed explicitly", () => {
  const { vault, kit } = tempLayout();
  const keys = openOrCreateVaultKeys(vault, PASSPHRASE);
  assert.ok(keys);
  zeroKeySet(keys);
  const created = createRecoveryKit(vault, PASSPHRASE, kit);
  const keyringPath = path.join(vault, "keyring.json");
  const before = fs.readFileSync(keyringPath);

  assert.throws(
    () => restoreVaultKeyring(vault, kit, generateRecoveryCode(), NEW_PASSPHRASE),
    /recovery code|authenticate/iu,
  );
  assert.deepEqual(fs.readFileSync(keyringPath), before);

  const removed = removeRecoverySlot(vault, PASSPHRASE, created.slotId);
  assert.equal(removed.slotId, created.slotId);
  assert.equal(readKeyring(vault)?.slots.length, 1);
});

test("a valid recovery kit from another vault is rejected before keyring replacement", () => {
  const target = tempLayout();
  const source = tempLayout();
  const targetVault = new DocumentVault(target.vault, PASSPHRASE);
  targetVault.put({ path: "Target.md", title: "Target", body: "target data" });
  targetVault.lock();
  const sourceKeys = openOrCreateVaultKeys(source.vault, PASSPHRASE);
  assert.ok(sourceKeys);
  zeroKeySet(sourceKeys);
  const wrongKit = createRecoveryKit(source.vault, PASSPHRASE, source.kit);
  const keyringPath = path.join(target.vault, "keyring.json");
  const before = fs.readFileSync(keyringPath);

  assert.throws(
    () => restoreVaultKeyring(target.vault, source.kit, wrongKit.recoveryCode, NEW_PASSPHRASE),
    /does not authenticate|wrong vault/iu,
  );
  assert.deepEqual(fs.readFileSync(keyringPath), before);
});

test("the CLI reports keyring status without a passphrase or secret fields", () => {
  const { vault } = tempLayout();
  const keys = openOrCreateVaultKeys(vault, PASSPHRASE);
  assert.ok(keys);
  zeroKeySet(keys);

  const result = runCli(["--vault", vault, "keyring", "status", "--json"], {
    VBRAIN_PASSPHRASE: "",
  });
  assert.equal(result.status, 0, result.stderr);
  const status = JSON.parse(result.stdout);
  assert.equal(status.format, "keyring");
  assert.equal(status.slots.length, 1);
  assert.equal(result.stdout.includes("salt"), false);
  assert.equal(result.stdout.includes("ciphertext"), false);
});

test("the CLI creates, restores, and removes recovery access without the OS keychain", () => {
  const { vault, kit } = tempLayout();
  const documentVault = new DocumentVault(vault, PASSPHRASE);
  const note = documentVault.put({ path: "CLI.md", title: "CLI", body: "restored by CLI" });
  documentVault.lock();
  const recoveryCode = generateRecoveryCode();

  const created = runCli(["--vault", vault, "keyring", "recovery", "create", "--out", kit], {
    VBRAIN_PASSPHRASE: PASSPHRASE,
    VBRAIN_RECOVERY_CODE: recoveryCode,
    VBRAIN_RECOVERY_CONFIRM: recoveryCode,
  });
  assert.equal(created.status, 0, created.stderr);
  assert.match(created.stdout, /Recovery kit created/iu);
  assert.doesNotMatch(created.stdout, new RegExp(recoveryCode, "u"));
  const slotId = readKeyring(vault)?.slots.find((slot) => slot.label === "recovery")?.id;
  assert.ok(slotId);

  fs.writeFileSync(path.join(vault, "keyring.json"), "{damaged", "utf8");
  const restored = runCli(["--vault", vault, "keyring", "recovery", "restore", "--from", kit], {
    VBRAIN_RECOVERY_CODE: recoveryCode,
    VBRAIN_NEW_PASSPHRASE: NEW_PASSPHRASE,
  });
  assert.equal(restored.status, 0, restored.stderr);
  assert.equal(new DocumentVault(vault, NEW_PASSPHRASE).get(note.id).body, "restored by CLI");

  const removed = runCli(["--vault", vault, "keyring", "recovery", "remove", "--slot", slotId], {
    VBRAIN_PASSPHRASE: NEW_PASSPHRASE,
  });
  assert.equal(removed.status, 0, removed.stderr);
  assert.match(removed.stderr, /does not invalidate/iu);
});

test("key material changes append paired, secret-free audit events", () => {
  const { vault, kit } = tempLayout();
  const keys = openOrCreateVaultKeys(vault, PASSPHRASE);
  assert.ok(keys);
  zeroKeySet(keys);

  const created = createRecoveryKit(vault, PASSPHRASE, kit);
  changeVaultPassphrase(vault, PASSPHRASE, NEW_PASSPHRASE);
  removeRecoverySlot(vault, NEW_PASSPHRASE, created.slotId);

  const events = readAudit(vault).filter((entry) => entry.actor === "cli-keyring");
  assert.deepEqual(
    events.map(({ outcome }) => outcome),
    ["pending", "allowed", "pending", "allowed", "pending", "allowed"],
  );
  for (let index = 0; index < events.length; index += 2) {
    assert.equal(events[index].key, events[index + 1].key);
  }
  const serialized = JSON.stringify(events);
  assert.equal(serialized.includes(created.recoveryCode), false);
  assert.equal(serialized.includes(kit), false);
  assert.equal(verifyAudit(vault, NEW_PASSPHRASE).valid, true);
});

test("rekey requires the matching recovery kit and can atomically advance its wrapped keyset", () => {
  const { vault, kit } = tempLayout();
  const current = openOrCreateVaultKeys(vault, PASSPHRASE);
  assert.ok(current);
  const created = createRecoveryKit(vault, PASSPHRASE, kit);
  const keyring = readKeyring(vault);
  assert.ok(keyring);

  assert.throws(() => prepareRecoveryForRekey(keyring, current), /recovery kit and code/iu);
  const prepared = prepareRecoveryForRekey(keyring, current, {
    kitPath: kit,
    code: created.recoveryCode,
  });
  assert.ok(prepared);
  const replacement = openOrCreateVaultKeys(tempLayout().vault, "replacement passphrase");
  assert.ok(replacement);
  const rewritten = rewriteRecoveryKitForRekey(prepared, created.recoveryCode, replacement);
  assert.equal(rewritten.id, created.slotId);
  const opened = unwrapSlot(JSON.parse(fs.readFileSync(kit, "utf8")).slot, created.recoveryCode);
  assert.equal(sameKeySet(opened, replacement), true);
  zeroKeySet(current);
  zeroKeySet(replacement);
  zeroKeySet(opened);
});
