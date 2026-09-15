import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { DocumentVault } from "../dist/documents.js";
import { removeTree } from "../scripts/fs-tree.mjs";
import { createRecoveryKit, generateRecoveryCode } from "../dist/keyring-recovery.js";
import { forgetVaultKeys, openOrCreateVaultKeys, openVaultKeys, readKeyring, zeroKeySet } from "../dist/keyring.js";
import {
  journalPath,
  planRekey,
  rekeyVault,
  resumeRekey,
  stagedTree,
} from "../dist/keyring-rekey.js";
import { SyncDeviceManager } from "../dist/sync.js";

const CURRENT = "phase-14-transition-current-passphrase";
const NEXT = "phase-14-transition-next-passphrase";

function fixture(label) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `vault-brain-${label}-`));
  const keys = openOrCreateVaultKeys(dir, CURRENT);
  assert.ok(keys);
  zeroKeySet(keys);
  const vault = new DocumentVault(dir, CURRENT);
  const note = vault.put({ path: "Transition.md", title: "Transition", body: "before" });
  vault.putAttachment(Buffer.from("transition attachment"), "transition.bin");
  vault.lock();
  return { dir, noteId: note.id };
}

function assertOpens(dir, passphrase) {
  const keys = openVaultKeys(dir, passphrase);
  assert.ok(keys);
  zeroKeySet(keys);
}

function cleanup(dir) {
  forgetVaultKeys(dir);
  removeTree(dir);
}

function withInstallInterruption(vaultDir, installNumber, callback) {
  const original = fs.renameSync;
  let installs = 0;
  const tree = stagedTree(vaultDir);
  fs.renameSync = (from, to, ...rest) => {
    if (String(from).startsWith(tree) && !String(to).startsWith(tree)) {
      installs += 1;
      if (installs === installNumber) throw new Error(`EIO: simulated install interruption ${installNumber}`);
    }
    return original(from, to, ...rest);
  };
  try {
    return callback(() => installs);
  } finally {
    fs.renameSync = original;
  }
}

function countIdentityRotationInstalls(vaultDir) {
  const original = fs.renameSync;
  const tree = stagedTree(vaultDir);
  let installs = 0;
  fs.renameSync = (from, to, ...rest) => {
    if (String(from).startsWith(tree) && !String(to).startsWith(tree)) installs += 1;
    return original(from, to, ...rest);
  };
  try {
    rekeyVault(vaultDir, CURRENT, NEXT, {
      rotateIdentities: {
        ownerLabel: "Transition owner",
        ownerDeviceId: "11111111-1111-4111-8111-111111111111",
      },
    });
    return installs;
  } finally {
    fs.renameSync = original;
  }
}

test("every normal re-key file install interruption is recoverable and replay is idempotent", () => {
  const probe = fixture("rekey-transition-probe");
  const installCount = planRekey(probe.dir).length;
  cleanup(probe.dir);

  for (let interruption = 1; interruption <= installCount; interruption += 1) {
    const { dir, noteId } = fixture(`rekey-transition-${interruption}`);
    try {
      withInstallInterruption(dir, interruption, () => {
        assert.throws(
          () => rekeyVault(dir, CURRENT, NEXT),
          new RegExp(`simulated install interruption ${interruption}`),
        );
      });
      assert.equal(fs.existsSync(journalPath(dir)), true, `journal survives install ${interruption}`);
      assert.equal(resumeRekey(dir), "finished");
      assert.equal(resumeRekey(dir), "none", "a second resume must be a no-op");
      forgetVaultKeys(dir);
      const vault = new DocumentVault(dir, NEXT);
      try {
        assert.equal(vault.get(noteId).body, "before");
      } finally {
        vault.lock();
      }
      assert.throws(() => openVaultKeys(dir, CURRENT), /authenticate|passphrase|unable/iu);
    } finally {
      cleanup(dir);
    }
  }
});

test("every identity-rotation file install interruption is recoverable and leaves a fresh owner", () => {
  const probe = fixture("identity-transition-probe");
  const installCount = countIdentityRotationInstalls(probe.dir);
  cleanup(probe.dir);

  for (let interruption = 1; interruption <= installCount; interruption += 1) {
    const { dir } = fixture(`identity-transition-${interruption}`);
    try {
      withInstallInterruption(dir, interruption, () => {
        assert.throws(
          () => rekeyVault(dir, CURRENT, NEXT, {
            rotateIdentities: {
              ownerLabel: "Transition owner",
              ownerDeviceId: "11111111-1111-4111-8111-111111111111",
            },
          }),
          new RegExp(`simulated install interruption ${interruption}`),
        );
      });
      const outcome = resumeRekey(dir);
      if (outcome === "finished") {
        forgetVaultKeys(dir);
        assertOpens(dir, NEXT);
        const manager = new SyncDeviceManager(dir, NEXT);
        try {
          const state = manager.state();
          assert.equal(state?.body.devices.length, 1);
          assert.equal(state.body.devices[0].certificate.deviceId, "11111111-1111-4111-8111-111111111111");
          assert.equal(manager.fingerprint()?.length, 64);
        } finally {
          manager.close();
        }
      } else {
        assert.equal(outcome, "rolled-back");
        forgetVaultKeys(dir);
        assertOpens(dir, CURRENT);
      }
      assert.equal(resumeRekey(dir), "none");
    } finally {
      cleanup(dir);
    }
  }
});

test("a journal write or keyring replacement interruption rolls back without claiming success", () => {
  const { dir } = fixture("keyring-boundary");
  const keyringPath = path.join(dir, "keyring.json");
  const original = fs.renameSync;
  let keyringReplacement = false;
  fs.renameSync = (from, to, ...rest) => {
    if (path.resolve(to) === path.resolve(keyringPath)) {
      keyringReplacement = true;
      throw new Error("EIO: simulated keyring replacement interruption");
    }
    return original(from, to, ...rest);
  };
  try {
    assert.throws(() => rekeyVault(dir, CURRENT, NEXT), /keyring replacement interruption/u);
  } finally {
    fs.renameSync = original;
  }
  try {
    assert.equal(keyringReplacement, true);
    assert.equal(fs.existsSync(journalPath(dir)), true);
    assert.equal(resumeRekey(dir), "rolled-back");
    assert.equal(resumeRekey(dir), "none");
    forgetVaultKeys(dir);
    assertOpens(dir, CURRENT);
    assert.throws(() => openVaultKeys(dir, NEXT), /authenticate|passphrase|unable/iu);
  } finally {
    cleanup(dir);
  }
});

test("a journal write interruption leaves the original vault untouched", () => {
  const { dir } = fixture("journal-write-boundary");
  const journal = journalPath(dir);
  const original = fs.renameSync;
  let journalWrite = false;
  fs.renameSync = (from, to, ...rest) => {
    if (path.resolve(to) === path.resolve(journal)) {
      journalWrite = true;
      throw new Error("EIO: simulated journal write interruption");
    }
    return original(from, to, ...rest);
  };
  try {
    assert.throws(() => rekeyVault(dir, CURRENT, NEXT), /journal write interruption/u);
  } finally {
    fs.renameSync = original;
  }
  try {
    assert.equal(journalWrite, true);
    assert.equal(fs.existsSync(journal), false);
    forgetVaultKeys(dir);
    assertOpens(dir, CURRENT);
    assert.throws(() => openVaultKeys(dir, NEXT), /authenticate|passphrase|unable/iu);
  } finally {
    cleanup(dir);
  }
});

test("a recovery-kit advance interrupted before keyring replacement is reported as a mismatched kit", () => {
  const { dir } = fixture("recovery-kit-boundary");
  const kitDir = fs.mkdtempSync(path.join(os.tmpdir(), "vault-brain-rekey-kit-"));
  const kit = path.join(kitDir, "recovery-kit.json");
  try {
    const recoveryCode = generateRecoveryCode();
    createRecoveryKit(dir, CURRENT, kit, { recoveryCode });
    const keyringPath = path.join(dir, "keyring.json");
    const original = fs.renameSync;
    fs.renameSync = (from, to, ...rest) => {
      if (path.resolve(to) === path.resolve(keyringPath)) throw new Error("EIO: kit boundary interruption");
      return original(from, to, ...rest);
    };
    try {
      assert.throws(
        () => rekeyVault(dir, CURRENT, NEXT, { recovery: { kitPath: kit, code: recoveryCode } }),
        /recovery kit was already rewritten|kit boundary interruption/u,
      );
    } finally {
      fs.renameSync = original;
    }

    assert.equal(fs.existsSync(journalPath(dir)), true);
    assert.equal(readKeyring(dir)?.slots.length, 2);
    assert.equal(resumeRekey(dir), "rolled-back");
    assert.throws(() => openVaultKeys(dir, NEXT), /authenticate|passphrase|unable/iu);
  } finally {
    cleanup(dir);
    removeTree(kitDir);
  }
});
