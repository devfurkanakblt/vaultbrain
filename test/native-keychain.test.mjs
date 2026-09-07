import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { forgetPassphrase, keychain, recallPassphrase, rememberPassphrase } from "../dist/keychain.js";

const required = process.env.VBRAIN_REQUIRE_NATIVE_KEYCHAIN === "1";

test("the host credential backend stores or reads and then removes an isolated credential", (t) => {
  const backend = keychain();
  if (!backend.available()) {
    if (required) assert.fail(`A native credential store is required on ${process.platform}.`);
    t.skip(`No native credential store is available on ${process.platform}.`);
    return;
  }

  const vaultDir = fs.mkdtempSync(path.join(os.tmpdir(), "vault-brain-native-keychain-"));
  const secret = `native-keychain-test-${process.pid}-${Date.now()}`;
  try {
    assert.equal(rememberPassphrase(vaultDir, secret), backend.name);
    assert.equal(recallPassphrase(vaultDir), secret);
    assert.equal(forgetPassphrase(vaultDir), true);
    assert.equal(recallPassphrase(vaultDir), undefined);
  } finally {
    forgetPassphrase(vaultDir);
    fs.rmSync(vaultDir, { recursive: true, force: true });
  }
});
