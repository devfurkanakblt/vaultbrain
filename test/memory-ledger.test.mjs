import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { MemoryLedger } from "../dist/memory/index.js";
import { openOrCreateVaultKeySet } from "../dist/keyring.js";

test("memory ledger stores and searches only Memory notes", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vaultbrain-memory-ledger-"));
  const passphrase = "synthetic test passphrase only";
  openOrCreateVaultKeySet(dir, passphrase);
  const ledger = new MemoryLedger(dir, passphrase);
  const result = ledger.remember({ kind: "preference", title: "Editor theme", body: "Dark mode", evidence: [{ messageId: "m1", quote: "I prefer dark mode" }], sourceKind: "user-stated", sensitive: false, links: ["Theme"] });
  assert.equal(result.status, "stored");
  assert.equal(ledger.search("dark mode").length, 1);
  assert.equal(ledger.remember({ kind: "fact", title: "Maybe", body: "An inference", evidence: [{ messageId: "m2", quote: "maybe" }], sourceKind: "inference", sensitive: false, links: [] }).status, "review");
  ledger.lock();
  assert.throws(() => ledger.search("dark"), /locked/i);
  fs.rmSync(dir, { recursive: true, force: true });
});
