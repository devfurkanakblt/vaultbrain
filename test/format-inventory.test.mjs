import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import ts from "typescript";
import * as format from "../dist/format-version.js";
import { DocumentVault } from "../dist/documents.js";
import { planRekey } from "../dist/keyring-rekey.js";

function literals(source) {
  const result = [];
  const tree = ts.createSourceFile("source.ts", source, ts.ScriptTarget.Latest, true);
  function visit(node) {
    if (
      (ts.isStringLiteral(node) ||
        ts.isNoSubstitutionTemplateLiteral(node) ||
        node.kind === ts.SyntaxKind.TemplateHead) &&
      node.text.startsWith("secondbrain-vault:")
    )
      result.push(node.text);
    ts.forEachChild(node, visit);
  }
  visit(tree);
  return result;
}

function assertDomains(source, allowed) {
  for (const value of literals(source)) assert.ok(allowed.has(value), `Uncatalogued crypto domain: ${value}`);
}

test("all TS domains and shared Rust domains match the frozen inventory", () => {
  const expected = JSON.parse(fs.readFileSync(new URL("./fixtures/format-domains.json", import.meta.url), "utf8"));
  assert.deepEqual(format.AAD, expected);
  const allowed = new Set(Object.values(expected));
  for (const file of fs.readdirSync("src", { recursive: true }).filter((file) => file.endsWith(".ts"))) {
    assertDomains(fs.readFileSync(path.join("src", file), "utf8"), allowed);
  }
  for (const file of fs.readdirSync("src-tauri/src", { recursive: true }).filter((file) => file.endsWith(".rs"))) {
    const source = fs
      .readFileSync(path.join("src-tauri/src", file), "utf8")
      .split("#[cfg(test)]")[0]
      .replace(/\/\/[^\n]*/gu, "");
    for (const match of source.matchAll(/"(secondbrain-vault:[^"\n]*)"/gu)) {
      const value = match[1].split("{")[0].replaceAll("\\0", "\0");
      assert.ok(allowed.has(value), `${file}: divergent Rust domain ${value}`);
    }
  }
  assert.throws(() => assertDomains('const aad = "secondbrain-vault:unregistered:v1";', allowed), /Uncatalogued/);
  const omitted = new Set(allowed);
  omitted.delete(expected.keyedEnvelope);
  assert.throws(() => assertDomains('const aad = "secondbrain-vault:kv:v2";', omitted), /Uncatalogued/);
});

test("real writers produce only catalogued, explicitly rekeyed encrypted files", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "format-inventory-"));
  let vault;
  try {
    vault = new DocumentVault(root, "format-inventory-passphrase");
    const note = vault.put({ path: "Catalogue.md", body: "first" });
    vault.put({ id: note.id, path: note.path, body: "second" });
    vault.putCanvas({ path: "Catalogue.canvas", nodes: [], edges: [] });
    vault.putAttachment(Buffer.from("catalogue bytes"), "catalogue.bin");
    vault.setRetentionPolicy({ version: 1, keepRevisions: 4, keepDays: null });
    const plugin = vault.installPlugin({
      manifest: {
        manifestVersion: 1,
        id: "catalogue-plugin",
        name: "Catalogue",
        version: "1.0.0",
        description: "Synthetic fixture",
        author: "Tests",
        capabilities: [],
      },
      source: "export function activate() {}",
    });
    vault.setPluginStorage(plugin.id, { preference: "value" });
    vault.setPluginRestrictedMode(true);
    vault.lock();
    const planned = new Set(planRekey(root).map((item) => item.path));
    const files = fs.readdirSync(root, { recursive: true }).filter((file) => file.endsWith(".enc"));
    for (const file of files) {
      const relative = file.replaceAll(path.sep, "/");
      const artifact = format.artifactForPath(relative);
      assert.equal(artifact.rekey.normal, "reencrypt", relative);
      assert.ok(planned.has(relative), `Missing rekey classification: ${relative}`);
    }
    assert.throws(() => format.artifactForPath("documents/new-secret.enc"), /Uncatalogued/);
    const omitted = { ...format.FORMAT_COMPATIBILITY };
    delete omitted.documentIndex;
    assert.throws(() => format.artifactForPath("documents/index.enc", omitted), /Uncatalogued/);
    fs.writeFileSync(path.join(root, "documents", "new-secret.enc"), "{}");
    assert.throws(() => planRekey(root), /Uncatalogued|cannot classify/);
  } finally {
    vault?.lock();
    fs.rmSync(root, { recursive: true, force: true });
  }
});
