#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { createRequire } from "node:module";

import { copyTree, removeTree } from "./fs-tree.mjs";

const root = path.resolve(import.meta.dirname, "..");
const out = path.join(root, "src-tauri", "resources", "desktop-sync");
const dist = path.join(root, "dist");
const helper = path.join(dist, "desktop-sync-helper.js");

if (!fs.existsSync(helper)) throw new Error("Build the TypeScript runtime before packaging the desktop sync helper.");
removeTree(out);
fs.mkdirSync(out, { recursive: true, mode: 0o700 });
fs.writeFileSync(path.join(out, ".gitkeep"), "");
fs.copyFileSync(process.execPath, path.join(out, process.platform === "win32" ? "node.exe" : "node"));
if (process.platform !== "win32") fs.chmodSync(path.join(out, "node"), 0o755);
copyTree(dist, path.join(out, "dist"));
// The sidecar runs from installed resources, where the repository's
// node_modules and package.json do not exist. Its document engine uses YAML.
const require = createRequire(import.meta.url);
const yamlRoot = path.dirname(require.resolve("yaml/package.json"));
fs.mkdirSync(path.join(out, "node_modules"), { recursive: true });
copyTree(yamlRoot, path.join(out, "node_modules", "yaml"));
fs.writeFileSync(path.join(out, "package.json"), JSON.stringify({ private: true, type: "module" }));
console.log(`Packaged desktop sync helper with the ${process.platform}/${process.arch} Node runtime.`);
