#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const root = path.resolve(import.meta.dirname, "..");
const out = path.join(root, "src-tauri", "resources", "desktop-sync");
const dist = path.join(root, "dist");
const helper = path.join(dist, "desktop-sync-helper.js");

if (!fs.existsSync(helper)) throw new Error("Build the TypeScript runtime before packaging the desktop sync helper.");
fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(out, { recursive: true, mode: 0o700 });
fs.copyFileSync(process.execPath, path.join(out, process.platform === "win32" ? "node.exe" : "node"));
if (process.platform !== "win32") fs.chmodSync(path.join(out, "node"), 0o755);
fs.cpSync(dist, path.join(out, "dist"), { recursive: true });
console.log(`Packaged desktop sync helper with the ${process.platform}/${process.arch} Node runtime.`);
