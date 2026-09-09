import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { validateReleaseVersions } from "./release.mjs";

const tag = process.argv[2];
if (!tag) throw new Error("Usage: node scripts/release/validate-versions.mjs <tag>");

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const packageVersion = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8")).version;
const tauriVersion = JSON.parse(fs.readFileSync(path.join(root, "src-tauri", "tauri.conf.json"), "utf8")).version;
const cargo = fs.readFileSync(path.join(root, "src-tauri", "Cargo.toml"), "utf8");
const cargoVersion = /^version\s*=\s*"([^"]+)"/mu.exec(cargo)?.[1];

const release = validateReleaseVersions({ tag, packageVersion, cargoVersion, tauriVersion });
process.stdout.write(`${JSON.stringify(release)}\n`);
