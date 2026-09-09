import fs from "node:fs";
import path from "node:path";

import { createReleaseOverlay } from "./release.mjs";

const output = process.argv[2];
if (!output) throw new Error("Usage: node scripts/release/prepare-config.mjs <output-file>");

const overlay = createReleaseOverlay({ publicKey: process.env.TAURI_UPDATER_PUBLIC_KEY });
const destination = path.resolve(output);
fs.mkdirSync(path.dirname(destination), { recursive: true });
fs.writeFileSync(destination, `${JSON.stringify(overlay, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
