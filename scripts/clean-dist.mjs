import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// tsc does not remove output for deleted source files. Build only owns dist.
const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const output = path.join(root, "dist");
if (fs.existsSync(output) && fs.lstatSync(output).isSymbolicLink()) {
  throw new Error("Refusing to clean a linked dist directory.");
}
fs.rmSync(output, { recursive: true, force: true });
