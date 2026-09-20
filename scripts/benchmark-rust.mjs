// The desktop core's save-path benchmark, driven the way `benchmark.mjs`
// drives the TypeScript one.
//
// Every budget in docs/PRODUCT.md is a desktop interaction, and the desktop
// runs the Rust core — so measuring only the TypeScript library, as this
// repository did until Phase 17, leaves the number the contract is actually
// about unmeasured. This runs the tiers and reports them together.
import { execFileSync } from "node:child_process";
import path from "node:path";
import process from "node:process";

const BINARY = path.resolve(
  "src-tauri/target/release",
  process.platform === "win32" ? "vbrain-bench.exe" : "vbrain-bench",
);

function argument(name, fallback) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : fallback;
}

const tiers = argument("--notes", "1000,10000")
  .split(",")
  .map((value) => Number.parseInt(value.trim(), 10));
const saves = argument("--saves", "200");
const strict = process.argv.includes("--enforce-open-budgets");

let failed = false;
for (const notes of tiers) {
  const args = [BINARY, "--notes", String(notes), "--saves", saves, "--assert"];
  if (strict) args.push("--enforce-open-budgets");
  try {
    process.stdout.write(execFileSync(args[0], args.slice(1), { encoding: "utf8" }));
  } catch (error) {
    process.stdout.write(String(error.stdout ?? ""));
    process.stderr.write(String(error.stderr ?? ""));
    failed = true;
  }
}
process.exitCode = failed ? 1 : 0;
