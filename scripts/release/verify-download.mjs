import { verifyDownloadedAssets, verifyTauriSignatures } from "./release.mjs";

const [expectedDirectory, downloadedDirectory] = process.argv.slice(2);
if (!expectedDirectory || !downloadedDirectory) {
  throw new Error("Usage: node scripts/release/verify-download.mjs <expected-directory> <downloaded-directory>");
}
const publicKey = process.env.TAURI_UPDATER_PUBLIC_KEY;
if (!publicKey?.trim()) throw new Error("Missing Tauri updater public key");
const result = verifyDownloadedAssets({ expectedDirectory, downloadedDirectory });
verifyTauriSignatures({ directory: downloadedDirectory, publicKey });
process.stdout.write(`Verified ${result.verified} release assets.\n`);
