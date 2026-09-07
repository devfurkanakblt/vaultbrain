import { verifyDownloadedAssets, verifyTauriSignatures } from "./release.mjs";

const [expectedDirectory, downloadedDirectory] = process.argv.slice(2);
if (!expectedDirectory || !downloadedDirectory) {
  throw new Error("Usage: node scripts/release/verify-download.mjs <expected-directory> <downloaded-directory>");
}
const result = verifyDownloadedAssets({ expectedDirectory, downloadedDirectory });
if (process.env.TAURI_UPDATER_PUBLIC_KEY) {
  verifyTauriSignatures({ directory: downloadedDirectory, publicKey: process.env.TAURI_UPDATER_PUBLIC_KEY });
}
process.stdout.write(`Verified ${result.verified} release assets.\n`);
