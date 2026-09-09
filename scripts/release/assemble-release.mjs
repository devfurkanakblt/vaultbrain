import fs from "node:fs";
import path from "node:path";

import { createLatestManifest, inspectReleaseArtifacts, writeReleaseChecksums } from "./release.mjs";

const arguments_ = process.argv.slice(2);
const subjectsOnly = arguments_[0] === "--subjects";
const [directory, tag, publishedAt] = subjectsOnly ? arguments_.slice(1) : arguments_;
if (!directory || !tag || (!subjectsOnly && !publishedAt)) {
  throw new Error("Usage: node scripts/release/assemble-release.mjs <directory> <tag> <published-at>");
}
const version = tag.startsWith("v") ? tag.slice(1) : "";
const artifacts = inspectReleaseArtifacts(directory, { version, requireProvenance: !subjectsOnly });
if (subjectsOnly) process.exit(0);
const latest = createLatestManifest({
  repository: "devfurkanakblt/vaultbrain",
  tag,
  version,
  publishedAt,
  artifacts,
});
fs.writeFileSync(path.join(directory, "latest.json"), `${JSON.stringify(latest, null, 2)}\n`, "utf8");
writeReleaseChecksums(directory);
