#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

// The Rust core targets x86_64-pc-windows-msvc, which links with MSVC's
// link.exe. Two things go wrong on a Windows developer machine and cargo's own
// error names neither of them:
//
//   1. Without Visual Studio Build Tools there is no MSVC linker at all, so
//      every build script fails to link and the entire Rust half of the project
//      — including the Phase 15 broker — rests on CI alone.
//   2. Git for Windows ships GNU coreutils `link` as usr\bin\link.exe. From a
//      Git Bash shell that is ahead of MSVC on PATH, so cargo finds a link.exe,
//      runs the wrong program, and reports `link: extra operand '...'`. That
//      reads like a cargo defect rather than a missing toolchain.
//
// A check that cannot run on a host is a verification gap, never a pass. This
// refuses before cargo starts and says which of the two it is.
export function diagnoseWindowsLinker({ msvcLinker, shadowingLink } = {}) {
  if (msvcLinker) return undefined;
  const shadow = shadowingLink
    ? `\n\nPATH also has ${shadowingLink}. That is Git for Windows' GNU coreutils \`link\`, not a linker: ` +
      "cargo finds it, runs it, and reports `link: extra operand '...'`, which does not name the real cause."
    : "";
  return (
    "The MSVC linker is not installed, so the Rust core cannot be built or tested on this host.\n" +
    'Install Visual Studio Build Tools with the "Desktop development with C++" workload, then run this again.\n' +
    "Until then the Rust half of the project is unverified locally: record it as NOT RUN, never as a pass." +
    shadow
  );
}

function findMsvcLinker() {
  const programFiles = process.env["ProgramFiles(x86)"] ?? String.raw`C:\Program Files (x86)`;
  const vswhere = path.join(programFiles, "Microsoft Visual Studio", "Installer", "vswhere.exe");
  if (!fs.existsSync(vswhere)) return undefined;
  let installation;
  try {
    installation = execFileSync(
      vswhere,
      ["-latest", "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"],
      { encoding: "utf8" },
    ).trim();
  } catch {
    return undefined;
  }
  if (!installation) return undefined;
  const toolRoot = path.join(installation, "VC", "Tools", "MSVC");
  if (!fs.existsSync(toolRoot)) return undefined;
  for (const version of fs.readdirSync(toolRoot)) {
    const linker = path.join(toolRoot, version, "bin", "Hostx64", "x64", "link.exe");
    if (fs.existsSync(linker)) return linker;
  }
  return undefined;
}

function findShadowingLink() {
  try {
    const hits = execFileSync("where.exe", ["link.exe"], { encoding: "utf8" }).split(/\r?\n/u);
    return hits.find((hit) => /[\\/]usr[\\/]bin[\\/]link\.exe$/iu.test(hit.trim()))?.trim();
  } catch {
    return undefined;
  }
}

const entryPoint = process.argv[1] ? path.resolve(process.argv[1]) : undefined;
if (entryPoint === fileURLToPath(import.meta.url)) {
  if (process.platform === "win32") {
    const diagnosis = diagnoseWindowsLinker({ msvcLinker: findMsvcLinker(), shadowingLink: findShadowingLink() });
    if (diagnosis) {
      console.error(diagnosis);
      process.exitCode = 1;
    }
  }
}
