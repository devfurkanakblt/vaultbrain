import assert from "node:assert/strict";
import test from "node:test";

import { diagnoseWindowsLinker } from "../scripts/rust-toolchain.mjs";

test("a host with the MSVC toolchain is not diagnosed", () => {
  assert.equal(diagnoseWindowsLinker({ msvcLinker: String.raw`C:\...\VC\Tools\MSVC\14.44\bin\Hostx64\x64\link.exe` }), undefined);
});

test("a missing MSVC toolchain names the prerequisite", () => {
  const diagnosis = diagnoseWindowsLinker({ msvcLinker: undefined });

  assert.match(diagnosis, /Visual Studio Build Tools/u);
  assert.match(diagnosis, /Desktop development with C\+\+/u);
});

test("a shadowing coreutils link is named, because cargo's own error does not", () => {
  const diagnosis = diagnoseWindowsLinker({ msvcLinker: undefined, shadowingLink: "C:\\Program Files\\Git\\usr\\bin\\link.exe" });

  // cargo finds this link.exe, runs it, and reports "link: extra operand", which
  // reads like a cargo bug rather than a missing toolchain.
  assert.match(diagnosis, /usr\\bin\\link\.exe/u);
  assert.match(diagnosis, /extra operand/u);
  assert.match(diagnosis, /coreutils/u);
});

test("a shadowing link is not reported when the real linker is installed", () => {
  const diagnosis = diagnoseWindowsLinker({
    msvcLinker: String.raw`C:\...\link.exe`,
    shadowingLink: "C:\\Program Files\\Git\\usr\\bin\\link.exe",
  });

  assert.equal(diagnosis, undefined);
});
