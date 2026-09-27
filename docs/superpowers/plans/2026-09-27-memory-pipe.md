# Memory pipe repair

**Goal:** Restore native memory requests after owner pairing.
**Design:** Preserve authentication, current-user ACLs, frame limits and deadlines. Correct Windows message transport only. Do not write user notes during verification.
**Files:** `src-tauri/src/memory.rs` (transport and Windows regression tests).

- [x] Reproduce a complete message timing out using a real Windows named pipe.
- [x] Correct message completion detection and run native memory tests.
- [x] Check response delivery and bounded disconnect behavior.
- [x] Rebuild desktop and verify a real memory_status request; retain owner unlock requirements.
- [x] Update graphify and review diff.

Verification: real Windows regression failed before the read fix; 8 native memory tests passed after both transport fixes. Native client returned ok:true; Node callMemoryNative returned ready and paired:true against the running unlocked desktop. Cowork itself has not been retested.
