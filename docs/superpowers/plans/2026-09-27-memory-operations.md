# Memory operations repair plan

Goal: make the paired memory API accept MCP candidates and return usable approved memory content.

Design: keep owner review and the memory-tag scope. Generate candidate IDs/timestamps on the server; include body only in read responses; bootstrap uses bounded approved-memory summaries. Preserve native error codes without exposing paths or credentials. Sandbox access still requires the host's normal approval mechanism.

- [x] Add failing Windows temporary-vault tests for candidate submission, owner approval, read, bootstrap and forget.
- [x] Repair candidate decoding, read content, and bootstrap dispatch.
- [x] Test and preserve safe native error codes through the Node client.
- [x] Run native memory and Node memory tests; build and refresh the desktop runtime.
- [x] Verify real status/search without writing to the owner's vault; update graphify.

Verification: 107 Rust library tests passed before final review refinements; final refinements passed all 10 memory tests and 28 Node tests. TypeScript build, targeted ESLint and git diff --check passed. Actual unlocked desktop returned ready/paired before final rebuild. Final executable was rebuilt and launched; status returned locked as expected after restart. No owner-vault notes were written. Independent review findings on ASCII error codes and long bootstrap entries were fixed with fail-before/pass-after tests.
