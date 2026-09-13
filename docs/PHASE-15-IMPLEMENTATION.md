# Phase 15 implementation and acceptance ledger

Base: `9ed71bf04ee1f2224df96c2a7102779f30724cbb`, branch
`phase-14-closure`. Personal memory belongs to a later release, not the initial
1.0 acceptance. The user executes tests; this change has not been test-verified.

## Implementation boundaries

- The native desktop owns encrypted notes, pairing credentials and privileged
  operations. Node invokes the selected native executable over bounded anonymous
  stdin/stdout, without a vault path, passphrase or data key.
- Six memory MCP tools use that native boundary. Public remember requests contain
  untrusted evidence and require owner review; they cannot authorize automatic
  writes by claiming a user quote.
- Setup adds only its parser-validated managed MCP table and preserves all other
  TOML bytes. It retains a backup. Removal refuses changed managed content. No
  real user configuration has been installed by development.
- Desktop Memory controls are opt-in. The demo cannot claim a paired connection.
- Existing portable queue dedupe now survives repeated completion delivery, and
  candidate validation sends sensitive content to review while rejecting secrets.
- The Windows memory broker now creates a protected, current-user-only named
  pipe, rejects remote clients, verifies the connected server executable, and
  uses bounded message reads/writes with a two-second deadline. The one-shot
  native client accepts one UTF-8 JSON request up to 64 KiB and rejects extra
  lines or oversized input. These changes are implementation evidence only;
  the Windows adversarial acceptance below remains **NOT RUN**.
- Hook capture now accepts only a bounded, absolute transcript reference after
  pairing. The native broker validates the event, enrollment cutoff and
  symlink-free path, then stores the reference (never transcript content) in
  the encrypted control record before returning acceptance. Duplicate
  session/turn deliveries are idempotent, accepted references expire after
  seven days, and paused or unpaired memory refuses capture. The durable queue
  is intentionally only a reference backlog; worker processing remains
  disabled until the compatibility obligation below is accepted. The hook
  exits unsuccessfully unless native returns `accepted: true`, so its source
  cursor cannot advance before encrypted persistence.

## Worker compatibility: open implementation obligation

Read-only local inspection found `codex-cli 0.154.0-alpha.6.2`. Its exec help
describes `--json` as JSONL events. The historical adapter assumed CLI 0.153.1,
parsed a single JSON result, inherited the authentication/config home and did not
establish a tool-free worker. A supplied version string was not verification.

The unsafe launch path is disabled with a compatibility error. No actual model
request has been made. This is a safety correction, not completion of capture.
Automatic hooks are not installed. A supported adapter still needs bounded
process execution, isolated configuration, schema-constrained output, exact
source validation, one worker, cancellation/generation checks and installed-CLI
acceptance. Native durable locked queue/capture acceptance must remain open until
this path exists. Do not label Phase 15 complete based on the manual MCP/UI slice.

## User-run validation

Run from the project root after changes finish, in order. Stop at a failure and
retain its command/output; successful earlier gates need not be repeated without
an affected change.

```powershell
npm.cmd run build
node --test test/memory.test.mjs test/memory-queue.test.mjs test/memory-ledger.test.mjs test/memory-client.test.mjs test/rekey-transitions.test.mjs
npm.cmd run quality
npm.cmd run quality:rust
npm.cmd run recovery:drill
$env:VBRAIN_REQUIRE_NATIVE_KEYCHAIN = '1'
npm.cmd run test:native-keychain
Remove-Item Env:VBRAIN_REQUIRE_NATIVE_KEYCHAIN
npm.cmd run package:check
npm.cmd run tauri:build -- --config src-tauri/tauri.windows.conf.json
```

All results for this change are **NOT RUN** until the user provides them. No new
100k benchmark is requested because the search implementation did not change.
Inspect package contents as well as the command exit status.

## External acceptance

| Obligation | Status |
| --- | --- |
| Actual two-device sync | NOT RUN; second physical device required |
| Independent security audit and finding closure | NOT RUN; external reviewer required |
| Production key, authorized draft and real updater on three platforms | NOT RUN; signing authorization and macOS/Linux hosts required |
| Native Windows IPC/DPAPI adversarial and lifecycle checks | NOT RUN |
| Real worker processing and restore/re-key acceptance | NOT COMPLETE |
| Paired reference capture and encrypted seven-day backlog | IMPLEMENTED; user-run native acceptance pending |

Review the acceptance runbooks for sync, re-key and release separately. Prior
Phase 14 results apply to the prior implementation commit; they do not verify
this new native/UI/MCP code. Later memory code must receive its own security
review before release.
