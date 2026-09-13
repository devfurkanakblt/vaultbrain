# Two-desktop sync acceptance runbook

This is a manual acceptance drill for two real desktop installations, one
owner device and one enrolled peer. It is intentionally separate from the
automated recovery drill and from `test/desktop-sync-helper.test.mjs`.

## Preconditions

- Use two disposable desktop installations with the same reviewed build and a
  synthetic encrypted vault. Do not use production notes.
- Use a self-hosted relay on a reachable machine. The relay stores opaque
  ciphertext only; keep its bearer token in a password manager or environment
  variable and never put it in a command argument or transcript.
- Keep the owner authority fingerprint and checkpoint ID available through a
  trusted channel. The first pull requires the authority fingerprint.
- Record the reviewed commit, OS and architecture, app version, Node/Rust/Tauri
  tool versions, relay URL, operator, and the evidence directory before starting.

## Relay preparation

On the relay host, set a fresh token and start the supported relay command:

PowerShell:

```powershell
$env:VBRAIN_RELAY_TOKEN = '<at-least-32-random-bytes>'
vbrain --experimental-trusted-sync sync relay serve .\relay-data --port 8787
```

POSIX shells:

```bash
export VBRAIN_RELAY_TOKEN='<at-least-32-random-bytes>'
vbrain --experimental-trusted-sync sync relay serve ./relay-data --port 8787
```

On the owner desktop, create a checkpoint and publish the owner state:

```bash
vbrain --experimental-trusted-sync --vault ./owner-vault sync checkpoint create
vbrain --experimental-trusted-sync --vault ./owner-vault sync relay push https://relay.example
```

The second desktop must already be an encrypted backup restore, or an enrolled
vault created through the desktop flow. An empty directory cannot be bootstrapped
from the relay. For a restored vault's first pull, use both pins:

```bash
vbrain --experimental-trusted-sync --vault ./peer-vault sync relay pull https://relay.example \
  --authority <owner-authority-sha256> \
  --checkpoint <owner-checkpoint-sha256>
```

## Manual two-desktop drill

Use the desktop UI for each lifecycle action. The CLI snippets above prepare the
relay and provide a recovery fallback; they are not evidence that the desktop
surface was exercised.

1. On desktop A, initialize or open the synthetic owner vault. Create a note,
   edit it, save it, and attach a small file. Record note ID and attachment
   content hash.
2. Enroll desktop B from the owner flow. Approve the enrollment on A, complete
   the request on B, and record both device IDs and the resulting authority
   fingerprint.
3. On A, create a checkpoint and push. On B, pull through the desktop sync
   controls. Confirm the note, edit, and attachment are present and hashes
   match.
4. Disconnect B from the relay. Make an edit on A and queue a local change on B.
   Reconnect B, pull, and resolve any concurrent heads through the desktop
   conflict UI. Record the chosen head and final content.
5. Start a large or deliberately slow transfer, cancel it, and confirm the UI
   reports cancellation while the vault remains openable. Repeat once with the
   relay unavailable and record the offline error.
6. Lock A while a sync operation is pending. Confirm the operation stops or
   waits according to the UI status and that no passphrase or bearer token is
   displayed in diagnostics.
7. Revoke B on A. Confirm B cannot publish a new accepted change. Create a
   post-revocation change on A, rotate the epoch as exposed by the enrollment
   flow, and verify B cannot decrypt or apply the new state.
8. Enroll a fresh desktop C after revocation. Pull the post-rotation state and
   confirm C can open it while the revoked B remains excluded.
9. If identity rotation is part of this release candidate, run it only against a
   disposable vault after making a verified encrypted backup. Confirm old peers
   must enroll again and that the old relay data is not silently deleted.

## Evidence record

Each row needs the exact command or UI action, host, timestamp, result, retained
artifact path, and reviewer. `NOT RUN` is an evidence gap and does not close the
gate.

| Check | Evidence to retain | Result | Reviewer | Artifact |
| --- | --- | --- | --- | --- |
| Owner vault opens on desktop A | version, vault identity, screenshot or transcript | NOT RUN |  |  |
| B enrollment request and owner approval | device IDs and authority fingerprint | NOT RUN |  |  |
| A push and B pull | checkpoint ID, pull result, note and attachment hashes | NOT RUN |  |  |
| Offline edit and reconnect | before/after change IDs and conflict decision | NOT RUN |  |  |
| Cancellation | operation status and vault-open check | NOT RUN |  |  |
| Offline relay failure | error output and unchanged vault evidence | NOT RUN |  |  |
| Lock during sync | UI status and diagnostic review | NOT RUN |  |  |
| Revocation and forward epoch exclusion | revoked-device failure and post-rotation state | NOT RUN |  |  |
| Fresh re-enrollment | new device ID and successful pull | NOT RUN |  |  |
| Identity rotation, if in scope | verified backup, new authority, old-peer refusal | NOT RUN |  |  |

The automated `npm run recovery:drill` and synthetic native package transition
may be attached as supporting evidence, but neither is a substitute for this
two-desktop drill.
