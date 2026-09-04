# Vault Brain

> A least-exposure, `.env`-style personal data vault for the AI age.

> **Project direction:** this MVP is evolving into a desktop-first, local-first,
> encrypted knowledge workspace under the motto **“Faster to recall. Safer to
> trust.”** See [`docs/PRODUCT.md`](docs/PRODUCT.md),
> [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and
> [`docs/ROADMAP.md`](docs/ROADMAP.md).

> **Compatibility:** Vault Brain is the product and CLI name. Existing vault
> storage, cryptographic, plugin-signature, sync, and writer-lock identifiers
> remain immutable so data created by earlier releases stays readable.

**TL;DR (TR):** Obsidian gibi kişisel bilgi yönetimi araçları verini (sağlık, kimlik,
finans) düz metin olarak AI ajanlarına besliyor. `Vault Brain`, veriyi
şifreli anahtar-değer çiftleri olarak saklar; AI önce sadece anahtar adlarını
ve açıklamaları görür (değerleri değil), ihtiyaç duyduğu **tek** değeri talep
eder, ve her erişim denetim kaydına (audit log) yazılır.

## Why

Personal-knowledge-management tools are increasingly wired straight into AI
agents. The common pattern — a graph of free-text notes, fully readable by
whatever model touches it — means every query potentially exposes your whole
vault, not just the fact you asked about.

This project borrows a habit developers already trust: **`.env` files**. We
don't hand an agent a whole config file to "figure out" — we let it ask for
one variable at a time. `Vault Brain` applies the same discipline to
personal data.

## Two modes — read this before you wire it into anything

This is the most important section in the README.

|                                                 | Mode 1 — `sbrain get` (Direct)                | Mode 2 — `sbrain mcp` (AI-assisted)                                                                                                                                                                                                                    |
| ----------------------------------------------- | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Who's involved                                  | You, or a script. No LLM.                     | An AI agent (e.g. Claude) via MCP                                                                                                                                                                                                                      |
| Exposure                                        | Zero — value never enters any model's context | Not zero — content **does** pass through the calling model's context, both when you tell the agent something worth saving (`store_note`) and when it resolves a value back (`resolve_key`) — that's inherent to how a conversational agent has to work |
| What the agent sees without decrypting anything | N/A                                           | Key names + descriptions (`list_keys` / `find_key`), and note timestamps + tags (`find_notes_in_range`)                                                                                                                                                |
| Audit                                           | Logged                                        | Logged — writes and reads both, including denials                                                                                                                                                                                                      |
| Scoping                                         | N/A                                           | Required per-agent grants: which keys, which actions, for how long, how masked                                                                                                                                                                         |

Mode 2 is a deliberate trade-off, not a zero-exposure claim: you get an agent
that can capture and recall notes for you in natural language, in exchange
for that agent seeing what you tell it _in that moment_. What it does **not**
get is standing access to your whole vault — every other note stays
encrypted and out of its context until it specifically asks for that one
key, and every access (read or write) is logged. If you want a hard
guarantee that something never touches any LLM, keep using Mode 1 for it.

### Grants: narrowing Mode 2 to one agent, one slice, one answer

MCP access is fail-closed. A vault with no grant policy cannot start the MCP
server. Add a grant first; from then on an agent gets only what a live grant
gives it.

```bash
# A kitchen assistant that may read one key, in one category, for a week.
vbrain grant add claude-code \
  --scope "health:BLOOD_TYPE:discover,resolve:none" \
  --expires 7d --note "meal planning"

# The same agent may see that an IBAN exists and confirm the last four digits,
# but never read the whole thing.
vbrain grant add claude-code --scope "finance:IBAN:discover,resolve:partial"

# Anything under this grant waits for you before it is answered.
vbrain grant add research-bot --scope "*:*:discover:full" --confirm

vbrain grant list                  # every grant, active, expired or revoked
vbrain grant requests              # resolutions waiting on you
vbrain grant approve <id>          # single-use, expires in five minutes
vbrain grant revoke <id>           # effective on the agent's very next call
```

A scope reads `file:keys:actions[:redaction]`. Keys are exact names, a
`PREFIX*` glob, or `*`; actions are `discover`, `resolve` and `store`;
redaction is `none`, `partial` (mask identifiers, keep a short tail so the agent
can confirm a match) or `full` (return the value's _shape_ — "an IBAN, 26
characters" — and none of its characters).

Three properties are worth stating plainly:

- **The narrowest scope wins.** When several scopes cover one key, the
  strictest redaction is applied, so adding a broad convenience grant can never
  quietly unmask something you already chose to hide.
- **An approval is single-use.** One "yes" answers one resolution and is then
  spent; it never becomes a standing permission.
- **Redaction narrows exposure, it does not create a boundary.** A masked value
  still crosses into the model's context as a masked value. The vault owner
  pins the grant identity with `mcp --agent`; it is never accepted from tool
  request data. Anything that must never reach a model belongs in Mode 1.

Grants live encrypted in `grants.enc` inside the vault, so the agent names, the
scopes and the pending approvals are all unreadable without the passphrase.

## Format

```env
# @desc: Bir sonraki doktor kontrol tarihi
DOCTOR_NEXT_APPOINTMENT="2026-09-15"

# @desc: Kan grubu
BLOOD_TYPE="0 Rh+"
```

- Files live as `vault/<name>.kv.enc` — AES-256-GCM encrypted, scrypt-derived
  key from your passphrase. The plaintext above never touches disk.
- Key names and `@desc` comments are copied into encrypted `schema.enc` by
  `sbrain index`; values are never included. Never put sensitive
  information in a description — the tool can't enforce that for you.

## Quickstart

The npm package is named `vault-brain`; installing it globally exposes the
short, project-specific `vbrain` command:

```bash
npm install --global vault-brain
vbrain --help
```

For local development from this repository:

```bash
npm install
npm run build

export VBRAIN_PASSPHRASE="use-a-real-passphrase-here"

node dist/cli.js --vault ./vault/personal init
node dist/cli.js --vault ./vault/personal add health 'DOCTOR_NEXT_APPOINTMENT="2026-09-15"' --desc "Bir sonraki doktor kontrol tarihi"
node dist/cli.js --vault ./vault/personal index

# Mode 1 — direct, zero-exposure
node dist/cli.js --vault ./vault/personal get health DOCTOR_NEXT_APPOINTMENT

# fast path — search the value-free schema
node dist/cli.js --vault ./vault/personal search "doktor"

# freeform journal entry (dev/testing — normally an agent calls store_note for you)
node dist/cli.js --vault ./vault/personal note health "Check-up yaptırdım, sonuçlar normal." --desc "Doktor ziyareti notu"

# browse notes by date after unlocking the encrypted catalog
node dist/cli.js --vault ./vault/personal timeline --category health

# Mode 2 — start the MCP server for an agent (Claude Code, etc.)
node dist/cli.js --vault ./vault/personal mcp --agent claude-code
```

A working demo vault (dummy data only) is checked in at `vault/example/`.

### Unlocking, locking and the storage format

```bash
# Prove the passphrase, and optionally hand it to the OS credential store
node dist/cli.js --vault ./vault/personal unlock --remember

# Which store is in use, and what this vault currently holds
node dist/cli.js --vault ./vault/personal keychain-status

# Explicitly end it: the remembered passphrase is forgotten
node dist/cli.js --vault ./vault/personal lock

# Rewrite pre-versioning files in the current encrypted envelope
node dist/cli.js --vault ./vault/personal migrate

# Re-wrap the keyring under a new passphrase, at the current KDF cost
node dist/cli.js --vault ./vault/personal passphrase change
```

Encrypted files carry an explicit envelope version, cipher name and the exact
scrypt parameters they were written with, and those header fields are
authenticated together with the ciphertext — an attacker cannot edit the
recorded cost factor to weaken the next derivation without the tag check
failing. Files written before versioning existed still open, and `vbrain
migrate` upgrades them in place. `test/fixtures/` holds vaults written by
earlier formats so a future change has to prove it can still read them.

- `vbrain passphrase change` — change the vault passphrase. The keyring is
  re-wrapped at the current key-derivation cost, so this is also how a vault
  created under an older, cheaper setting raises its work factor. Nothing is
  re-encrypted, and it takes the same time on a 100,000-note vault as on an
  empty one. Add `--allow-same-passphrase` to raise the cost without changing
  the passphrase. It never consults the OS credential store for the current
  passphrase, so running it unattended requires both `VBRAIN_PASSPHRASE` (the
  current passphrase) and `VBRAIN_NEW_PASSPHRASE` (the replacement) to be set.
  If this vault has a passphrase remembered in the OS credential store, it is
  updated to the new one.

## Encrypted Markdown documents

The new document engine stores Markdown notes as individually encrypted objects
with stable IDs and revisions. Its search/link index is encrypted too; titles,
note bodies, tags and search tokens are not written to disk as plaintext.

```bash
# Create two linked notes
node dist/cli.js --vault ./vault/personal docs put Projects/Alpha \
  --title "Project Alpha" \
  --body "Launch plan owned by [[People/Ada]]. #project/active"

node dist/cli.js --vault ./vault/personal docs put People/Ada \
  --title "Ada" \
  --body "Works on [[Projects/Alpha]]. #person"

# Fast encrypted-index recall and knowledge links
node dist/cli.js --vault ./vault/personal docs search "launch tag:project/active"
node dist/cli.js --vault ./vault/personal docs backlinks Projects/Alpha
node dist/cli.js --vault ./vault/personal docs links Projects/Alpha

# Directly decrypt one note, or emit portable Markdown with frontmatter
node dist/cli.js --vault ./vault/personal docs get Projects/Alpha
node dist/cli.js --vault ./vault/personal docs get Projects/Alpha --with-frontmatter
```

Use `docs list`, `docs import`, `docs rebuild-index`, and `docs remove` for the
remaining document lifecycle operations. These are direct CLI operations; no
model sees their output unless you explicitly pipe it into one.

Revision recovery and encrypted attachments are built in:

```bash
node dist/cli.js --vault ./vault/personal docs history Projects/Alpha
node dist/cli.js --vault ./vault/personal docs restore Projects/Alpha 1
node dist/cli.js --vault ./vault/personal docs unresolved
node dist/cli.js --vault ./vault/personal docs rename Projects/Alpha Archive/Alpha

node dist/cli.js --vault ./vault/personal docs attach ./diagram.png --mime image/png
node dist/cli.js --vault ./vault/personal docs attachments
node dist/cli.js --vault ./vault/personal docs attachment-get <id> ./restored-diagram.png
```

Semantic recall is available as an explicit, on-device path and never changes
ordinary full-text search. With an embedding model already available in a local
Ollama instance:

```bash
node dist/cli.js --vault ./vault/personal docs semantic-search \
  "where did I write about fixing a car?" \
  --model nomic-embed-text \
  --url http://127.0.0.1:11434
```

The command unlocks the vault, sends at most 16,000 characters per note to the
chosen local model, and keeps its revision-aware vector index only in process
memory. `--max-characters`, `--min-score`, and `--limit` tune that boundary and
the result set. Model URLs must be literal HTTP loopback addresses and redirects
are refused; a remote model cannot be enabled accidentally. Locking clears the
vectors, and successful semantic searches add a value-free audit event. The
exported `OllamaLocalModelAdapter` also provides a non-streaming local
`generate()` boundary for host integrations. Treat the local model process as
trusted: it receives the bounded plaintext needed for the operation.

An existing Obsidian vault can be migrated as one checked operation. Markdown
and frontmatter are preserved, ordinary files become content-addressed encrypted
attachments, and JSON Canvas boards bind to the imported note/attachment IDs.
Hidden directories such as `.obsidian` and `.git` are skipped by default.

```bash
node dist/cli.js --vault ./vault/personal docs import-obsidian ./MyObsidianVault \
  --report ./obsidian-integrity-report.json
```

The report records malformed notes/canvases, skipped symbolic links, ambiguous
attachment names, unresolved wikilinks and missing local Markdown links. The
report itself contains source paths and is plaintext, so store or remove it as
you would any other migration log. The encrypted destination must be outside
the source vault, preventing an import from recursively consuming its own
output. Use `--include-hidden` only when hidden source content is intentional.

### Performance gates

```bash
npm run benchmark        # 1,000 notes  — the everyday gate
npm run benchmark:10k    # 10,000 notes
npm run benchmark:100k   # 100,000 notes (slow: it writes 100k encrypted objects)
```

Each builds a disposable encrypted corpus and enforces the p95 budgets from
[`docs/PRODUCT.md`](docs/PRODUCT.md) at that size: unlock, quick-switch,
full-text search, note open and backlinks. The gates are measured, not
aspirational — a tier's numbers are only raised with a measurement and a
reason, never to turn a red run green.

Building the larger tiers is what surfaced the work behind them. Three write
and resolve paths scanned the whole vault (quadratic during a bulk import), and
search re-normalized every note body inside the query loop, so a 10,000-note
corpus took minutes to build and 80 ms to search. With reverse lookups in the
index and search text normalized once per session, the same corpus builds in
seconds and answers a full-text query in about 3 ms p95.

## Native desktop workspace

The repository now includes a Tauri 2 desktop application. Its React webview has
no direct filesystem or key access; forty-two capability-scoped commands cross into
the Rust core for unlock, lock, the whole note lifecycle, search, backlinks,
value-minimized graph topology, typed property rows, templates and daily notes,
encrypted canvases, content-addressed attachments and sandboxed plugins. The
session key stays in Rust memory and is zeroized on lock.

```bash
# Browser-backed UI development (uses a safe in-memory demo vault)
npm run desktop:dev

# Full native application against encrypted vault files
npm run tauri:dev

# Produce signed-ready MSI and NSIS installer artifacts
npm run tauri:build

# Faster local release check without installer generation
npm run tauri:build -- --no-bundle
```

The current workspace includes a lock screen, file tree, tab strip, CodeMirror
Markdown editor, reading view, split pane, properties, outline, backlinks,
encrypted search, quick switcher, command palette, keyboard shortcuts, theme
editor, local knowledge graph, filterable property table, spatial canvas and
attachment library. Dirty notes are persisted before
navigation, before a tab closes and before lock, so the 700 ms autosave window
cannot discard an edit.

| Shortcut                                  | Action                                                                    |
| ----------------------------------------- | ------------------------------------------------------------------------- |
| `Ctrl+O`                                  | Quick switcher — title, path or alias; `alt+↵` opens it in the split pane |
| `Ctrl+K`                                  | Command palette                                                           |
| `Ctrl+Shift+F`                            | Search the encrypted vault                                                |
| `Ctrl+\`                                  | Open the current note in the split pane                                   |
| `Ctrl+W`                                  | Close the active tab (saving it first if dirty)                           |
| `Ctrl+D`                                  | Open (or first create) today's daily note                                 |
| `Ctrl+N` / `Ctrl+S` / `Ctrl+E` / `Ctrl+L` | New note · save · write/read · lock                                       |

A note's whole life is available from the document toolbar and the command
palette, not only from the CLI:

- **Move or retitle.** A note keeps its ID, so its history and every link that
  resolved to it by ID survive the move. Wikilinks that spelled out the old
  title stay as written and become unresolved mentions, which the context panel
  can relink in one click.
- **Delete and restore.** Deleting archives the live revision before unlinking
  the encrypted object, so the note is still recoverable from _Restore a deleted
  note_ in the command palette.
- **History.** Every revision is a separate encrypted object. The history dialog
  decrypts one at a time to read, and restoring writes the old content forward
  as a new revision rather than rewinding the counter, so nothing already
  archived is invalidated.
- **Templates and daily notes.** Any note tagged `template` shows up in _New
  note from a template_, with the same `{{title}}`, `{{path}}`,
  `{{date:YYYY-MM-DD}}`, `{{time:HH:mm}}` and custom variables the CLI renders.
  `Ctrl+D` opens today's daily note, creating it only the first time.

The sidebar's _Canvas_ and _Files_ views round out the workspace without ever
handing the webview a file path:

- **Canvas.** A board of freeform text cards, group frames, web links, and file
  nodes that point at a vault note or an encrypted attachment by id. Nodes are
  dragged on a fixed surface, connected with directed edges, and written back as
  one encrypted canvas document under the same stale-revision check that guards
  notes — a canvas edited elsewhere is rejected rather than overwritten. Edits
  autosave 900 ms after the last change, and a node whose target has since been
  deleted renders as a missing reference rather than disappearing.
- **Files.** The attachment library adds files by encrypting their bytes in the
  Rust core, and decrypts one only when it is previewed or downloaded. Images,
  audio, video, PDFs and text preview inline from an object URL that is revoked
  as soon as the preview closes.

### Plugins, without Obsidian's trust model

An Obsidian plugin runs as arbitrary Node inside the app: it can read your whole
filesystem, and no amount of encryption at rest survives that. Here a plugin is
a manifest and one JavaScript file, and its reach is finite and declared.

```json
{
  "manifestVersion": 1,
  "id": "word-count",
  "name": "Word count",
  "version": "0.2.0",
  "description": "Shows how many words the open note holds",
  "author": "example",
  "capabilities": ["notes:read", "ui:panel", "commands"]
}
```

```bash
vbrain plugins install ./plugin.json ./main.js   # installs, but leaves it off
vbrain plugins list                              # what is installed and what it may reach
vbrain plugins enable word-count
vbrain plugins remove word-count                 # takes the plugin's settings with it
```

Publishers can bind the manifest and exact source bytes into one Ed25519
package. The public key travels in the signature; the private key never enters
the vault:

```bash
vbrain plugins keygen ./publisher.private.pem
vbrain plugins sign ./plugin.json ./main.js \
  --key ./publisher.private.pem --out ./plugin.signed.json
vbrain plugins install ./plugin.signed.json ./main.js

# Signed-only operation and local emergency revocation
vbrain plugins restricted on
vbrain plugins revoke-signer word-count
vbrain plugins policy
vbrain plugins restore-signer <64-character-key-id>
```

Restricted mode refuses unsigned installation and prevents already-installed
unsigned packages from running. Revocation is keyed by the SHA-256 fingerprint
of the publisher's Ed25519 public key, so every installed package from that key
stops on the next plugin refresh; the encrypted policy travels with the vault.
The first accepted signing key is pinned to that plugin ID, and an update from
a different key is refused until the old plugin is explicitly removed.
Signatures prove that the source and manifest have not changed since the holder
of that key signed them. They do **not** prove who owns a self-declared key, so
the first trust decision still belongs to the person installing the plugin.

The capabilities are `notes:metadata`, `notes:read`, `notes:write`, `search`,
`canvas:read`, `canvas:write`, `attachments:read`, `commands`, `ui:notice`,
`ui:panel` and `storage`. There is deliberately no network capability: it is not
offered and cannot be requested. A manifest naming a capability this build does
not know is **refused**, not trimmed — installing it would mean showing you a
list that understates its reach.

Three things make that list mean something:

- **It runs in a worker with no DOM, no filesystem and no network.** `fetch`,
  `XMLHttpRequest`, `WebSocket` and `importScripts` are removed before the
  plugin's first line runs, and the plugin is _loaded_ as a worker script rather
  than `eval`'d — so the app never has to grant `'unsafe-eval'` to anything.
- **Every call is checked against the manifest.** A method that isn't in the
  capability table has no capability and is refused, so a host method added
  without one is unreachable rather than accidentally public.
- **The Rust command layer is the actual boundary**, and it does not trust the
  worker or the host. A plugin that escaped the sandbox entirely would still
  hold only the capabilities the webview itself has — and the vault key never
  enters the webview at all.

What this does _not_ do is protect you from a plugin abusing what you granted.
`notes:read` means it reads your notes. The defence there is the capability list
you approve before it runs, and the switch that turns it off.

Plugins and the restricted/revocation policy live encrypted in the vault like
everything else, so they travel with it, and one cannot be swapped on disk
without the passphrase. Both the TypeScript CLI core and the Rust desktop core
verify the same length-prefixed signature payload before a signed package is
accepted or loaded.

Two session guards protect an unlocked window you walked away from:

- **Inactivity lock.** The vault re-locks after a configurable idle window —
  1, 5 (default) or 15 minutes, or disabled — set from the sidebar's _Auto-lock_
  control. Keystrokes, pointer input and scrolling reset it; the lock screen
  then says why it locked.
- **Self-clearing clipboard.** Copying a note or a single property value marks
  the clipboard as workspace-owned and rewrites it to empty 30 seconds later,
  and again on lock — but only if the clipboard still holds exactly what was
  copied, so it never wipes something you copied elsewhere in the meantime. If
  the webview denies clipboard read access, the copy still works and the
  workspace tells you it cannot take the value back.

The file tree and the property view are windowed: they keep a viewport's worth
of rows in the document no matter how many notes the vault holds, so a
40,000-row folder costs the same to render as a 40-row one. (The interface is
bounded; the encrypted core's own 10k/100k budgets are still only measured
against the 1,000-note benchmark corpus.)

The theme editor — sidebar palette icon, or _Customize theme_ in the command
palette — derives the whole interface from four colours (chrome, surface, ink,
accent) plus a reading size and typeface, with four presets to start from. It
shows the WCAG contrast ratio for ink-on-surface and accent-on-chrome as you
edit and flags a combination that drops below AA. The theme is a per-device
preference stored in `localStorage`; it never enters the encrypted vault.

Obsidian-style YAML frontmatter, safe templates and daily notes are supported:

```bash
# Mark any encrypted note as a template and use familiar variables such as
# {{title}}, {{date:YYYY-MM-DD}}, {{time:HH:mm}} and custom {{name}} values.
node dist/cli.js --vault ./vault/personal docs from-template \
  Templates/Meeting Meetings/Kickoff \
  --title "Kickoff" --date 2026-08-30 --var client=Acme

# Idempotent: the first call creates the note; later calls open the same note.
node dist/cli.js --vault ./vault/personal docs daily 2026-08-30 \
  --folder Journal --template Templates/Daily
```

Imported Markdown accepts nested YAML properties, block scalars, tag/alias lists
and common scalar values. YAML aliases are deliberately disabled and duplicate or
prototype-shaping keys are rejected before anything enters encrypted storage.

### Wiring into Claude Code / an MCP client

```json
{
  "mcpServers": {
    "vault-brain": {
      "command": "node",
      "args": [
        "/absolute/path/to/secondbrain-vault/dist/cli.js",
        "--vault",
        "/absolute/path/to/vault/personal",
        "mcp",
        "--agent",
        "claude-code"
      ],
      "env": {
        "SBRAIN_PASSPHRASE": "use-a-real-passphrase-here"
      }
    }
  }
}
```

Once connected, you don't type CLI commands yourself — you just talk. Tell
the agent "bugün doktora gittim, tahliller normaldi, 6 ay sonra tekrar
kontrol" and it calls `store_note` on your behalf. Ask "bir sonraki doktor
kontrolüm ne zaman?" and it calls `find_key` → `resolve_key`. The CLI's own
`add`/`note`/`get` commands still exist, but they're there for scripting and
testing — not the intended everyday interface.

The server exposes five tools:

| Tool                  | Touches values?           | Gets audited? |
| --------------------- | ------------------------- | ------------- |
| `list_keys`           | No                        | No            |
| `find_key`            | No                        | No            |
| `find_notes_in_range` | No — timestamps/tags only | No            |
| `store_note`          | Yes — that's the point    | Yes           |
| `resolve_key`         | Yes                       | Yes           |

Under a grant policy the three value-free tools return only the keys that
agent may discover, `store_note` needs a `store` action, and `resolve_key`
additionally records who asked, under which grant, how much came back, and
whether the answer was allowed, denied or held for approval.

`store_note` covers both shapes: pass an explicit `key` for a fact that
should overwrite itself (like `IBAN`), or omit it for a freeform journal
note — it gets an auto-generated, timestamp-prefixed key (`NOTE_20260830_...`)
so entries stack up instead of colliding. `find_notes_in_range` then lets an
agent browse "what did I note about health in August" using only that
timestamp, with zero decryption — the note-taking equivalent of Obsidian's
daily-notes view, but without reading your notes to build it.

## Encrypted sync protocol — Phase 6 foundation

Sync remains transport-independent: an append-only encrypted change log with
per-device chains, causal parents and explicit conflict inspection. Exported
JSON contains only keyed opaque IDs and AES-GCM ciphertext. Enrolled devices
sign every new change with a separate Ed25519 key; the owner-signed encrypted
registry pins device certificates and revocation sequence cutoffs.
Owner-signed freshness checkpoints commit to the verified causal heads and
change count. An authenticated self-hosted relay stores only opaque immutable
ciphertext, with request, storage and object-count quotas.

Pass `--sync-device <uuid>` to a document or plugin command to capture its note,
canvas, attachment, plugin-package or plugin-policy mutation automatically. A
synchronized session also records an encrypted per-object application cursor,
so conflict-free remote changes can be replayed into the real vault exactly
once.

```bash
# Initialize enrollment and pin the returned authority fingerprint.
sbrain --experimental-trusted-sync sync devices init "Owner laptop" \
  --device-id <device-id>

# On a securely bootstrapped second device, create a proof-of-possession request.
sbrain --experimental-trusted-sync sync devices request "Travel laptop" \
  --device-id <second-device-id> > enrollment-request.json

# The owner approves it, then transfers the newer encrypted registry back.
sbrain --experimental-trusted-sync sync devices enroll enrollment-request.json
sbrain --experimental-trusted-sync sync devices export > device-registry.json
sbrain --experimental-trusted-sync sync devices import device-registry.json

# Removal is owner-signed at the last device sequence observed locally.
sbrain --experimental-trusted-sync sync devices revoke <second-device-id>

# Record revision 1 of one logical object.
sbrain --experimental-trusted-sync sync append <device-id> note <note-id> put \
  --revision 1 --value '{"title":"Plan","body":"private"}'

# Exchange opaque envelopes through files/stdout.
sbrain --experimental-trusted-sync sync export > changes.json
sbrain --experimental-trusted-sync sync import changes.json

# Validate the complete DAG, list/inspect concurrent heads, then apply a clean one.
sbrain --experimental-trusted-sync sync verify
sbrain --experimental-trusted-sync sync conflicts
sbrain --experimental-trusted-sync sync resolve note <note-id>
sbrain --experimental-trusted-sync sync apply note <note-id>

# Resolve manually by naming one preserved head. Plugin-policy conflicts can
# instead use --safe, which only unions revocations and enables restricted mode.
sbrain --experimental-trusted-sync --sync-device <device-id> \
  sync resolve note <note-id> --head <change-id>
sbrain --experimental-trusted-sync --sync-device <device-id> \
  sync resolve vault plugin-policy --safe

# Example automatically captured edit.
sbrain --experimental-trusted-sync --sync-device <device-id> \
  docs put Plans/Launch.md --body "Ready"

# Publish a known-good checkpoint and push it with the encrypted change log.
export SBRAIN_RELAY_TOKEN='<at-least-32-random-bytes>'
sbrain --experimental-trusted-sync sync checkpoint create
sbrain --experimental-trusted-sync sync relay push https://relay.example

# First contact pins fingerprints obtained through a trusted channel.
sbrain --experimental-trusted-sync --vault ./restored-vault \
  sync relay pull https://relay.example \
  --authority <owner-authority-sha256> \
  --checkpoint <owner-checkpoint-sha256>
```

Unresolved heads fail before live storage is touched. Plugin package bytes and
the fail-closed plugin policy are portable, while plugin storage and the local
enabled/disabled execution choice never enter the sync log; a received plugin
is always installed disabled. Synchronized attachment snapshots currently
share the 8 MiB change limit (about 6 MiB of raw bytes); resumable chunked
transport for larger blobs and independently witnessed freshness remain
Phase 6 work. The relay is not key escrow: first-device recovery needs an
encrypted vault backup containing the original key-derivation metadata. A
normal device clone must never carry another device's `documents/sync/identity`
directory; private identity keys are local-only and absent from sync exports.

Revoking a device rotates the content key: the registry advances to a new epoch,
a fresh random content key is wrapped to each remaining device's X25519 key, and
the revoked device receives no wrap. Rotation is forward-only. A revoked device
keeps the epoch keys it already held and can still decrypt every change written
before the rotation; what it loses is everything written afterwards, including
whatever the relay accumulates from then on. Recovering historical plaintext
still only takes the passphrase and an encrypted vault backup — the passphrase
remains the security boundary.

See the [sync protocol design](docs/superpowers/specs/2026-08-31-encrypted-sync-change-protocol-design.md)
and [relay operations guide](docs/SYNC-RELAY.md).

The on-disk format is frozen at 1.0 — see [`docs/FORMAT-1.0.md`](docs/FORMAT-1.0.md).
The product itself remains pre-1.0 pending independent review.

## The "fast find" layer

`sbrain index` rebuilds encrypted `schema.enc` — key names + descriptions, no values —
across the whole vault. `sbrain search` / the `find_key` MCP tool run a fuzzy
match over that small, safe file instead of decrypting and scanning every
vault file. This is the speed win over an Obsidian graph traversal: lookup
cost scales with the number of _keys_, not the size of your notes.

## Threat model / honesty notes

- Encryption protects data **at rest**. Once `vbrain get` or `resolve_key`
  decrypts a value, it's plaintext in that process's memory / stdout — treat
  it like any other secret in a terminal.
- The passphrase prompt is masked on a real terminal, and `sbrain unlock
--remember` can hand the passphrase to the OS credential store instead
  (Windows DPAPI, macOS Keychain, libsecret on Linux). Only the Windows path is
  exercised by this project's tests, because that is the platform it is
  developed on. An OS credential store protects the secret from other users and
  other machines — not from code already running as you.
- `VBRAIN_PASSPHRASE` still wins over both, which is what makes scripts and MCP
  work; an environment variable is visible to your own processes, so prefer the
  credential store for interactive use.
- Nothing here stops a user (or a misconfigured agent with general filesystem
  tools) from reading `vault/*.kv.enc` directly — they'll just get ciphertext,
  which is the actual protection. The real enforcement point is keeping an
  agent's filesystem access scoped away from the vault directory and routed
  through the MCP tools instead.
- This is an MVP. It has not been audited. Don't put real medical or
  financial identifiers in it yet — validate the model with dummy data first.
- Rotation is forward-only. A revoked device keeps the epoch keys it already
  held and can still decrypt every change written before the rotation; what
  it loses is everything written afterwards, including whatever the relay
  accumulates from then on. Recovering historical plaintext still only takes
  the passphrase and an encrypted vault backup — the passphrase remains the
  security boundary.

## Roadmap

Phases 0–5 are implemented. Phase 6 now has the encrypted immutable change log,
live note/canvas/attachment/plugin capture and application, owner-signed device
enrollment and removal with automatic epoch content-key rotation on revocation,
owner-signed freshness checkpoints, an authenticated opaque self-hosted relay,
an automated recovery drill, a frozen 1.0 on-disk format with committed
conformance fixtures, and read-only desktop sync status. Desktop-driven sync
mutation (enrollment, revocation, relay push/pull from the app), resumable
chunked transport for attachments larger than the change limit, and the
independent security audit remain open — see
[`docs/AUDIT-SCOPE.md`](docs/AUDIT-SCOPE.md) for the audit readiness package.
iOS/Android clients are out of scope: Vault Brain stays local-first with
optional self-hosted sync rather than putting the passphrase, and a hosted
relay dependency, on a phone. The maintained checklist is in
[`docs/ROADMAP.md`](docs/ROADMAP.md).

## License

MIT
