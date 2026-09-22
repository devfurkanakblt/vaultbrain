# Vault Brain — Product Contract

## Positioning

Vault Brain is a local-first knowledge workspace whose default promise is:

> Faster to recall. Safer to trust.

It competes with Obsidian on the workflows people use every day—Markdown notes,
links, backlinks, search, properties, daily notes, graph exploration, extensions
and cross-device access—while making encryption and least-exposure AI access
part of the architecture instead of optional add-ons.

It is not a clone. Obsidian's public product principles emphasize durable open
formats, on-device storage, privacy and extensibility. We retain those valuable
properties, then raise the default security boundary: locked vault content,
search indexes and attachments must not be readable as plaintext at rest.

References:

- <https://obsidian.md/about>
- <https://obsidian.md/help/plugins>

## Non-negotiable product principles

1. **Local-first:** creating, editing, linking and searching work without an account or network.
2. **Encrypted by default:** note bodies, properties, attachments, indexes and recovery snapshots are encrypted at rest.
3. **Open escape hatch:** import and export standard Markdown, frontmatter and attachments without proprietary lock-in.
4. **Least exposure AI:** discovery, permission and resolution are separate operations; bulk vault access is never implicit.
5. **Fast at human scale:** common actions remain instant in a 100,000-note vault on reference hardware.
6. **Auditable extensibility:** plugins declare capabilities and run with explicit, revocable grants.
7. **No dark cloud dependency:** sync and AI features are optional layers, not prerequisites for opening the vault.

## Product surfaces

### Daily workspace

- Markdown editor with source and reading modes
- File tree, tabs, command palette and keyboard-first navigation
- Wikilinks, block links, embeds, tags, aliases and typed properties
- Backlinks, outgoing links, unlinked mentions and local graph
- Daily notes, templates, bookmarks, outline and recovery history
- Attachments, canvas/whiteboard and database-like property views

### Recall engine

- Instant title, property and full-text search
- Prefix, phrase, boolean, tag, date and property filters
- Ranked results with snippets
- Link and graph queries without rescanning every note
- Optional on-device semantic search, disabled by default

### AI boundary

- Safe catalog search without note bodies
- Per-agent grants scoped by vault, collection, note, field, action and expiry
- Explicit one-item resolution with audit trail
- Local-model path for zero-network workflows
- Redacted tool results and user confirmation policies for sensitive classes

**Delivered scope (0.2.0):** the MCP surface is key-value only — `list_keys`,
`find_key`, `resolve_key`, `store_note` and `find_notes_in_range`, over the
`*.kv.enc` categories and their value-free catalog. Grants are scoped by
file, key pattern, action and expiry. Note- and field-level scoping, and any
discovery or resolve path for Markdown documents, are not built: an agent
cannot reach a note created by `vbrain docs put` or the Obsidian importer.
The list above is the target contract; this paragraph is what ships today.
See [`CLI-AUDIT-2026-09-19.md`](CLI-AUDIT-2026-09-19.md), finding 10.

### Portability and ecosystem

- Lossless Markdown/frontmatter import and export
- Obsidian vault importer with link/attachment validation
- Versioned plugin API and signed packages
- Theme tokens and CSS customization
- Desktop only; encrypted sync stays desktop-to-desktop, so the passphrase
  never leaves a machine the owner controls and no hosted relay becomes
  mandatory

## Success measures

Performance budgets are measured after unlock on a reference 4-core laptop with
100,000 medium notes:

| Interaction                      | Target (p95) | Status                    |
| -------------------------------- | -----------: | ------------------------- |
| Open indexed note                |      < 50 ms | Met, gated on p95         |
| Title/quick switch search        |      < 30 ms | Met, gated on p95         |
| Full-text result first paint     |     < 100 ms | Met, gated on p95         |
| Backlink query                   |      < 50 ms | Met, gated on p95         |
| Incremental save acknowledgement |      < 20 ms | Met; gated on p50 and max |
| Cold unlock to usable shell      |        < 2 s | Met; gated on p50 of five |

"Gated" means `scripts/benchmark.mjs --assert` fails the build when the target
regresses, at the 1k, 10k and 100k tiers.

Two rows gate a statistic other than p95, and both say so rather than quietly
measuring something easier. The targets themselves are unchanged.

**Cold unlock** is one event per session, not a distribution, so it is measured
as five cold unlocks — each in its own process, because a second unlock in the
same process is a warm one — and the median is gated. One sample of an
operation that reads and decrypts a 140 MB index reported the CI runner as much
as the vault: fourteen consecutive samples ranged 1,087–2,074 ms around a
1.78 s median, and the 2,074 ms one failed a gate the other thirteen passed.

**Incremental save** is gated on the median and on the worst of 200 samples
(< 1 s), with p95 reported in every run and printed whenever it crosses the
20 ms target. A save is four durable file operations, and on a shared CI disk a
small fraction of fsyncs stall for hundreds of milliseconds: across thirty
measurements the median never left 2.2–4.9 ms while the worst sample ranged
4 ms to 493 ms, and p95 sat wherever that run's stall rate put it — twice over
20 ms on a save path that had not changed. More samples do not fix that; when
roughly one save in twenty stalls, p95 measures the stall rate. The median
gates the path with a sixfold margin, the worst sample gates catastrophe, and
the p95 target stays the number this contract is written in.

**Incremental save acknowledgement.** Phase 17 replaced the whole-index
rewrite on the save path with an encrypted change log in both cores, so the
cost of saving one note no longer grows with the vault. Measured after that
change:

| Vault         | TypeScript p95 | Rust (desktop) p95 |
| ------------- | -------------: | -----------------: |
| 1,000 notes   |     **3.5 ms** |        **4.95 ms** |
| 10,000 notes  |     **3.5 ms** |        **5.03 ms** |
| 100,000 notes |    **4.55 ms** |        **5.98 ms** |

Measured by the `performance-budgets` CI job on its Linux runner, 200 samples.
Before the change the same harness gave 16.6 ms at 1,000 notes and 141.7 ms at
10,000 for TypeScript, and 34.4 ms and 2,553 ms for the desktop core.

Both cores are flat in vault size rather than linear in it: a save costs the
same at 100,000 notes as at 1,000. The 1k and 10k tiers are gated on every
pull request; 100k runs on pushes to `main`, because it writes 100,000
encrypted objects per core.

Acknowledging a save before its data is durable is explicitly not an acceptable
way to meet this number.

Security release gates:

- No plaintext note bodies, attachment bytes or search tokens remain on disk after lock.
- Every privileged AI/plugin operation is denied by default and independently auditable.
- Crash-safe writes and recovery are covered by fault-injection tests.
- Cryptographic formats are versioned and have migration/recovery fixtures.
- A third-party security review is required before recommending real medical or financial data.

## Explicitly deferred

- Collaborative real-time editing before single-user sync is proven
- Public publishing before a safe, reviewable export pipeline exists
- Arbitrary unsandboxed community plugins
- Server-side plaintext search or server-held decryption keys
