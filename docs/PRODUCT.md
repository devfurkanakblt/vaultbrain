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

| Interaction                      | Target (p95) |
| -------------------------------- | -----------: |
| Open indexed note                |      < 50 ms |
| Title/quick switch search        |      < 30 ms |
| Full-text result first paint     |     < 100 ms |
| Backlink query                   |      < 50 ms |
| Incremental save acknowledgement |      < 20 ms |
| Cold unlock to usable shell      |        < 2 s |

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
