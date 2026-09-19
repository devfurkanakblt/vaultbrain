# Context format decision — 2026-09-19

A proposal to replace Markdown with a purpose-built `.ctx` context format was
evaluated against this repository. **The file format is rejected. Three of its
semantics are adopted as roadmap candidates, carried on the frontmatter and
property machinery that already exists.**

This is a decision record, not a plan. Nothing here is scheduled; the adopted
items are candidates for Phase 18 and are listed as such at the end.

## The proposal

A human-readable, parser-exact file format for LLM context, whose ideas were:

- Every fact has an identity and is referenced rather than repeated
  (`[DB001] database` … `database: ->DB001`)
- `scope` blocks, so retrieval loads one subsystem's facts and not the rest
- Priority tags (`@critical`, `@low`) a compiler drops when the context budget
  tightens
- Temporal validity (`valid-from`, `valid-until`, `replaced-by`) so a model is
  not handed a superseded decision
- A `facts` / `note` split, so "which database?" does not ship the prose
- A three-layer architecture: `.ctx` file → context AST → retrieval and a
  budget-aware context compiler → model-specific prompt

## Decision

Rejected as an on-disk format. Adopted as semantics: **temporal supersession**,
**priority**, and **budget-aware assembly**.

## Rationale

### 1. The proposal's own conclusion argues against the format

The source discussion ends by locating the gain somewhere else entirely:
optimisation belongs in removing redundant information, reducing repetition,
correct chunking, and retrieval that pulls only the relevant sections into
context — not in converting `.md` to another format. Its specific advice for
this project was a `Markdown → semantic chunks → metadata → relevance retrieval
→ context assembly` pipeline. That is a retrieval argument, not a format one.

### 2. It contradicts two non-negotiable product principles

[`docs/PRODUCT.md`](PRODUCT.md) principle 3 is an "open escape hatch: import and
export standard Markdown, frontmatter and attachments **without proprietary
lock-in**". A bespoke `.ctx` format is proprietary lock-in by construction.

Principle 4 is "least exposure AI: bulk vault access is never implicit". The
`.ctx` premise is that a large context dump is going to happen, so it should be
made cheaper and more precise. This product's thesis is that the dump does not
happen: discovery reads a value-free catalog and `resolve_key` returns one
scalar. Optimising the cost of a dump optimises an operation the AI boundary
deliberately does not offer.

### 3. A new encrypted artifact family is expensive here, and we have the receipt

Adding a format to this codebase is not "write a parser". Every durable
encrypted artifact must be declared in the frozen inventory in
[`src/format-version.ts`](../src/format-version.ts) with its AAD
domain-separation string, its `reads`/`writes` versions and its re-key
behaviour; `planRekey` in [`src/keyring-rekey.ts`](../src/keyring-rekey.ts)
must classify it, and refuses the whole vault when it cannot. Backup/restore,
sync change types, import/export round-trip and the format-conformance tests
follow.

That cost is not hypothetical. Finding 5 of
[`docs/CLI-AUDIT-2026-09-19.md`](CLI-AUDIT-2026-09-19.md) is exactly this
failure for a single forgotten file: because `schema.enc` was never added to the
inventory, an ordinary `add` + `index` vault cannot be re-keyed at all
(`exit 1: Refusing to re-key: cannot classify schema.enc`). One missed file
makes a vault un-re-keyable. A whole new artifact family multiplies that
surface.

### 4. Encryption removes the format's main benefit

Half of `.ctx`'s appeal is that a person opens the file in an editor and reads
it while a parser reads it exactly. In this vault every artifact is an encrypted
envelope; nobody opens the file. The readability argument does not survive
contact with the storage model.

## What the vault already has

| `.ctx` idea | Status here |
|---|---|
| `facts` / `note` split | Present — KV entries (`src/store.ts`) and documents (`src/documents.ts`) are separate subsystems. Not unified at the MCP boundary; see CLI-AUDIT finding 10. |
| Identity and reference | Present for documents — stable note ids, `[[wikilinks]]`, and the `linkSources` / `backlinks` / resolved-source index. Absent for KV entries. |
| `scope` | Partial — categories, tags and paths, plus grant scopes. Grant scope is a *permission* boundary, not a *retrieval budget*. |
| Priority | Absent. |
| Temporal validity | Absent. Revision history and `createdAt`/`updatedAt` exist; "this fact supersedes that one" is not modelled. |
| Budget-aware assembly | Absent. |
| Model-specific serializer | Absent, and out of scope: it would put prompt construction inside a storage product. |

## What we adopt instead

All three ride on typed properties, which are already normalised, indexed and
searchable (`NoteDocument.properties`, and `fields.properties` in the search
scorer).

1. **Temporal supersession** — `valid-from`, `valid-until` and `supersedes` as
   reserved frontmatter properties, with index fields and search filters. This
   is the strongest idea in the proposal because it targets a real retrieval
   failure: finding the right document and returning information that is no
   longer true. No format change; additive frontmatter only.
2. **Priority** — a `priority` property weighted by the search ranker.
3. **Budget-aware assembly** — belongs at the MCP layer, not in storage. If
   grant-controlled Markdown discovery and resolve tools are ever added
   (CLI-AUDIT finding 10, currently answered by narrowing the documented scope
   to KV-only), a `budget` parameter belongs on those tools.

Items 1 and 2 are nearly free once the search parser gains the `[key:value]`
property filter that CLI-AUDIT finding 9 calls for: `-[valid-until:*]` then
excludes expired facts with no additional machinery.

## What we explicitly do not adopt

- A `.ctx` file format, or any new on-disk artifact family, for this purpose.
- Tokenizer-targeted abbreviation (`p:vault`, `db:pg`). The source discussion
  rejects this too, on readability grounds.
- Model-specific prompt serialisation.

## Status

Not scheduled. Items 1–3 are Phase 18 candidates and are not counted against any
open phase in [`docs/ROADMAP.md`](ROADMAP.md). Items 1 and 2 should be sequenced
after CLI-AUDIT finding 9, which builds the property filter they depend on.
