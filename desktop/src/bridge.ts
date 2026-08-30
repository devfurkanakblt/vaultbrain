import { invoke } from "@tauri-apps/api/core";
import type { Backlink, Bookmark, KnowledgeGraph, NoteDocument, NoteSummary, PropertyRow, SavedView, SearchHit, UnlinkedMention, VaultInfo, WorkspaceState } from "./types";

const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

const now = new Date().toISOString();
let demoNotes: NoteDocument[] = [
  {
    version: 1,
    id: "0d17d6a9-55af-4cd3-b46a-9c76067c1934",
    path: "Atlas/Product principles.md",
    title: "Product principles",
    aliases: ["North star"],
    tags: ["product", "evergreen"],
    properties: { status: "living", confidence: 0.92, owner: "You" },
    createdAt: now,
    updatedAt: now,
    revision: 7,
    body: "# Product principles\n\nOur tools should feel **instant**, remain useful without a network, and reveal only what the current task needs.\n\n## Operating constraints\n\n- Local-first by construction\n- Encryption is the default, not a toggle\n- AI access is narrow, explicit, and audited\n\nThis connects to [[Security/Least exposure]] and [[Roadmap/Desktop shell]].",
  },
  {
    version: 1,
    id: "b161a8df-8a4c-4564-bacd-26b65d781b62",
    path: "Security/Least exposure.md",
    title: "Least exposure",
    aliases: [],
    tags: ["security"],
    properties: { status: "reviewed", threatModel: "local-first" },
    createdAt: now,
    updatedAt: now,
    revision: 3,
    body: "# Least exposure\n\nDiscovery and resolution are separate capabilities. A model can locate a key without reading its value.\n\nBacklink: [[Atlas/Product principles]].",
  },
  {
    version: 1,
    id: "69b01afd-38dc-4f61-ad95-3b24933e7296",
    path: "Journal/2026/08/30.md",
    title: "2026-08-30",
    aliases: [],
    tags: ["daily"],
    properties: { date: "2026-08-30" },
    createdAt: now,
    updatedAt: now,
    revision: 1,
    body: "# 2026-08-30\n\nThe desktop shell begins today. Keep it calm, dense, and unmistakably ours.",
  },
];

let demoViews: SavedView[] = [];
let demoWorkspace: WorkspaceState = { version: 1, bookmarks: [], layouts: [] };

const WIKILINK = /\[\[[^\]]*\]\]/gu;

function mentionPattern(name: string) {
  return new RegExp(`(?<![\\p{L}\\p{N}_])(${name.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")})(?![\\p{L}\\p{N}_])`, "giu");
}

/** Demo-mode mirror of the Rust scan: whole words, never inside a wikilink. */
function demoMentions(body: string, name: string) {
  const masked = body.replace(WIKILINK, (match) => " ".repeat(match.length));
  return [...masked.matchAll(mentionPattern(name))];
}

/** Rewrite only the text between wikilinks, so existing links stay untouched. */
function outsideLinks(body: string, rewrite: (segment: string) => string) {
  return body
    .split(/(\[\[[^\]]*\]\])/gu)
    .map((part, index) => (index % 2 === 1 ? part : rewrite(part)))
    .join("");
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  return invoke<T>(command, args);
}

/** Demo-mode stand-in for the Rust label propagation: connected components. */
function demoClusters(nodeIds: string[], edges: KnowledgeGraph["edges"]) {
  const neighbours = new Map<string, string[]>(nodeIds.map((id) => [id, []]));
  for (const edge of edges) {
    neighbours.get(edge.source)?.push(edge.target);
    neighbours.get(edge.target)?.push(edge.source);
  }
  const groups: string[][] = [];
  const seen = new Set<string>();
  for (const id of nodeIds) {
    if (seen.has(id)) continue;
    const group: string[] = [];
    const queue = [id];
    seen.add(id);
    while (queue.length) {
      const current = queue.shift()!;
      group.push(current);
      for (const next of neighbours.get(current) ?? []) {
        if (!seen.has(next)) {
          seen.add(next);
          queue.push(next);
        }
      }
    }
    groups.push(group);
  }
  groups.sort((left, right) => right.length - left.length);
  return new Map(groups.flatMap((group, cluster) => group.map((id) => [id, cluster] as const)));
}

export const vaultBridge = {
  async unlock(path: string, passphrase: string): Promise<VaultInfo> {
    if (isTauri) return call<VaultInfo>("unlock_vault", { vaultPath: path, passphrase });
    await new Promise((resolve) => setTimeout(resolve, 520));
    if (!passphrase) throw new Error("Enter a passphrase to unlock the vault.");
    return { name: path.split(/[\\/]/u).filter(Boolean).at(-1) ?? "Demo vault", path, noteCount: demoNotes.length };
  },
  async lock(): Promise<void> {
    if (isTauri) return call<void>("lock_vault");
  },
  async listNotes(): Promise<NoteSummary[]> {
    if (isTauri) return call<NoteSummary[]>("list_notes");
    return demoNotes.map(({ body: _body, properties: _properties, createdAt: _created, version: _version, ...note }) => note);
  },
  async getNote(reference: string): Promise<NoteDocument> {
    if (isTauri) return call<NoteDocument>("get_note", { reference });
    const note = demoNotes.find((item) => item.id === reference || item.path === reference);
    if (!note) throw new Error(`Note not found: ${reference}`);
    return structuredClone(note);
  },
  async saveNote(note: NoteDocument): Promise<NoteDocument> {
    if (isTauri) return call<NoteDocument>("save_note", { note });
    await new Promise((resolve) => setTimeout(resolve, 180));
    const next = { ...note, revision: note.revision + 1, updatedAt: new Date().toISOString() };
    demoNotes = demoNotes.map((item) => (item.id === note.id ? next : item));
    return structuredClone(next);
  },
  async createNote(path: string, title: string): Promise<NoteDocument> {
    if (isTauri) return call<NoteDocument>("create_note", { path, title });
    const note: NoteDocument = {
      version: 1,
      id: crypto.randomUUID(),
      path: path.toLowerCase().endsWith(".md") ? path : `${path}.md`,
      title,
      body: `# ${title}\n\n`,
      aliases: [],
      tags: [],
      properties: {},
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      revision: 1,
    };
    demoNotes = [...demoNotes, note];
    return structuredClone(note);
  },
  async search(query: string): Promise<SearchHit[]> {
    if (isTauri) return call<SearchHit[]>("search_notes", { query, limit: 50 });
    const normalized = query.toLocaleLowerCase();
    if (!normalized) return [];
    return demoNotes
      .filter((note) => `${note.title} ${note.path} ${note.tags.join(" ")} ${note.body}`.toLocaleLowerCase().includes(normalized))
      .map((note) => ({ ...note, score: note.title.toLocaleLowerCase().includes(normalized) ? 20 : 4, excerpt: note.body.replace(/[#*_\[\]]/gu, " ").slice(0, 150) }))
      .sort((a, b) => b.score - a.score);
  },
  async backlinks(reference: string): Promise<Backlink[]> {
    if (isTauri) return call<Backlink[]>("get_backlinks", { reference });
    const target = demoNotes.find((note) => note.id === reference || note.path === reference);
    if (!target) return [];
    const names = [target.title, target.path.replace(/\.md$/iu, "")];
    return demoNotes.filter((note) => note.id !== target.id && names.some((name) => note.body.includes(`[[${name}`)));
  },
  async graph(): Promise<KnowledgeGraph> {
    if (isTauri) return call<KnowledgeGraph>("get_knowledge_graph");
    const byLabel = new Map<string, string>();
    for (const note of demoNotes) {
      byLabel.set(note.title.toLocaleLowerCase(), note.id);
      byLabel.set(note.path.replace(/\.md$/iu, "").toLocaleLowerCase(), note.id);
    }
    const edges: KnowledgeGraph["edges"] = [];
    for (const note of demoNotes) {
      for (const match of note.body.matchAll(/\[\[([^\]|#^]+)/gu)) {
        const target = byLabel.get(match[1].trim().toLocaleLowerCase());
        if (target && target !== note.id && !edges.some((edge) => edge.source === note.id && edge.target === target)) {
          edges.push({ source: note.id, target });
        }
      }
    }
    const clusters = demoClusters(demoNotes.map((note) => note.id), edges);
    return {
      nodes: demoNotes.map((note) => ({
        id: note.id,
        title: note.title,
        path: note.path,
        tags: note.tags,
        degree: edges.filter((edge) => edge.source === note.id || edge.target === note.id).length,
        cluster: clusters.get(note.id) ?? 0,
      })),
      edges,
    };
  },
  async propertyRows(): Promise<PropertyRow[]> {
    if (isTauri) return call<PropertyRow[]>("list_property_rows");
    return demoNotes.map((note) => rowOf(note));
  },
  async updateNoteProperty(reference: string, key: string, value: unknown): Promise<PropertyRow> {
    if (isTauri) return call<PropertyRow>("update_note_property", { reference, key, value: value ?? null });
    const note = demoNotes.find((item) => item.id === reference || item.path === reference);
    if (!note) throw new Error(`Note not found: ${reference}`);
    const properties = { ...note.properties };
    if (value === undefined || value === null) delete properties[key];
    else properties[key] = value;
    const next = { ...note, properties, revision: note.revision + 1, updatedAt: new Date().toISOString() };
    demoNotes = demoNotes.map((item) => (item.id === note.id ? next : item));
    return rowOf(next);
  },
  async savedViews(): Promise<SavedView[]> {
    if (isTauri) return call<SavedView[]>("list_saved_views");
    return structuredClone(demoViews);
  },
  async saveView(view: SavedView): Promise<SavedView[]> {
    if (isTauri) return call<SavedView[]>("save_saved_view", { view });
    const stamped: SavedView = { ...view, id: view.id || crypto.randomUUID(), updatedAt: new Date().toISOString() };
    const index = demoViews.findIndex((item) => item.id === stamped.id);
    demoViews = index >= 0
      ? demoViews.map((item) => (item.id === stamped.id ? stamped : item))
      : [...demoViews, { ...stamped, createdAt: new Date().toISOString() }];
    demoViews.sort((left, right) => left.name.localeCompare(right.name));
    return structuredClone(demoViews);
  },
  async deleteView(id: string): Promise<SavedView[]> {
    if (isTauri) return call<SavedView[]>("delete_saved_view", { id });
    demoViews = demoViews.filter((view) => view.id !== id);
    return structuredClone(demoViews);
  },
  async workspaceState(): Promise<WorkspaceState> {
    if (isTauri) return call<WorkspaceState>("get_workspace_state");
    return structuredClone(demoWorkspace);
  },
  async saveWorkspaceState(state: WorkspaceState): Promise<WorkspaceState> {
    if (isTauri) return call<WorkspaceState>("save_workspace_state", { workspace: state });
    const stamp = new Date().toISOString();
    const bookmarks: Bookmark[] = [];
    for (const bookmark of state.bookmarks) {
      if (!bookmarks.some((item) => item.id === bookmark.id)) bookmarks.push({ ...bookmark, createdAt: bookmark.createdAt || stamp });
    }
    demoWorkspace = {
      version: 1,
      bookmarks,
      layouts: state.layouts
        .map((layout) => ({ ...layout, id: layout.id || crypto.randomUUID(), createdAt: layout.createdAt || stamp, updatedAt: stamp }))
        .sort((left, right) => left.name.localeCompare(right.name)),
    };
    return structuredClone(demoWorkspace);
  },
  async unlinkedMentions(reference: string): Promise<UnlinkedMention[]> {
    if (isTauri) return call<UnlinkedMention[]>("get_unlinked_mentions", { reference });
    const target = demoNotes.find((note) => note.id === reference || note.path === reference);
    if (!target) return [];
    const linked = new Set((await vaultBridge.backlinks(target.id)).map((note) => note.id));
    const names = [target.title, ...target.aliases].filter(Boolean).sort((left, right) => right.length - left.length);
    const mentions: UnlinkedMention[] = [];
    for (const note of demoNotes) {
      if (note.id === target.id || linked.has(note.id)) continue;
      for (const name of names) {
        const hits = demoMentions(note.body, name);
        if (!hits.length) continue;
        const at = hits[0].index ?? 0;
        mentions.push({
          id: note.id, path: note.path, title: note.title, aliases: note.aliases, tags: note.tags,
          updatedAt: note.updatedAt, revision: note.revision,
          name, count: hits.length, excerpt: note.body.slice(Math.max(0, at - 60), at + name.length + 60).replace(/\s+/gu, " ").trim(),
        });
        break;
      }
    }
    return mentions.sort((left, right) => left.path.localeCompare(right.path));
  },
  async linkMention(source: string, target: string): Promise<UnlinkedMention[]> {
    if (isTauri) return call<UnlinkedMention[]>("link_unlinked_mention", { source, target });
    const from = demoNotes.find((note) => note.id === source);
    const to = demoNotes.find((note) => note.id === target);
    if (!from || !to) throw new Error("Note not found.");
    let body = from.body;
    for (const name of [to.title, ...to.aliases].filter(Boolean).sort((left, right) => right.length - left.length)) {
      const pattern = mentionPattern(name);
      body = outsideLinks(body, (segment) =>
        segment.replace(pattern, (surface) => (surface === to.title ? `[[${to.title}]]` : `[[${to.title}|${surface}]]`)));
    }
    const next = { ...from, body, revision: from.revision + 1, updatedAt: new Date().toISOString() };
    demoNotes = demoNotes.map((note) => (note.id === from.id ? next : note));
    return vaultBridge.unlinkedMentions(target);
  },
};

function rowOf(note: NoteDocument): PropertyRow {
  return {
    id: note.id,
    path: note.path,
    title: note.title,
    tags: note.tags,
    properties: structuredClone(note.properties),
    updatedAt: note.updatedAt,
  };
}
