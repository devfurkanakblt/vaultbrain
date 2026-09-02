import { invoke } from "@tauri-apps/api/core";
import type { AttachmentContent, AttachmentInfo, Backlink, Bookmark, CanvasDocument, CanvasInput, CanvasSummary, DailyNote, DeletedNote, KnowledgeGraph, NoteDocument, NoteSummary, PluginCallContext, PluginPackage, PluginSecurityPolicy, PluginSummary, PropertyRow, RevisionInfo, SavedView, SearchHit, UnlinkedMention, VaultInfo, WorkspaceState } from "./types";

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
/** Demo mode keeps archived revisions in memory so history and undelete work. */
let demoHistory: NoteDocument[] = [];
let demoPlugins: PluginPackage[] = [];
let demoPluginStorage: Record<string, Record<string, string>> = {};
let demoPluginPolicy: PluginSecurityPolicy = { version: 1, restrictedMode: false, revokedSigners: [] };
const demoPluginInstances = new Map<string, { pluginId: string; revision: number }>();
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

let demoAttachments: { info: AttachmentInfo; data: string }[] = [];
let demoCanvases: CanvasDocument[] = [];

/**
 * Demo mode has no vault key, so this is a plain content hash standing in for
 * the real address, which is an HMAC of the bytes under the vault key.
 */
function demoAttachmentId(data: string): string {
  let hash = 0x811c9dc5;
  for (let index = 0; index < data.length; index += 1) {
    hash = Math.imul(hash ^ data.charCodeAt(index), 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, "0").repeat(8);
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
    demoPluginInstances.clear();
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
  async renameNote(reference: string, path: string, title?: string): Promise<NoteDocument> {
    if (isTauri) return call<NoteDocument>("rename_note", { reference, path, title });
    const note = await vaultBridge.getNote(reference);
    const logical = path.toLowerCase().endsWith(".md") ? path : `${path}.md`;
    if (demoNotes.some((item) => item.id !== note.id && item.path.toLocaleLowerCase() === logical.toLocaleLowerCase())) {
      throw new Error(`A note already exists at ${logical}.`);
    }
    demoHistory = [...demoHistory, structuredClone(note)];
    const next: NoteDocument = {
      ...note,
      path: logical,
      title: title?.trim() || note.title,
      revision: note.revision + 1,
      updatedAt: new Date().toISOString(),
    };
    demoNotes = demoNotes.map((item) => (item.id === note.id ? next : item));
    return structuredClone(next);
  },
  async deleteNote(reference: string): Promise<NoteSummary> {
    if (isTauri) return call<NoteSummary>("delete_note", { reference });
    const note = await vaultBridge.getNote(reference);
    demoHistory = [...demoHistory, structuredClone(note)];
    demoNotes = demoNotes.filter((item) => item.id !== note.id);
    const { body: _body, properties: _properties, createdAt: _createdAt, version: _version, ...summary } = note;
    return summary;
  },
  async deletedNotes(): Promise<DeletedNote[]> {
    if (isTauri) return call<DeletedNote[]>("list_deleted_notes");
    const latest = new Map<string, NoteDocument>();
    for (const note of demoHistory) {
      if (demoNotes.some((item) => item.id === note.id)) continue;
      const held = latest.get(note.id);
      if (!held || held.revision < note.revision) latest.set(note.id, note);
    }
    return [...latest.values()]
      .map((note) => ({ id: note.id, path: note.path, title: note.title, revision: note.revision, updatedAt: note.updatedAt }))
      .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
  },
  async noteRevisions(reference: string): Promise<RevisionInfo[]> {
    if (isTauri) return call<RevisionInfo[]>("list_note_revisions", { reference });
    const live = demoNotes.find((note) => note.id === reference || note.path === reference);
    const id = live?.id ?? reference;
    const archived = demoHistory
      .filter((note) => note.id === id)
      .map((note) => ({ revision: note.revision, updatedAt: note.updatedAt, current: false }));
    const current = live ? [{ revision: live.revision, updatedAt: live.updatedAt, current: true }] : [];
    return [...archived, ...current].sort((left, right) => right.revision - left.revision);
  },
  async noteRevision(reference: string, revision: number): Promise<NoteDocument> {
    if (isTauri) return call<NoteDocument>("get_note_revision", { reference, revision });
    const live = demoNotes.find((note) => note.id === reference || note.path === reference);
    const id = live?.id ?? reference;
    if (live?.revision === revision) return structuredClone(live);
    const archived = demoHistory.find((note) => note.id === id && note.revision === revision);
    if (!archived) throw new Error(`Revision ${revision} not found for note ${reference}.`);
    return structuredClone(archived);
  },
  async restoreRevision(reference: string, revision: number): Promise<NoteDocument> {
    if (isTauri) return call<NoteDocument>("restore_note_revision", { reference, revision });
    const historical = await vaultBridge.noteRevision(reference, revision);
    const live = demoNotes.find((note) => note.id === historical.id);
    if (live) demoHistory = [...demoHistory, structuredClone(live)];
    const base = live?.revision ?? Math.max(0, ...demoHistory.filter((note) => note.id === historical.id).map((note) => note.revision));
    const restored: NoteDocument = { ...historical, revision: base + 1, updatedAt: new Date().toISOString() };
    demoNotes = live
      ? demoNotes.map((note) => (note.id === restored.id ? restored : note))
      : [...demoNotes, restored];
    return structuredClone(restored);
  },
  async templates(): Promise<NoteSummary[]> {
    if (isTauri) return call<NoteSummary[]>("list_templates");
    return demoNotes
      .filter((note) => note.tags.includes("template"))
      .map(({ body: _body, properties: _properties, createdAt: _createdAt, version: _version, ...note }) => note)
      .sort((left, right) => left.path.localeCompare(right.path));
  },
  async createFromTemplate(template: string, path: string, title?: string, variables?: Record<string, string>, date?: string): Promise<NoteDocument> {
    if (isTauri) return call<NoteDocument>("create_from_template", { template, path, title, variables, date });
    const source = await vaultBridge.getNote(template);
    const logical = path.toLowerCase().endsWith(".md") ? path : `${path}.md`;
    if (demoNotes.some((note) => note.path.toLocaleLowerCase() === logical.toLocaleLowerCase())) {
      throw new Error(`A note already exists at ${logical}.`);
    }
    const chosen = title?.trim() || logical.split("/").at(-1)!.replace(/\.md$/iu, "");
    const render = demoRenderer(chosen, logical, date, variables);
    const note: NoteDocument = {
      version: 1,
      id: crypto.randomUUID(),
      path: logical,
      title: render(chosen),
      body: render(source.body),
      aliases: [],
      tags: source.tags.filter((tag) => tag !== "template"),
      properties: Object.fromEntries(Object.entries(source.properties).map(([key, value]) => [key, typeof value === "string" ? render(value) : value])),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      revision: 1,
    };
    demoNotes = [...demoNotes, note];
    return structuredClone(note);
  },
  async dailyNote(date?: string, folder?: string, template?: string): Promise<DailyNote> {
    if (isTauri) return call<DailyNote>("open_daily_note", { date, folder, template });
    const day = demoDay(date);
    const directory = (folder ?? "Daily").trim().replace(/^\/+|\/+$/gu, "");
    const logical = `${directory ? `${directory}/` : ""}${day}.md`;
    const existing = demoNotes.find((note) => note.path.toLocaleLowerCase() === logical.toLocaleLowerCase());
    if (existing) return { note: structuredClone(existing), created: false };
    if (template) {
      const note = await vaultBridge.createFromTemplate(template, logical, day, undefined, day);
      const tagged = { ...note, tags: [...new Set(["daily", ...note.tags])], properties: { ...note.properties, date: day } };
      demoNotes = demoNotes.map((item) => (item.id === note.id ? tagged : item));
      return { note: structuredClone(tagged), created: true };
    }
    const note: NoteDocument = {
      version: 1,
      id: crypto.randomUUID(),
      path: logical,
      title: day,
      body: `# ${day}\n\n`,
      aliases: [],
      tags: ["daily"],
      properties: { date: day },
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      revision: 1,
    };
    demoNotes = [...demoNotes, note];
    return { note: structuredClone(note), created: true };
  },
  async search(query: string): Promise<SearchHit[]> {
    if (isTauri) return call<SearchHit[]>("search_notes", { query, limit: 50 });
    const normalized = query.toLocaleLowerCase();
    if (!normalized) return [];
    return demoNotes
      .filter((note) => `${note.title} ${note.path} ${note.tags.join(" ")} ${note.body}`.toLocaleLowerCase().includes(normalized))
      .map((note) => ({
        ...note,
        score: note.title.toLocaleLowerCase().includes(normalized) ? 20 : 4,
        excerpt: note.body.replace(/[#*_]/gu, " ").replaceAll("[", " ").replaceAll("]", " ").slice(0, 150),
      }))
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
  async canvases(): Promise<CanvasSummary[]> {
    if (isTauri) return call<CanvasSummary[]>("list_canvases");
    return demoCanvases
      .map(({ nodes, edges, createdAt: _createdAt, version: _version, ...summary }) => ({
        ...summary,
        nodeCount: nodes.length,
        edgeCount: edges.length,
      }))
      .sort((left, right) => left.path.localeCompare(right.path));
  },
  async getCanvas(reference: string): Promise<CanvasDocument> {
    if (isTauri) return call<CanvasDocument>("get_canvas", { reference });
    const normalized = reference.toLocaleLowerCase().replace(/\.canvas$/u, "");
    const canvas = demoCanvases.find((item) => item.id === reference
      || item.path.toLocaleLowerCase().replace(/\.canvas$/u, "") === normalized
      || item.title.toLocaleLowerCase() === normalized);
    if (!canvas) throw new Error(`Canvas not found: ${reference}`);
    return structuredClone(canvas);
  },
  async saveCanvas(input: CanvasInput): Promise<CanvasDocument> {
    if (isTauri) return call<CanvasDocument>("save_canvas", { input });
    const canvasPath = input.path.toLocaleLowerCase().endsWith(".canvas") ? input.path : `${input.path}.canvas`;
    const existing = demoCanvases.find((item) => item.id === input.id || item.path.toLocaleLowerCase() === canvasPath.toLocaleLowerCase());
    if (existing && input.baseRevision !== undefined && input.baseRevision !== existing.revision) {
      throw new Error(`Canvas revision conflict: expected ${input.baseRevision}, current ${existing.revision}.`);
    }
    const stamp = new Date().toISOString();
    const canvas: CanvasDocument = {
      version: 1,
      id: existing?.id ?? input.id ?? crypto.randomUUID(),
      path: canvasPath,
      title: input.title?.trim() || canvasPath.split("/").at(-1)?.replace(/\.canvas$/iu, "") || "Untitled canvas",
      nodes: structuredClone(input.nodes),
      edges: structuredClone(input.edges),
      nodeCount: input.nodes.length,
      edgeCount: input.edges.length,
      createdAt: existing?.createdAt ?? input.createdAt ?? stamp,
      updatedAt: stamp,
      revision: (existing?.revision ?? 0) + 1,
    };
    demoCanvases = existing
      ? demoCanvases.map((item) => item.id === existing.id ? canvas : item)
      : [...demoCanvases, canvas];
    return structuredClone(canvas);
  },
  async deleteCanvas(reference: string): Promise<CanvasDocument> {
    if (isTauri) return call<CanvasDocument>("delete_canvas", { reference });
    const canvas = await vaultBridge.getCanvas(reference);
    demoCanvases = demoCanvases.filter((item) => item.id !== canvas.id);
    return canvas;
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
  async plugins(): Promise<PluginSummary[]> {
    if (isTauri) return call<PluginSummary[]>("list_plugins");
    return demoPlugins.map(summarizeDemoPlugin).sort((left, right) => left.name.localeCompare(right.name));
  },
  async authorizePluginInstance(pluginId: string, revision: number): Promise<{ instanceToken: string }> {
    if (isTauri) return call<{ instanceToken: string }>("authorize_plugin_instance", { pluginId, revision });
    const summary = summarizeDemoPlugin(
      demoPlugins.find((plugin) => plugin.id === pluginId) ?? (() => { throw new Error("Plugin not found."); })()
    );
    if (!summary.enabled || summary.revision !== revision) throw new Error("Plugin authorization is stale or disabled.");
    const instanceToken = crypto.randomUUID();
    demoPluginInstances.set(instanceToken, { pluginId, revision });
    return { instanceToken };
  },
  async pluginCall(context: PluginCallContext, method: string, params: Record<string, unknown>): Promise<unknown> {
    if (isTauri) return call<unknown>("plugin_call", { ...context, method, params });
    const authorization = demoPluginInstances.get(context.instanceToken);
    const plugin = demoPlugins.find((entry) => entry.id === context.pluginId);
    if (!authorization || authorization.pluginId !== context.pluginId || authorization.revision !== context.revision || !plugin) {
      throw new Error("Invalid plugin instance authorization.");
    }
    const summary = summarizeDemoPlugin(plugin);
    if (!summary.enabled || summary.revision !== context.revision) throw new Error("Plugin authorization was revoked or changed.");
    const reference = String(params.reference ?? "");
    switch (method) {
      case "notes.list": return vaultBridge.listNotes();
      case "notes.metadata": {
        const note = await vaultBridge.getNote(reference);
        const { body: _body, ...metadata } = note;
        return metadata;
      }
      case "notes.read": return vaultBridge.getNote(reference);
      case "notes.create": return vaultBridge.createNote(String(params.path ?? ""), String(params.title ?? ""));
      case "notes.update": {
        const note = await vaultBridge.getNote(reference);
        return vaultBridge.saveNote({ ...note, body: String(params.body ?? "") });
      }
      case "search.query": return vaultBridge.search(String(params.query ?? ""));
      case "canvas.list": return vaultBridge.canvases();
      case "canvas.read": return vaultBridge.getCanvas(reference);
      case "canvas.save": return vaultBridge.saveCanvas(params.input as CanvasInput);
      case "attachments.list": return vaultBridge.attachments();
      case "attachments.read": return vaultBridge.readAttachment(String(params.id ?? ""));
      case "storage.get": {
        const stored = await vaultBridge.pluginStorage(context.pluginId);
        return stored[String(params.key ?? "")] ?? null;
      }
      case "storage.set": {
        const stored = await vaultBridge.pluginStorage(context.pluginId);
        await vaultBridge.savePluginStorage(context.pluginId, { ...stored, [String(params.key ?? "")]: String(params.value ?? "") });
        return null;
      }
      default: throw new Error(`Unknown privileged plugin method: ${method}`);
    }
  },
  async getPlugin(reference: string): Promise<PluginPackage> {
    if (isTauri) return call<PluginPackage>("get_plugin", { reference });
    const plugin = demoPlugins.find((item) => item.id === reference || item.manifest.id === reference);
    if (!plugin) throw new Error(`Plugin not found: ${reference}`);
    return structuredClone(plugin);
  },
  async pluginSecurityPolicy(): Promise<PluginSecurityPolicy> {
    if (isTauri) return call<PluginSecurityPolicy>("get_plugin_security_policy");
    return structuredClone(demoPluginPolicy);
  },
  async setPluginRestrictedMode(restrictedMode: boolean): Promise<PluginSecurityPolicy> {
    if (isTauri) return call<PluginSecurityPolicy>("set_plugin_restricted_mode", { restrictedMode });
    demoPluginPolicy = { ...demoPluginPolicy, restrictedMode };
    return structuredClone(demoPluginPolicy);
  },
  async revokePluginSigner(reference: string): Promise<PluginSecurityPolicy> {
    if (isTauri) return call<PluginSecurityPolicy>("revoke_plugin_signer", { reference });
    const plugin = await vaultBridge.getPlugin(reference);
    const signer = plugin.signature?.keyId ?? (plugin.manifest.signature ? `demo-${plugin.manifest.id}` : undefined);
    if (!signer) throw new Error("An unsigned plugin has no signer to revoke.");
    demoPluginPolicy = {
      ...demoPluginPolicy,
      revokedSigners: [...new Set([...demoPluginPolicy.revokedSigners, signer])],
    };
    demoPlugins = demoPlugins.map((item) => {
      const itemSigner = item.signature?.keyId ?? (item.manifest.signature ? `demo-${item.manifest.id}` : undefined);
      return itemSigner === signer ? { ...item, enabled: false } : item;
    });
    return structuredClone(demoPluginPolicy);
  },
  async restorePluginSigner(keyId: string): Promise<PluginSecurityPolicy> {
    if (isTauri) return call<PluginSecurityPolicy>("restore_plugin_signer", { keyId });
    demoPluginPolicy = {
      ...demoPluginPolicy,
      revokedSigners: demoPluginPolicy.revokedSigners.filter((entry) => entry !== keyId),
    };
    return structuredClone(demoPluginPolicy);
  },
  async installPlugin(manifest: PluginPackage["manifest"], source: string, enabled?: boolean): Promise<PluginSummary> {
    if (isTauri) return call<PluginSummary>("install_plugin", { manifest, source, enabled });
    if (demoPluginPolicy.restrictedMode && !manifest.signature) {
      throw new Error("Restricted mode accepts cryptographically signed plugins only.");
    }
    const existing = demoPlugins.find((item) => item.manifest.id === manifest.id);
    const stamp = new Date().toISOString();
    const plugin: PluginPackage = {
      version: 1,
      id: existing?.id ?? crypto.randomUUID(),
      manifest,
      source,
      enabled: enabled ?? existing?.enabled ?? false,
      installedAt: existing?.installedAt ?? stamp,
      updatedAt: stamp,
      revision: (existing?.revision ?? 0) + 1,
    };
    demoPlugins = existing
      ? demoPlugins.map((item) => (item.id === existing.id ? plugin : item))
      : [...demoPlugins, plugin];
    return summarizeDemoPlugin(plugin);
  },
  async setPluginEnabled(reference: string, enabled: boolean): Promise<PluginSummary> {
    if (isTauri) return call<PluginSummary>("set_plugin_enabled", { reference, enabled });
    const plugin = await vaultBridge.getPlugin(reference);
    const next = { ...plugin, enabled, updatedAt: new Date().toISOString() };
    demoPlugins = demoPlugins.map((item) => (item.id === plugin.id ? next : item));
    return summarizeDemoPlugin(next);
  },
  async deletePlugin(reference: string): Promise<PluginSummary> {
    if (isTauri) return call<PluginSummary>("delete_plugin", { reference });
    const plugin = await vaultBridge.getPlugin(reference);
    demoPlugins = demoPlugins.filter((item) => item.id !== plugin.id);
    delete demoPluginStorage[plugin.id];
    return summarizeDemoPlugin(plugin);
  },
  async pluginStorage(reference: string): Promise<Record<string, string>> {
    if (isTauri) return call<Record<string, string>>("get_plugin_storage", { reference });
    const plugin = await vaultBridge.getPlugin(reference);
    return { ...(demoPluginStorage[plugin.id] ?? {}) };
  },
  async savePluginStorage(reference: string, data: Record<string, string>): Promise<Record<string, string>> {
    if (isTauri) return call<Record<string, string>>("set_plugin_storage", { reference, data });
    const plugin = await vaultBridge.getPlugin(reference);
    demoPluginStorage = { ...demoPluginStorage, [plugin.id]: { ...data } };
    return { ...data };
  },
  async attachments(): Promise<AttachmentInfo[]> {
    if (isTauri) return call<AttachmentInfo[]>("list_attachments");
    return demoAttachments.map((entry) => structuredClone(entry.info));
  },
  /** `data` is base64: bytes cross the IPC boundary as JSON or not at all. */
  async addAttachment(filename: string, mime: string, data: string): Promise<AttachmentInfo> {
    if (isTauri) return call<AttachmentInfo>("add_attachment", { filename, mime, data });
    if (!data) throw new Error("Attachments must be between 1 byte and 250 MiB.");
    const id = demoAttachmentId(data);
    const existing = demoAttachments.find((entry) => entry.info.id === id);
    if (existing) return structuredClone(existing.info);
    const info: AttachmentInfo = {
      id,
      filename: filename.trim(),
      mime: mime.trim().toLowerCase(),
      size: Math.floor((data.length * 3) / 4),
      chunks: 1,
      createdAt: new Date().toISOString(),
    };
    demoAttachments = [...demoAttachments, { info, data }];
    return structuredClone(info);
  },
  async readAttachment(id: string): Promise<AttachmentContent> {
    if (isTauri) return call<AttachmentContent>("read_attachment", { id });
    const entry = demoAttachments.find((item) => item.info.id === id);
    if (!entry) throw new Error(`Attachment not found: ${id}`);
    return structuredClone(entry);
  },
  async deleteAttachment(id: string): Promise<AttachmentInfo> {
    if (isTauri) return call<AttachmentInfo>("delete_attachment", { id });
    const entry = demoAttachments.find((item) => item.info.id === id);
    if (!entry) throw new Error(`Attachment not found: ${id}`);
    demoAttachments = demoAttachments.filter((item) => item.info.id !== id);
    return structuredClone(entry.info);
  },
};

/** Demo-mode mirror of the Rust template renderer, same variable grammar. */
function demoRenderer(title: string, path: string, date: string | undefined, variables?: Record<string, string>) {
  const when = date ? new Date(`${date}T12:00:00`) : new Date();
  const pad = (value: number) => String(value).padStart(2, "0");
  const stamp = (format: string) => format.replace(/YYYY|MM|DD|HH|mm|ss/gu, (token) => ({
    YYYY: String(when.getFullYear()),
    MM: pad(when.getMonth() + 1),
    DD: pad(when.getDate()),
    HH: pad(when.getHours()),
    mm: pad(when.getMinutes()),
    ss: pad(when.getSeconds()),
  })[token]!);
  return (text: string) => text.replace(/\{\{\s*([\w.-]+)(?::([^}]+))?\s*\}\}/gu, (whole, name: string, format?: string) => {
    if (name === "date") return stamp(format?.trim() || "YYYY-MM-DD");
    if (name === "time") return stamp(format?.trim() || "HH:mm");
    if (name === "title") return title;
    if (name === "path") return path;
    if (name === "year") return stamp("YYYY");
    if (name === "month") return stamp("MM");
    if (name === "day") return stamp("DD");
    return variables?.[name] ?? whole;
  });
}

function demoDay(date?: string) {
  const when = date ? new Date(`${date}T12:00:00`) : new Date();
  if (Number.isNaN(when.getTime())) throw new Error("A daily note date must use YYYY-MM-DD.");
  return `${when.getFullYear()}-${String(when.getMonth() + 1).padStart(2, "0")}-${String(when.getDate()).padStart(2, "0")}`;
}

function summarizeDemoPlugin(plugin: PluginPackage): PluginSummary {
  const signer = plugin.signature?.keyId ?? (plugin.manifest.signature ? `demo-${plugin.manifest.id}` : undefined);
  const revoked = Boolean(signer && demoPluginPolicy.revokedSigners.includes(signer));
  const signatureStatus = revoked ? "revoked" : signer ? "verified" : "unsigned";
  return {
    id: plugin.id,
    manifestId: plugin.manifest.id,
    name: plugin.manifest.name,
    version: plugin.manifest.version,
    description: plugin.manifest.description,
    author: plugin.manifest.author,
    capabilities: plugin.manifest.capabilities,
    enabled: plugin.enabled && !revoked && (!demoPluginPolicy.restrictedMode || signatureStatus === "verified"),
    signatureStatus,
    ...(signer ? { signer } : {}),
    signed: signatureStatus === "verified",
    sourceBytes: new TextEncoder().encode(plugin.source).length,
    updatedAt: plugin.updatedAt,
    revision: plugin.revision,
  };
}

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
