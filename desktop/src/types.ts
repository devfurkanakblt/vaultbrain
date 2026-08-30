export interface VaultInfo {
  name: string;
  path: string;
  noteCount: number;
}

export interface NoteSummary {
  id: string;
  path: string;
  title: string;
  aliases: string[];
  tags: string[];
  updatedAt: string;
  revision: number;
}

export interface NoteDocument extends NoteSummary {
  version: 1;
  body: string;
  properties: Record<string, unknown>;
  createdAt: string;
}

export interface SearchHit extends NoteSummary {
  score: number;
  excerpt: string;
}

export interface Backlink extends NoteSummary {}

export interface GraphNode {
  id: string;
  title: string;
  path: string;
  tags: string[];
  degree: number;
  /** Community index from the vault's link graph. 0 is always the largest. */
  cluster: number;
}

export interface GraphEdge {
  source: string;
  target: string;
}

export interface KnowledgeGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface PropertyRow {
  id: string;
  path: string;
  title: string;
  tags: string[];
  properties: Record<string, unknown>;
  updatedAt: string;
}

/** A note that names another in plain text without linking it. */
export interface UnlinkedMention extends NoteSummary {
  name: string;
  count: number;
  excerpt: string;
}

export interface Bookmark {
  id: string;
  label: string;
  createdAt: string;
}

export interface WorkspaceLayout {
  id: string;
  name: string;
  tabs: string[];
  active: string | null;
  secondary: string | null;
  view: string;
  createdAt: string;
  updatedAt: string;
}

/** Pinned notes and named layouts. Encrypted in the vault, never in settings. */
export interface WorkspaceState {
  version: 1;
  bookmarks: Bookmark[];
  layouts: WorkspaceLayout[];
}

export type SortDirection = "asc" | "desc";

/** A stored property query. Lives encrypted in the vault, never in app settings. */
export interface SavedView {
  id: string;
  name: string;
  filter: string;
  tags: string[];
  sort: string;
  direction: SortDirection;
  columns: string[];
  createdAt: string;
  updatedAt: string;
}

export type SaveState = "saved" | "saving" | "dirty" | "error";
