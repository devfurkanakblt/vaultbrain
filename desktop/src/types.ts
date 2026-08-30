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

export type SaveState = "saved" | "saving" | "dirty" | "error";
