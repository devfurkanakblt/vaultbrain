/** How a message should read: a confirmation, or something that went wrong. */
export type NoticeTone = "info" | "error";

/** Hands a message up to whatever surface the workspace shows messages on. */
export type Notify = (message: string, tone?: NoticeTone) => void;

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
  frontmatterSource?: string;
}

export interface SearchHit extends NoteSummary {
  score: number;
  excerpt: string;
}

export type Backlink = NoteSummary;

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

/** One archived or live revision of a note. */
export interface RevisionInfo {
  revision: number;
  updatedAt: string;
  current: boolean;
}

/** A note whose object is gone but whose encrypted history is still on disk. */
export interface DeletedNote {
  id: string;
  path: string;
  title: string;
  revision: number;
  updatedAt: string;
}

/** An installed plugin: identity, labels and reach — never its source. */
export interface PluginSummary {
  id: string;
  manifestId: string;
  name: string;
  version: string;
  description: string;
  author: string;
  capabilities: string[];
  enabled: boolean;
  signatureStatus: "unsigned" | "verified" | "revoked";
  signer?: string;
  signed: boolean;
  sourceBytes: number;
  updatedAt: string;
  revision: number;
}

/** A plugin's manifest and source together. Only the sandbox needs the source. */
export interface PluginPackage {
  version: 1;
  id: string;
  manifest: {
    manifestVersion: 1;
    id: string;
    name: string;
    version: string;
    description: string;
    author: string;
    capabilities: string[];
    signature?: string;
  };
  source: string;
  signature?: { algorithm: "ed25519"; keyId: string };
  enabled: boolean;
  installedAt: string;
  updatedAt: string;
  revision: number;
}

export interface PluginSecurityPolicy {
  version: 1;
  restrictedMode: boolean;
  revokedSigners: string[];
}

export interface PluginCallContext {
  pluginId: string;
  instanceToken: string;
  revision: number;
}

/** A daily note, plus whether this call is what created it. */
export interface DailyNote {
  note: NoteDocument;
  created: boolean;
}

/** An encrypted, content-addressed attachment. `id` is derived from its bytes. */
export interface AttachmentInfo {
  id: string;
  filename: string;
  mime: string;
  size: number;
  chunks: number;
  createdAt: string;
}

/** An attachment plus its decrypted bytes, base64 for the JSON IPC boundary. */
export interface AttachmentContent {
  info: AttachmentInfo;
  data: string;
}

export type CanvasNode =
  | ({ type: "text"; text: string } & CanvasNodeBase)
  | ({ type: "file"; file: string; noteId?: string; attachmentId?: string; subpath?: string } & CanvasNodeBase)
  | ({ type: "group"; label?: string; background?: string } & CanvasNodeBase)
  | ({ type: "link"; url: string } & CanvasNodeBase);

export interface CanvasNodeBase {
  id: string;
  x: number;
  y: number;
  width: number;
  height: number;
  color?: string;
}

export interface CanvasEdge {
  id: string;
  fromNode: string;
  toNode: string;
  fromSide?: "top" | "right" | "bottom" | "left";
  toSide?: "top" | "right" | "bottom" | "left";
  fromEnd?: "none" | "arrow";
  toEnd?: "none" | "arrow";
  color?: string;
  label?: string;
}

export interface CanvasSummary {
  id: string;
  path: string;
  title: string;
  nodeCount: number;
  edgeCount: number;
  updatedAt: string;
  revision: number;
}

export interface CanvasDocument extends CanvasSummary {
  version: 1;
  nodes: CanvasNode[];
  edges: CanvasEdge[];
  createdAt: string;
}

export interface CanvasInput {
  id?: string;
  path: string;
  title?: string;
  nodes: CanvasNode[];
  edges: CanvasEdge[];
  createdAt?: string;
  baseRevision?: number;
}

/** One device in the signed sync registry. `revokedAfterSequence` is absent — not null — for an active device. */
export interface SyncDeviceSummary {
  deviceId: string;
  name: string;
  serial: number;
  epoch: number;
  revokedAfterSequence?: number;
}

export interface SyncCheckpointSummary {
  id: string;
  sequence: number;
  changeCount: number;
  createdAt: string;
}

/**
 * Read-only visibility into the encrypted sync store the CLI owns. There is
 * no honest way to compute how many recorded changes remain unapplied from
 * this data alone: `changeCount` counts change files (many edits can target
 * one object) while `appliedObjectCount` is a per-object cursor, so the two
 * are different units and must never be subtracted against each other.
 */
/** Mirrors `KeyringStatus` in src-tauri/src/keyring.rs and src/keyring-status.ts. */
export type KeyringCostStatus = "below-default" | "default" | "above-default";

export interface KeyringStatusSlot {
  id: string;
  type: string;
  label: string;
  createdAt: string;
  recovery: boolean;
  kdf: { name: string; N: number; r: number; p: number; cost: KeyringCostStatus };
}

export interface RecoveryKitReport {
  slotId: string;
  kitPath: string;
  /** Shown once and never stored anywhere by the application. */
  recoveryCode: string;
}

export interface PassphraseChangeReport {
  slotsRewritten: number;
  slotsPreserved: number;
  previousN: number;
  newN: number;
}

export interface KeyringStatusData {
  format: string;
  version: number | null;
  recommendedScryptN: number;
  recoveryConfigured: boolean;
  slots: KeyringStatusSlot[];
}

export interface SyncStatusData {
  enrolled: boolean;
  authorityFingerprint: string;
  epoch: number;
  registryRevision: number;
  registryVersion: number;
  devices: SyncDeviceSummary[];
  checkpoint: SyncCheckpointSummary | null;
  changeCount: number;
  appliedObjectCount: number;
  readable: boolean;
}
