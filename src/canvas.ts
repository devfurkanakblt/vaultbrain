import path from "node:path";
import { normalizeVaultPath } from "./markdown.js";

/**
 * The canvas format is JSON Canvas 1.0 field-for-field, plus two extensions
 * that carry identity: `noteId` and `attachmentId` on a `file` node. JSON
 * Canvas keys a file node by its path, which contradicts the rule the rest of
 * this vault is built on — a user-facing path is a mutable label, not identity.
 * Storing the ID means renaming or moving a note cannot break a board, and no
 * disk write is needed to repair one: the `file` label is re-derived on read.
 */

export type CanvasSide = "top" | "right" | "bottom" | "left";
export type CanvasEnd = "none" | "arrow";

export interface CanvasNodeBase {
  /** Canvas-local short ID, required by JSON Canvas. Not a vault identity. */
  id: string;
  x: number;
  y: number;
  width: number;
  height: number;
  color?: string;
}

export type CanvasTextNode = { type: "text"; text: string } & CanvasNodeBase;
export type CanvasFileNode = {
  type: "file";
  noteId?: string;
  attachmentId?: string;
  file: string;
  subpath?: string;
} & CanvasNodeBase;
export type CanvasGroupNode = { type: "group"; label?: string; background?: string } & CanvasNodeBase;
export type CanvasLinkNode = { type: "link"; url: string } & CanvasNodeBase;

export type CanvasNode = CanvasTextNode | CanvasFileNode | CanvasGroupNode | CanvasLinkNode;

export interface CanvasEdge {
  id: string;
  fromNode: string;
  fromSide?: CanvasSide;
  fromEnd?: CanvasEnd;
  toNode: string;
  toSide?: CanvasSide;
  toEnd?: CanvasEnd;
  color?: string;
  label?: string;
}

export interface CanvasDocument {
  version: 1;
  id: string;
  /** "Boards/Roadmap.canvas" — a mutable label, not identity. */
  path: string;
  title: string;
  nodes: CanvasNode[];
  edges: CanvasEdge[];
  createdAt: string;
  updatedAt: string;
  revision: number;
}

/** The listing shape, mirroring NoteSummary: identity and labels, no content. */
export interface CanvasSummary {
  id: string;
  path: string;
  title: string;
  nodeCount: number;
  edgeCount: number;
  updatedAt: string;
  revision: number;
}

export interface CanvasInput {
  path: string;
  title?: string;
  nodes: CanvasNode[];
  edges: CanvasEdge[];
  id?: string;
  createdAt?: string;
  baseRevision?: number;
}

export const MAX_CANVAS_NODES = 5_000;
export const MAX_CANVAS_EDGES = 10_000;
export const MAX_CANVAS_BYTES = 8 * 1024 * 1024;
const MAX_COORDINATE = 10_000_000;
const MAX_TEXT_BYTES = 256 * 1024;
const MAX_LABEL_LENGTH = 160;
const MAX_URL_LENGTH = 2048;
const MAX_FILE_LABEL_LENGTH = 512;
const MAX_SUBPATH_LENGTH = 512;

const NODE_ID = /^[A-Za-z0-9_-]{1,64}$/u;
const COLOR = /^([1-6]|#[0-9a-fA-F]{6})$/u;
const NOTE_ID = /^[a-f0-9-]{36}$/u;
const ATTACHMENT_ID = /^[a-f0-9]{64}$/u;
const SUBPATH = /^#\^?.+$/u;
const SIDES = new Set<string>(["top", "right", "bottom", "left"]);
const ENDS = new Set<string>(["none", "arrow"]);

/** The folder name a canvas export uses for decrypted attachment bytes. */
export const DEFAULT_ASSETS_DIR = "assets";

export function normalizeCanvasPath(input: string): string {
  return normalizeVaultPath(input, ".canvas", "Canvas");
}

export function canvasBasename(canvasPath: string): string {
  return path.posix.basename(canvasPath, ".canvas");
}

/** Line breaks included: every label in this format is a single line. */
function hasControlCharacters(value: string): boolean {
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function requireLabel(value: unknown, what: string, max: number): string {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${what} must be a non-empty string.`);
  const text = value.trim();
  if (text.length > max) throw new Error(`${what} cannot exceed ${max} characters.`);
  if (hasControlCharacters(text)) throw new Error(`${what} must be a single line without control characters.`);
  return text;
}

function optionalLabel(value: unknown, what: string, max: number): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") throw new Error(`${what} must be a string.`);
  if (!value.trim()) return undefined;
  return requireLabel(value, what, max);
}

export function normalizeCanvasTitle(value: string): string {
  return requireLabel(value, "Canvas title", 300);
}

function optionalColor(value: unknown, what: string): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string" || !COLOR.test(value)) {
    throw new Error(`${what} must be a preset 1-6 or a #rrggbb hex colour.`);
  }
  return value;
}

function geometry(
  node: Record<string, unknown>,
  nodeId: string
): Pick<CanvasNodeBase, "x" | "y" | "width" | "height"> {
  const read = (key: "x" | "y" | "width" | "height"): number => {
    const value = node[key];
    if (typeof value !== "number" || !Number.isInteger(value)) {
      throw new Error(`Canvas node ${nodeId}: ${key} must be a finite integer.`);
    }
    if (Math.abs(value) > MAX_COORDINATE) {
      throw new Error(`Canvas node ${nodeId}: ${key} cannot exceed ${MAX_COORDINATE}.`);
    }
    return value;
  };
  const width = read("width");
  const height = read("height");
  if (width < 1 || height < 1) {
    throw new Error(`Canvas node ${nodeId}: width and height must be at least 1.`);
  }
  return { x: read("x"), y: read("y"), width, height };
}

function normalizeSubpath(value: unknown, nodeId: string): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (
    typeof value !== "string" ||
    value.length > MAX_SUBPATH_LENGTH ||
    hasControlCharacters(value) ||
    !SUBPATH.test(value)
  ) {
    throw new Error(
      `Canvas node ${nodeId}: subpath must be "#heading" or "#^block", up to ${MAX_SUBPATH_LENGTH} characters.`
    );
  }
  return value;
}

function normalizeUrl(value: unknown, nodeId: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`Canvas node ${nodeId}: a link node needs a url.`);
  }
  const url = value.trim();
  if (url.length > MAX_URL_LENGTH) {
    throw new Error(`Canvas node ${nodeId}: url cannot exceed ${MAX_URL_LENGTH} characters.`);
  }
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Canvas node ${nodeId}: url is not a valid absolute URL.`);
  }
  // A link node is stored text and nothing more — the vault never fetches it —
  // but file:, data: and javascript: would still be handed to whatever opens
  // the board later, so they are refused here, at the format boundary.
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`Canvas node ${nodeId}: only http: and https: URLs are allowed.`);
  }
  return url;
}

function normalizeNode(raw: unknown, seen: Set<string>): CanvasNode {
  if (!isRecord(raw)) throw new Error("Every canvas node must be an object.");
  const id = raw.id;
  if (typeof id !== "string" || !NODE_ID.test(id)) {
    throw new Error(`Invalid canvas node ID: ${JSON.stringify(id)}. Use 1-64 of A-Z a-z 0-9 _ -.`);
  }
  if (seen.has(id)) throw new Error(`Duplicate canvas node ID: ${id}`);
  seen.add(id);

  const base: CanvasNodeBase = { id, ...geometry(raw, id) };
  const color = optionalColor(raw.color, `Canvas node ${id}: color`);
  if (color) base.color = color;

  switch (raw.type) {
    case "text": {
      if (typeof raw.text !== "string") throw new Error(`Canvas node ${id}: a text node needs text.`);
      if (Buffer.byteLength(raw.text, "utf8") > MAX_TEXT_BYTES) {
        throw new Error(`Canvas node ${id}: text cannot exceed 256 KiB.`);
      }
      return { ...base, type: "text", text: raw.text };
    }
    case "file": {
      const noteId = raw.noteId === undefined || raw.noteId === null ? undefined : String(raw.noteId);
      const attachmentId =
        raw.attachmentId === undefined || raw.attachmentId === null ? undefined : String(raw.attachmentId);
      if (noteId && attachmentId) {
        throw new Error(`Canvas node ${id}: a file node cannot set both noteId and attachmentId.`);
      }
      if (noteId && !NOTE_ID.test(noteId)) throw new Error(`Canvas node ${id}: invalid noteId.`);
      if (attachmentId && !ATTACHMENT_ID.test(attachmentId)) {
        throw new Error(`Canvas node ${id}: invalid attachmentId.`);
      }
      const node: CanvasFileNode = {
        ...base,
        type: "file",
        file: requireLabel(raw.file, `Canvas node ${id}: file`, MAX_FILE_LABEL_LENGTH),
      };
      if (noteId) node.noteId = noteId;
      if (attachmentId) node.attachmentId = attachmentId;
      const subpath = normalizeSubpath(raw.subpath, id);
      if (subpath) node.subpath = subpath;
      return node;
    }
    case "group": {
      const node: CanvasGroupNode = { ...base, type: "group" };
      const label = optionalLabel(raw.label, `Canvas node ${id}: label`, MAX_LABEL_LENGTH);
      if (label) node.label = label;
      const background = optionalLabel(
        raw.background,
        `Canvas node ${id}: background`,
        MAX_FILE_LABEL_LENGTH
      );
      if (background) node.background = background;
      return node;
    }
    case "link":
      return { ...base, type: "link", url: normalizeUrl(raw.url, id) };
    default:
      // JSON Canvas may add node types later. Carrying an unvalidatable node
      // through the vault would be a way around every limit above, so a board
      // that contains one is refused and the offending node is named.
      throw new Error(`Canvas node ${id}: unsupported node type ${JSON.stringify(raw.type)}.`);
  }
}

function normalizeEdge(raw: unknown, nodeIds: Set<string>, seen: Set<string>): CanvasEdge {
  if (!isRecord(raw)) throw new Error("Every canvas edge must be an object.");
  const id = raw.id;
  if (typeof id !== "string" || !NODE_ID.test(id)) {
    throw new Error(`Invalid canvas edge ID: ${JSON.stringify(id)}. Use 1-64 of A-Z a-z 0-9 _ -.`);
  }
  if (seen.has(id)) throw new Error(`Duplicate canvas edge ID: ${id}`);
  seen.add(id);

  const endpoint = (key: "fromNode" | "toNode"): string => {
    const value = raw[key];
    if (typeof value !== "string" || !nodeIds.has(value)) {
      throw new Error(`Canvas edge ${id}: ${key} does not name a node on this canvas.`);
    }
    return value;
  };
  const side = (key: "fromSide" | "toSide"): CanvasSide | undefined => {
    const value = raw[key];
    if (value === undefined || value === null || value === "") return undefined;
    if (typeof value !== "string" || !SIDES.has(value)) {
      throw new Error(`Canvas edge ${id}: ${key} must be top, right, bottom or left.`);
    }
    return value as CanvasSide;
  };
  const end = (key: "fromEnd" | "toEnd"): CanvasEnd | undefined => {
    const value = raw[key];
    if (value === undefined || value === null || value === "") return undefined;
    if (typeof value !== "string" || !ENDS.has(value)) {
      throw new Error(`Canvas edge ${id}: ${key} must be none or arrow.`);
    }
    return value as CanvasEnd;
  };

  const edge: CanvasEdge = { id, fromNode: endpoint("fromNode"), toNode: endpoint("toNode") };
  const fromSide = side("fromSide");
  if (fromSide) edge.fromSide = fromSide;
  const fromEnd = end("fromEnd");
  if (fromEnd) edge.fromEnd = fromEnd;
  const toSide = side("toSide");
  if (toSide) edge.toSide = toSide;
  const toEnd = end("toEnd");
  if (toEnd) edge.toEnd = toEnd;
  const color = optionalColor(raw.color, `Canvas edge ${id}: color`);
  if (color) edge.color = color;
  const label = optionalLabel(raw.label, `Canvas edge ${id}: label`, MAX_LABEL_LENGTH);
  if (label) edge.label = label;
  return edge;
}

export function normalizeCanvasNodes(nodes: unknown): CanvasNode[] {
  if (!Array.isArray(nodes)) throw new Error("A canvas needs a nodes array.");
  if (nodes.length > MAX_CANVAS_NODES) {
    throw new Error(`A canvas cannot contain more than ${MAX_CANVAS_NODES} nodes.`);
  }
  const seen = new Set<string>();
  return nodes.map((node) => normalizeNode(node, seen));
}

export function normalizeCanvasEdges(edges: unknown, nodes: CanvasNode[]): CanvasEdge[] {
  if (!Array.isArray(edges)) throw new Error("A canvas needs an edges array.");
  if (edges.length > MAX_CANVAS_EDGES) {
    throw new Error(`A canvas cannot contain more than ${MAX_CANVAS_EDGES} edges.`);
  }
  const nodeIds = new Set(nodes.map((node) => node.id));
  const seen = new Set<string>();
  return edges.map((edge) => normalizeEdge(edge, nodeIds, seen));
}

export function assertCanvasSize(document: CanvasDocument): void {
  if (Buffer.byteLength(JSON.stringify(document), "utf8") > MAX_CANVAS_BYTES) {
    throw new Error("A canvas cannot exceed 8 MiB serialized.");
  }
}

/**
 * Reads a JSON Canvas 1.0 document. Identity extensions are accepted when
 * present — a board this vault exported and re-imported keeps them — but a
 * plain JSON Canvas file has none, and binding those is the vault's job.
 */
export function parseJsonCanvas(text: string): { nodes: CanvasNode[]; edges: CanvasEdge[] } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("The source file is not valid JSON.");
  }
  if (!isRecord(parsed)) throw new Error("A JSON Canvas document must be a JSON object.");
  const nodes = normalizeCanvasNodes(parsed.nodes ?? []);
  return { nodes, edges: normalizeCanvasEdges(parsed.edges ?? [], nodes) };
}

/**
 * Writes plain JSON Canvas 1.0: the identity extensions are dropped and every
 * `file` node carries the label the vault derived for it. Attachment labels are
 * re-rooted at the assets folder the caller names, because that is where the
 * bytes land if it asked for them at all.
 *
 * `exportedAssetPaths` maps an attachment id to the path the caller actually
 * wrote it to. Two attachments can share a filename, and a whole-vault export
 * has to give the second one a different name; without the map this node would
 * name the first one's file and the canvas would quietly point at the wrong
 * bytes.
 */
export function serializeJsonCanvas(
  canvas: CanvasDocument,
  assetsDir = DEFAULT_ASSETS_DIR,
  exportedAssetPaths?: ReadonlyMap<string, string>
): string {
  const nodes = canvas.nodes.map((node) => {
    if (node.type !== "file") return { ...node };
    const { noteId: _noteId, attachmentId, ...rest } = node;
    if (!attachmentId) return { ...rest };
    const exported = exportedAssetPaths?.get(attachmentId);
    return { ...rest, file: exported ?? path.posix.join(assetsDir, path.posix.basename(node.file)) };
  });
  return `${JSON.stringify({ nodes, edges: canvas.edges }, null, 2)}\n`;
}
