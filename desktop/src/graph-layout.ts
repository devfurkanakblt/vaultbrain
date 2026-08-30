import type { GraphNode } from "./types";

export interface Point {
  x: number;
  y: number;
}

export interface Rect {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface LayoutEdge {
  source: string;
  target: string;
}

export interface LayoutOptions {
  /** Relaxation passes. Fixed, so the layout never depends on wall-clock time. */
  iterations?: number;
  /**
   * Vaults larger than this keep the seeded placement. Relaxation is linear in
   * the node count but still costs a frame or two, and past this size the
   * community seeding already separates the graph legibly.
   */
  relaxLimit?: number;
}

const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5));
const REPULSION_CELL = 74;
const REPULSION = 2400;
const SPRING = 0.045;
const REST_LENGTH = 78;
const GRAVITY = 0.0016;
const MAX_STEP = 26;
const DEFAULT_ITERATIONS = 120;
const DEFAULT_RELAX_LIMIT = 1500;
const EMPTY_FRAME: Rect = { x: -500, y: -390, width: 1000, height: 780 };

/**
 * Deterministic community-seeded force layout.
 *
 * Nothing here is random. Communities are laid out on a ring in cluster order,
 * members fill their community along a golden-angle spiral, and the relaxation
 * pass runs a fixed number of steps. The same vault therefore draws the same
 * map on every unlock — a graph that reshuffles itself is a graph nobody learns.
 */
export function layoutGraph(nodes: GraphNode[], edges: LayoutEdge[], options: LayoutOptions = {}): Map<string, Point> {
  const positions = seedPositions(nodes);
  const { iterations = DEFAULT_ITERATIONS, relaxLimit = DEFAULT_RELAX_LIMIT } = options;
  if (nodes.length > 1 && nodes.length <= relaxLimit && iterations > 0) {
    relax(nodes, edges, positions, iterations);
  }
  return positions;
}

function seedPositions(nodes: GraphNode[]): Map<string, Point> {
  const positions = new Map<string, Point>();
  const clusters = [...new Set(nodes.map((node) => node.cluster))].sort((left, right) => left - right);
  const clusterOrder = new Map(clusters.map((cluster, index) => [cluster, index]));
  const sizes = new Map<number, number>();
  for (const node of nodes) sizes.set(node.cluster, (sizes.get(node.cluster) ?? 0) + 1);

  const galaxy = clusters.length < 2 ? 0 : 180 + clusters.length * 32;
  const placed = new Map<number, number>();
  for (const node of nodes) {
    const rank = placed.get(node.cluster) ?? 0;
    placed.set(node.cluster, rank + 1);
    const size = sizes.get(node.cluster) ?? 1;
    const centreAngle = ((clusterOrder.get(node.cluster) ?? 0) / Math.max(clusters.length, 1)) * Math.PI * 2;
    const spread = 36 + Math.sqrt(size) * 26;
    const radius = spread * Math.sqrt((rank + 0.5) / size);
    const angle = rank * GOLDEN_ANGLE;
    positions.set(node.id, {
      x: Math.cos(centreAngle) * galaxy + Math.cos(angle) * radius,
      y: Math.sin(centreAngle) * galaxy + Math.sin(angle) * radius,
    });
  }
  return positions;
}

function relax(nodes: GraphNode[], edges: LayoutEdge[], positions: Map<string, Point>, iterations: number) {
  const count = nodes.length;
  const slot = new Map(nodes.map((node, index) => [node.id, index]));
  const x = new Float64Array(count);
  const y = new Float64Array(count);
  nodes.forEach((node, index) => {
    const point = positions.get(node.id)!;
    x[index] = point.x;
    y[index] = point.y;
  });

  const links: number[] = [];
  for (const edge of edges) {
    const source = slot.get(edge.source);
    const target = slot.get(edge.target);
    if (source !== undefined && target !== undefined && source !== target) links.push(source, target);
  }

  const forceX = new Float64Array(count);
  const forceY = new Float64Array(count);
  const buckets = new Map<string, number[]>();

  for (let step = 0; step < iterations; step += 1) {
    const cooling = 1 - step / iterations;
    forceX.fill(0);
    forceY.fill(0);

    // Repulsion only between near neighbours. A uniform grid keeps this linear,
    // so a few thousand notes stay interactive instead of quadratic.
    buckets.clear();
    for (let index = 0; index < count; index += 1) {
      const key = `${Math.floor(x[index] / REPULSION_CELL)}:${Math.floor(y[index] / REPULSION_CELL)}`;
      const bucket = buckets.get(key);
      if (bucket) bucket.push(index);
      else buckets.set(key, [index]);
    }
    for (const [key, bucket] of buckets) {
      const [column, row] = key.split(":").map(Number);
      for (let dx = 0; dx <= 1; dx += 1) {
        for (let dy = dx === 0 ? 0 : -1; dy <= 1; dy += 1) {
          const other = dx === 0 && dy === 0 ? bucket : buckets.get(`${column + dx}:${row + dy}`);
          if (!other) continue;
          for (let a = 0; a < bucket.length; a += 1) {
            for (let b = other === bucket ? a + 1 : 0; b < other.length; b += 1) {
              repel(bucket[a], other[b], x, y, forceX, forceY);
            }
          }
        }
      }
    }

    for (let link = 0; link < links.length; link += 2) {
      const source = links[link];
      const target = links[link + 1];
      const dx = x[target] - x[source];
      const dy = y[target] - y[source];
      const distance = Math.hypot(dx, dy) || 1;
      const pull = ((distance - REST_LENGTH) / distance) * SPRING;
      forceX[source] += dx * pull;
      forceY[source] += dy * pull;
      forceX[target] -= dx * pull;
      forceY[target] -= dy * pull;
    }

    for (let index = 0; index < count; index += 1) {
      const stepX = clampStep(forceX[index] - x[index] * GRAVITY) * cooling;
      const stepY = clampStep(forceY[index] - y[index] * GRAVITY) * cooling;
      x[index] += stepX;
      y[index] += stepY;
    }
  }

  nodes.forEach((node, index) => positions.set(node.id, { x: round(x[index]), y: round(y[index]) }));
}

function repel(a: number, b: number, x: Float64Array, y: Float64Array, forceX: Float64Array, forceY: Float64Array) {
  let dx = x[a] - x[b];
  let dy = y[a] - y[b];
  let squared = dx * dx + dy * dy;
  if (squared === 0) {
    // Two notes seeded on the same point: separate them the same way every time.
    dx = a - b;
    dy = 1;
    squared = dx * dx + 1;
  }
  if (squared > REPULSION_CELL * REPULSION_CELL) return;
  const push = REPULSION / squared;
  forceX[a] += dx * push;
  forceY[a] += dy * push;
  forceX[b] -= dx * push;
  forceY[b] -= dy * push;
}

function clampStep(value: number) {
  return Math.max(-MAX_STEP, Math.min(MAX_STEP, value));
}

function round(value: number) {
  return Number.isFinite(value) ? Math.round(value * 100) / 100 : 0;
}

/** Bounding box of every laid-out node, padded, for the initial and "fit" view. */
export function boundsOf(positions: Map<string, Point>, padding = 130): Rect {
  if (positions.size === 0) return EMPTY_FRAME;
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  for (const point of positions.values()) {
    minX = Math.min(minX, point.x);
    minY = Math.min(minY, point.y);
    maxX = Math.max(maxX, point.x);
    maxY = Math.max(maxY, point.y);
  }
  return {
    x: minX - padding,
    y: minY - padding,
    width: Math.max(maxX - minX, 1) + padding * 2,
    height: Math.max(maxY - minY, 1) + padding * 2,
  };
}

/**
 * Which nodes actually reach the document. A 100k-note vault must never put
 * 100k circles in the DOM, so anything outside the viewport is dropped and what
 * remains is capped to the best-connected nodes.
 */
export function nodesInView<T extends GraphNode>(nodes: T[], positions: Map<string, Point>, view: Rect, cap: number): T[] {
  const inside: T[] = [];
  for (const node of nodes) {
    const point = positions.get(node.id);
    if (!point) continue;
    if (point.x < view.x || point.x > view.x + view.width) continue;
    if (point.y < view.y || point.y > view.y + view.height) continue;
    inside.push(node);
  }
  if (inside.length <= cap) return inside;
  return inside
    .slice()
    .sort((left, right) => right.degree - left.degree || left.id.localeCompare(right.id))
    .slice(0, cap);
}
