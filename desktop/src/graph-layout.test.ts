import { describe, expect, it } from "vitest";
import { boundsOf, layoutGraph, nodesInView, type LayoutEdge, type Point } from "./graph-layout";
import type { GraphNode } from "./types";

function node(id: string, cluster: number, degree = 0): GraphNode {
  return { id, title: id, path: `Atlas/${id}.md`, tags: [], degree, cluster };
}

function link(source: string, target: string): LayoutEdge {
  return { source, target };
}

function distance(left: Point, right: Point) {
  return Math.hypot(left.x - right.x, left.y - right.y);
}

const twoTriangles = {
  nodes: [node("a", 0, 2), node("b", 0, 2), node("c", 0, 2), node("d", 1, 2), node("e", 1, 2), node("f", 1, 2)],
  edges: [link("a", "b"), link("b", "c"), link("c", "a"), link("d", "e"), link("e", "f"), link("f", "d")],
};

describe("graph layout", () => {
  it("places every node at a finite point", () => {
    const positions = layoutGraph(twoTriangles.nodes, twoTriangles.edges);
    expect(positions.size).toBe(twoTriangles.nodes.length);
    for (const point of positions.values()) {
      expect(Number.isFinite(point.x)).toBe(true);
      expect(Number.isFinite(point.y)).toBe(true);
    }
  });

  it("draws the same map for the same vault on every run", () => {
    const first = layoutGraph(twoTriangles.nodes, twoTriangles.edges);
    const second = layoutGraph(twoTriangles.nodes, twoTriangles.edges);
    expect([...second]).toEqual([...first]);
  });

  it("keeps separate communities further apart than their own members", () => {
    const positions = layoutGraph(twoTriangles.nodes, twoTriangles.edges);
    const left = ["a", "b", "c"].map((id) => positions.get(id)!);
    const right = ["d", "e", "f"].map((id) => positions.get(id)!);
    const within = Math.max(
      ...left.flatMap((one) => left.map((other) => distance(one, other))),
      ...right.flatMap((one) => right.map((other) => distance(one, other))),
    );
    const between = Math.min(...left.flatMap((one) => right.map((other) => distance(one, other))));
    expect(between).toBeGreaterThan(within);
  });

  it("skips relaxation past the limit but still seeds every node", () => {
    const many = Array.from({ length: 400 }, (_, index) => node(`n${index}`, index % 7));
    const positions = layoutGraph(many, [], { relaxLimit: 100 });
    expect(positions.size).toBe(400);
    expect([...layoutGraph(many, [], { relaxLimit: 100 })]).toEqual([...positions]);
  });

  it("reports a frame that contains every node", () => {
    const positions = layoutGraph(twoTriangles.nodes, twoTriangles.edges);
    const frame = boundsOf(positions);
    for (const point of positions.values()) {
      expect(point.x).toBeGreaterThanOrEqual(frame.x);
      expect(point.x).toBeLessThanOrEqual(frame.x + frame.width);
      expect(point.y).toBeGreaterThanOrEqual(frame.y);
      expect(point.y).toBeLessThanOrEqual(frame.y + frame.height);
    }
  });

  it("falls back to a usable frame for an empty graph", () => {
    expect(boundsOf(new Map())).toEqual({ x: -500, y: -390, width: 1000, height: 780 });
  });
});

describe("graph culling", () => {
  const nodes = [node("near", 0, 1), node("far", 0, 9)];
  const positions = new Map<string, Point>([
    ["near", { x: 10, y: 10 }],
    ["far", { x: 4000, y: 4000 }],
  ]);

  it("drops nodes outside the viewport", () => {
    const visible = nodesInView(nodes, positions, { x: 0, y: 0, width: 100, height: 100 }, 50);
    expect(visible.map((item) => item.id)).toEqual(["near"]);
  });

  it("caps a dense viewport to the best-connected nodes", () => {
    const dense = Array.from({ length: 300 }, (_, index) => node(`n${index}`, 0, index));
    const packed = new Map(dense.map((item, index) => [item.id, { x: index % 20, y: Math.floor(index / 20) }]));
    const visible = nodesInView(dense, packed, { x: -50, y: -50, width: 400, height: 400 }, 25);
    expect(visible).toHaveLength(25);
    expect(visible.map((item) => item.id)).toContain("n299");
    expect(visible.map((item) => item.id)).not.toContain("n0");
  });

  it("ignores nodes the layout never placed", () => {
    const visible = nodesInView([...nodes, node("ghost", 0)], positions, { x: -1, y: -1, width: 5000, height: 5000 }, 50);
    expect(visible.map((item) => item.id)).toEqual(["near", "far"]);
  });
});
