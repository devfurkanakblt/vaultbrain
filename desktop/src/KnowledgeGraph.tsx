import { useCallback, useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent, type WheelEvent as ReactWheelEvent } from "react";
import { Maximize2, Network, Search } from "lucide-react";
import { boundsOf, layoutGraph, nodesInView, type Point, type Rect } from "./graph-layout";
import type { GraphNode, KnowledgeGraph as Graph } from "./types";

/** Hard ceiling on circles in the document, whatever the vault's size. */
const MAX_DRAWN = 1200;
const MAX_LABELS = 90;
const MIN_SPAN = 220;
const MAX_SPAN = 24_000;
/**
 * Community colours. These identify groups rather than carry the theme, so they
 * stay fixed and stay distinguishable from each other — but the first one is
 * the one the eye reads as "primary", so it tracks the workspace accent.
 */
const CLUSTER_PALETTE = ["#c9794a", "#88b8b0", "#c9a227", "#a795cc", "#6f8f4f", "#7fa9d8", "#d98fa8", "#9fd6a0"];

function colorFor(cluster: number) {
  return CLUSTER_PALETTE[cluster % CLUSTER_PALETTE.length];
}

function fit(nodes: GraphNode[], positions: Map<string, Point>): Rect {
  const visible = new Map<string, Point>();
  for (const node of nodes) {
    const point = positions.get(node.id);
    if (point) visible.set(node.id, point);
  }
  return boundsOf(visible);
}

export function KnowledgeGraph({ graph, onOpen }: { graph: Graph; onOpen: (id: string) => void }) {
  const [filter, setFilter] = useState("");
  const [cluster, setCluster] = useState<number | null>(null);
  const [view, setView] = useState<Rect | null>(null);
  const surface = useRef<SVGSVGElement | null>(null);
  const drag = useRef<{ x: number; y: number; view: Rect } | null>(null);

  const positions = useMemo(() => layoutGraph(graph.nodes, graph.edges), [graph]);

  const clusters = useMemo(() => {
    const sizes = new Map<number, number>();
    for (const node of graph.nodes) sizes.set(node.cluster, (sizes.get(node.cluster) ?? 0) + 1);
    return [...sizes.entries()].sort((left, right) => right[1] - left[1] || left[0] - right[0]);
  }, [graph]);

  const visible = useMemo(() => {
    const query = filter.trim().toLocaleLowerCase();
    const nodes = graph.nodes.filter((node) => {
      if (cluster !== null && node.cluster !== cluster) return false;
      if (!query) return true;
      return `${node.title} ${node.path} ${node.tags.join(" ")}`.toLocaleLowerCase().includes(query);
    });
    const ids = new Set(nodes.map((node) => node.id));
    return { nodes, edges: graph.edges.filter((edge) => ids.has(edge.source) && ids.has(edge.target)) };
  }, [cluster, filter, graph]);

  // Refit whenever the visible set changes, so isolating a community or typing a
  // filter lands on something the eye can actually read.
  useEffect(() => setView(fit(visible.nodes, positions)), [positions, visible.nodes]);

  const drawn = useMemo(
    () => (view ? nodesInView(visible.nodes, positions, view, MAX_DRAWN) : []),
    [positions, view, visible.nodes],
  );
  const drawnIds = useMemo(() => new Set(drawn.map((node) => node.id)), [drawn]);
  const drawnEdges = useMemo(
    () => visible.edges.filter((edge) => drawnIds.has(edge.source) && drawnIds.has(edge.target)),
    [drawnIds, visible.edges],
  );
  const labelled = useMemo(() => {
    if (drawn.length <= MAX_LABELS) return new Set(drawn.map((node) => node.id));
    return new Set(
      [...drawn]
        .sort((left, right) => right.degree - left.degree || left.id.localeCompare(right.id))
        .slice(0, MAX_LABELS)
        .map((node) => node.id),
    );
  }, [drawn]);

  const toUser = useCallback((clientX: number, clientY: number, frame: Rect) => {
    const element = surface.current;
    if (!element) return { x: frame.x + frame.width / 2, y: frame.y + frame.height / 2 };
    const box = element.getBoundingClientRect();
    // The viewBox is drawn with "meet", so both axes share one scale and the
    // leftover space is split evenly — mirror that to land on user coordinates.
    const scale = Math.min(box.width / frame.width, box.height / frame.height) || 1;
    return {
      x: frame.x + (clientX - box.left - (box.width - frame.width * scale) / 2) / scale,
      y: frame.y + (clientY - box.top - (box.height - frame.height * scale) / 2) / scale,
    };
  }, []);

  function zoom(event: ReactWheelEvent<SVGSVGElement>) {
    if (!view) return;
    event.preventDefault();
    const factor = Math.exp(event.deltaY * 0.0014);
    const width = Math.min(MAX_SPAN, Math.max(MIN_SPAN, view.width * factor));
    const ratio = width / view.width;
    const anchor = toUser(event.clientX, event.clientY, view);
    setView({
      x: anchor.x - (anchor.x - view.x) * ratio,
      y: anchor.y - (anchor.y - view.y) * ratio,
      width,
      height: view.height * ratio,
    });
  }

  function startPan(event: ReactPointerEvent<SVGSVGElement>) {
    if (!view || event.button !== 0) return;
    drag.current = { x: event.clientX, y: event.clientY, view };
    event.currentTarget.setPointerCapture?.(event.pointerId);
  }

  function pan(event: ReactPointerEvent<SVGSVGElement>) {
    const start = drag.current;
    if (!start) return;
    const element = surface.current;
    const box = element?.getBoundingClientRect();
    const scale = box ? Math.min(box.width / start.view.width, box.height / start.view.height) || 1 : 1;
    setView({
      ...start.view,
      x: start.view.x - (event.clientX - start.x) / scale,
      y: start.view.y - (event.clientY - start.y) / scale,
    });
  }

  function endPan(event: ReactPointerEvent<SVGSVGElement>) {
    drag.current = null;
    if (event.currentTarget.hasPointerCapture?.(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId);
  }

  const communityCount = cluster === null ? clusters.length : 1;

  return <section className="knowledge-view graph-view" aria-label="Knowledge graph">
    <header className="knowledge-header">
      <div>
        <p className="eyebrow">KNOWLEDGE TOPOLOGY</p><h2>Global graph</h2>
        <span>{drawn.length} of {visible.nodes.length} notes drawn · {drawnEdges.length} resolved links · {communityCount} {communityCount === 1 ? "community" : "communities"} · bodies remain unopened</span>
      </div>
      <label className="knowledge-filter"><Search size={15} /><input aria-label="Filter graph" value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter nodes…" /></label>
    </header>

    {clusters.length > 1 && <div className="cluster-bar" role="group" aria-label="Communities">
      <button className={cluster === null ? "active" : ""} onClick={() => setCluster(null)}>All · {graph.nodes.length}</button>
      {clusters.slice(0, 8).map(([id, size]) => <button
        key={id}
        className={cluster === id ? "active" : ""}
        onClick={() => setCluster(cluster === id ? null : id)}
        aria-pressed={cluster === id}
      ><i style={{ background: colorFor(id) }} />Community {id + 1} · {size}</button>)}
    </div>}

    <div className="graph-canvas">
      <div className="graph-legend"><Network size={14} /><span>Encrypted index</span><i /><span>Colour = community · size = connections</span></div>
      <button className="graph-expand" title="Fit graph" onClick={() => setView(fit(visible.nodes, positions))}><Maximize2 size={15} /></button>
      {visible.nodes.length > 0 && view ? <svg
        ref={surface}
        viewBox={`${view.x} ${view.y} ${view.width} ${view.height}`}
        role="img"
        aria-label={`${visible.nodes.length} note knowledge graph in ${communityCount} communities`}
        onWheel={zoom}
        onPointerDown={startPan}
        onPointerMove={pan}
        onPointerUp={endPan}
        onPointerCancel={endPan}
      >
        <g className="graph-edges">{drawnEdges.map((edge) => {
          const source = positions.get(edge.source)!; const target = positions.get(edge.target)!;
          return <line key={`${edge.source}-${edge.target}`} x1={source.x} y1={source.y} x2={target.x} y2={target.y} />;
        })}</g>
        <g>{drawn.map((node) => {
          const position = positions.get(node.id)!; const radius = 7 + Math.min(node.degree, 9) * 1.8;
          return <g className="graph-node" key={node.id} transform={`translate(${position.x} ${position.y})`} onClick={() => onOpen(node.id)} role="button" tabIndex={0} onKeyDown={(event) => (event.key === "Enter" || event.key === " ") && onOpen(node.id)}>
            <circle r={radius + 8} className="node-halo" /><circle r={radius} fill={colorFor(node.cluster)} />
            {labelled.has(node.id) && <text y={radius + 20}>{node.title}</text>}
          </g>;
        })}</g>
      </svg> : <div className="knowledge-empty"><Network size={28} /><p>No matching nodes.</p></div>}
    </div>
  </section>;
}
