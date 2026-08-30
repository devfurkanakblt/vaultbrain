import { useMemo, useState } from "react";
import { Maximize2, Network, Search } from "lucide-react";
import type { KnowledgeGraph as Graph } from "./types";

function colorFor(path: string) {
  const palette = ["#c7ef55", "#88b8b0", "#d69a68", "#a795cc", "#e4d688"];
  const folder = path.split("/")[0];
  const hash = [...folder].reduce((sum, character) => sum + character.charCodeAt(0), 0);
  return palette[hash % palette.length];
}

export function KnowledgeGraph({ graph, onOpen }: { graph: Graph; onOpen: (id: string) => void }) {
  const [filter, setFilter] = useState("");
  const visible = useMemo(() => {
    const query = filter.trim().toLocaleLowerCase();
    const nodes = query ? graph.nodes.filter((node) => `${node.title} ${node.path} ${node.tags.join(" ")}`.toLocaleLowerCase().includes(query)) : graph.nodes;
    const ids = new Set(nodes.map((node) => node.id));
    return { nodes, edges: graph.edges.filter((edge) => ids.has(edge.source) && ids.has(edge.target)) };
  }, [filter, graph]);
  const positions = useMemo(() => new Map(visible.nodes.map((node, index) => {
    const angle = (index / Math.max(visible.nodes.length, 1)) * Math.PI * 2 - Math.PI / 2;
    const ring = 240 + (index % 3) * 48;
    return [node.id, { x: 500 + Math.cos(angle) * ring, y: 390 + Math.sin(angle) * ring }];
  })), [visible.nodes]);

  return <section className="knowledge-view graph-view" aria-label="Knowledge graph">
    <header className="knowledge-header"><div><p className="eyebrow">KNOWLEDGE TOPOLOGY</p><h2>Local graph</h2><span>{visible.nodes.length} notes · {visible.edges.length} resolved links · bodies remain unopened</span></div>
      <label className="knowledge-filter"><Search size={15} /><input aria-label="Filter graph" value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter nodes…" /></label>
    </header>
    <div className="graph-canvas">
      <div className="graph-legend"><Network size={14} /><span>Encrypted index</span><i /><span>Node size = connections</span></div>
      <button className="graph-expand" title="Fit graph"><Maximize2 size={15} /></button>
      {visible.nodes.length ? <svg viewBox="0 0 1000 780" role="img" aria-label={`${visible.nodes.length} note knowledge graph`}>
        <g className="graph-edges">{visible.edges.map((edge) => {
          const source = positions.get(edge.source); const target = positions.get(edge.target);
          return source && target ? <line key={`${edge.source}-${edge.target}`} x1={source.x} y1={source.y} x2={target.x} y2={target.y} /> : null;
        })}</g>
        <g>{visible.nodes.map((node) => {
          const position = positions.get(node.id)!; const radius = 8 + Math.min(node.degree, 8) * 2;
          return <g className="graph-node" key={node.id} transform={`translate(${position.x} ${position.y})`} onClick={() => onOpen(node.id)} role="button" tabIndex={0} onKeyDown={(event) => (event.key === "Enter" || event.key === " ") && onOpen(node.id)}>
            <circle r={radius + 8} className="node-halo" /><circle r={radius} fill={colorFor(node.path)} /><text y={radius + 22}>{node.title}</text>
          </g>;
        })}</g>
      </svg> : <div className="knowledge-empty"><Network size={28} /><p>No matching nodes.</p></div>}
    </div>
  </section>;
}
