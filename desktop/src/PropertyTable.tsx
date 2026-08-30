import { useMemo, useState } from "react";
import { ArrowUpDown, Search, TableProperties } from "lucide-react";
import { useVirtualWindow } from "./virtual";
import type { PropertyRow } from "./types";

const ROW_HEIGHT = 34;

function display(value: unknown) {
  if (value === null || value === undefined || value === "") return "—";
  if (Array.isArray(value)) return value.join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

export function PropertyTable({ rows, onOpen }: { rows: PropertyRow[]; onOpen: (id: string) => void }) {
  const [filter, setFilter] = useState("");
  const [sort, setSort] = useState("title");
  const columns = useMemo(() => [...new Set(rows.flatMap((row) => Object.keys(row.properties)))].sort().slice(0, 8), [rows]);
  const visible = useMemo(() => rows.filter((row) => `${row.title} ${row.path} ${row.tags.join(" ")} ${JSON.stringify(row.properties)}`.toLocaleLowerCase().includes(filter.toLocaleLowerCase())).sort((left, right) => {
    const a = sort === "title" ? left.title : sort === "path" ? left.path : display(left.properties[sort]);
    const b = sort === "title" ? right.title : sort === "path" ? right.path : display(right.properties[sort]);
    return a.localeCompare(b, undefined, { numeric: true });
  }), [filter, rows, sort]);
  const view = useVirtualWindow(visible.length, ROW_HEIGHT);
  const span = 2 + columns.length;

  return <section className="knowledge-view property-view" aria-label="Property table">
    <header className="knowledge-header"><div><p className="eyebrow">STRUCTURED MEMORY</p><h2>Property view</h2><span>{visible.length} notes · {columns.length} typed fields · local query</span></div>
      <label className="knowledge-filter"><Search size={15} /><input aria-label="Filter properties" value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter rows…" /></label>
    </header>
    <div className="property-table-wrap" ref={view.ref} onScroll={view.onScroll}>{visible.length ? <table className="property-table"><thead><tr>
      {["title", "path", ...columns].map((column) => <th key={column}><button onClick={() => setSort(column)}>{column}<ArrowUpDown size={11} /></button></th>)}
    </tr></thead><tbody>
      {view.topPad > 0 && <tr className="row-spacer" aria-hidden="true" style={{ height: view.topPad }}><td colSpan={span} /></tr>}
      {visible.slice(view.start, view.end).map((row) => <tr key={row.id} onDoubleClick={() => onOpen(row.id)}>
      <td><button className="table-note-link" onClick={() => onOpen(row.id)}>{row.title}</button><small>{row.tags.map((tag) => `#${tag}`).join(" ")}</small></td><td>{row.path}</td>{columns.map((column) => <td key={column}>{display(row.properties[column])}</td>)}
    </tr>)}
      {view.bottomPad > 0 && <tr className="row-spacer" aria-hidden="true" style={{ height: view.bottomPad }}><td colSpan={span} /></tr>}
    </tbody></table> : <div className="knowledge-empty"><TableProperties size={28} /><p>No matching property rows.</p></div>}</div>
  </section>;
}
