import { useEffect, useMemo, useState } from "react";
import { ArrowDown, ArrowUp, ArrowUpDown, Bookmark, Search, TableProperties, Trash2 } from "lucide-react";
import { useVirtualWindow } from "./virtual";
import type { PropertyRow, SavedView, SortDirection } from "./types";

const ROW_HEIGHT = 34;
const MAX_COLUMNS = 8;

function display(value: unknown) {
  if (value === null || value === undefined || value === "") return "—";
  if (Array.isArray(value)) return value.join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

/** Text back into a typed property. An empty box clears the property outright. */
export function parseCell(input: string, previous: unknown): unknown {
  const text = input.trim();
  if (text === "" || text === "null") return null;
  if (Array.isArray(previous)) return text.split(",").map((part) => part.trim()).filter(Boolean);
  if (text === "true") return true;
  if (text === "false") return false;
  if (/^-?\d+(?:\.\d+)?$/u.test(text)) return Number(text);
  return text;
}

function editableValue(value: unknown) {
  if (value === null || value === undefined) return "";
  if (Array.isArray(value)) return value.join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

export function PropertyTable({
  rows,
  views,
  onOpen,
  onSaveView,
  onDeleteView,
  onEditProperty,
}: {
  rows: PropertyRow[];
  views: SavedView[];
  onOpen: (id: string) => void;
  onSaveView: (view: SavedView) => Promise<void>;
  onDeleteView: (id: string) => Promise<void>;
  onEditProperty: (id: string, key: string, value: unknown) => Promise<void>;
}) {
  const [filter, setFilter] = useState("");
  const [sort, setSort] = useState("title");
  const [direction, setDirection] = useState<SortDirection>("asc");
  const [activeView, setActiveView] = useState("");
  const [viewName, setViewName] = useState("");
  const [editing, setEditing] = useState<{ id: string; column: string } | null>(null);
  const [draft, setDraft] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");

  const available = useMemo(() => [...new Set(rows.flatMap((row) => Object.keys(row.properties)))].sort(), [rows]);
  const saved = useMemo(() => views.find((view) => view.id === activeView), [activeView, views]);
  const columns = useMemo(() => {
    const chosen = saved?.columns.filter((column) => available.includes(column)) ?? [];
    return chosen.length ? chosen : available.slice(0, MAX_COLUMNS);
  }, [available, saved]);

  // A saved view that is deleted elsewhere must not keep steering this table.
  useEffect(() => {
    if (activeView && !views.some((view) => view.id === activeView)) setActiveView("");
  }, [activeView, views]);

  const visible = useMemo(() => {
    const query = filter.trim().toLocaleLowerCase();
    const sign = direction === "desc" ? -1 : 1;
    return rows
      .filter((row) => !query || `${row.title} ${row.path} ${row.tags.join(" ")} ${JSON.stringify(row.properties)}`.toLocaleLowerCase().includes(query))
      .sort((left, right) => {
        const a = sort === "title" ? left.title : sort === "path" ? left.path : display(left.properties[sort]);
        const b = sort === "title" ? right.title : sort === "path" ? right.path : display(right.properties[sort]);
        return sign * a.localeCompare(b, undefined, { numeric: true });
      });
  }, [direction, filter, rows, sort]);
  const view = useVirtualWindow(visible.length, ROW_HEIGHT);
  const span = 2 + columns.length;

  function applyView(id: string) {
    setActiveView(id);
    const next = views.find((item) => item.id === id);
    setFilter(next?.filter ?? "");
    setSort(next?.sort || "title");
    setDirection(next?.direction ?? "asc");
    setViewName(next?.name ?? "");
    setError("");
  }

  function sortBy(column: string) {
    if (column === sort) setDirection(direction === "asc" ? "desc" : "asc");
    else { setSort(column); setDirection("asc"); }
  }

  async function storeView() {
    const name = viewName.trim();
    if (!name) { setError("Name the view before saving it."); return; }
    setError("");
    try {
      await onSaveView({
        id: saved?.name === name ? saved.id : "",
        name,
        filter,
        tags: [],
        sort,
        direction,
        columns,
        createdAt: saved?.createdAt ?? "",
        updatedAt: "",
      });
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Could not save that view.");
    }
  }

  async function removeView() {
    if (!saved) return;
    try {
      await onDeleteView(saved.id);
      setActiveView("");
      setViewName("");
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Could not delete that view.");
    }
  }

  function beginEdit(row: PropertyRow, column: string) {
    setEditing({ id: row.id, column });
    setDraft(editableValue(row.properties[column]));
    setError("");
  }

  async function commitEdit(row: PropertyRow, column: string) {
    const next = parseCell(draft, row.properties[column]);
    setPending(true);
    try {
      await onEditProperty(row.id, column, next);
      setEditing(null);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Could not write that property.");
    } finally {
      setPending(false);
    }
  }

  return <section className="knowledge-view property-view" aria-label="Property table">
    <header className="knowledge-header">
      <div><p className="eyebrow">STRUCTURED MEMORY</p><h2>Property view</h2>
        <span>{visible.length} notes · {columns.length} typed fields · local query</span></div>
      <label className="knowledge-filter"><Search size={15} /><input aria-label="Filter properties" value={filter} onChange={(event) => { setFilter(event.target.value); }} placeholder="Filter rows…" /></label>
    </header>

    <div className="saved-views" role="group" aria-label="Saved queries">
      <Bookmark size={14} />
      <select aria-label="Saved query" value={activeView} onChange={(event) => applyView(event.target.value)}>
        <option value="">Unsaved query</option>
        {views.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
      </select>
      <input aria-label="View name" value={viewName} onChange={(event) => setViewName(event.target.value)} placeholder="Name this query…" />
      <button onClick={() => void storeView()}>Save view</button>
      {saved && <button className="danger" onClick={() => void removeView()} title={`Delete ${saved.name}`}><Trash2 size={13} /><span>Delete</span></button>}
      <small>Stored encrypted in the vault</small>
    </div>
    {error && <p className="property-error" role="alert">{error}</p>}

    <div className="property-table-wrap" ref={view.ref} onScroll={view.onScroll}>{visible.length ? <table className="property-table"><thead><tr>
      {["title", "path", ...columns].map((column) => <th key={column}><button onClick={() => sortBy(column)} aria-label={`Sort by ${column}`}>
        {column}{sort === column ? (direction === "asc" ? <ArrowUp size={11} /> : <ArrowDown size={11} />) : <ArrowUpDown size={11} />}
      </button></th>)}
    </tr></thead><tbody>
      {view.topPad > 0 && <tr className="row-spacer" aria-hidden="true" style={{ height: view.topPad }}><td colSpan={span} /></tr>}
      {visible.slice(view.start, view.end).map((row) => <tr key={row.id}>
        <td><button className="table-note-link" onClick={() => onOpen(row.id)}>{row.title}</button><small>{row.tags.map((tag) => `#${tag}`).join(" ")}</small></td>
        <td>{row.path}</td>
        {columns.map((column) => {
          const active = editing?.id === row.id && editing.column === column;
          return <td key={column} className={active ? "cell-editing" : "cell"} onDoubleClick={() => beginEdit(row, column)}>
            {active ? <input
              autoFocus
              aria-label={`${column} for ${row.title}`}
              value={draft}
              disabled={pending}
              onChange={(event) => setDraft(event.target.value)}
              onBlur={() => void commitEdit(row, column)}
              onKeyDown={(event) => {
                if (event.key === "Enter") { event.preventDefault(); void commitEdit(row, column); }
                if (event.key === "Escape") { event.preventDefault(); setEditing(null); }
              }}
            /> : display(row.properties[column])}
          </td>;
        })}
      </tr>)}
      {view.bottomPad > 0 && <tr className="row-spacer" aria-hidden="true" style={{ height: view.bottomPad }}><td colSpan={span} /></tr>}
    </tbody></table> : <div className="knowledge-empty"><TableProperties size={28} /><p>No matching property rows.</p></div>}</div>
  </section>;
}
