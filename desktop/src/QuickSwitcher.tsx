import { useEffect, useMemo, useState } from "react";
import { FileText, Search, Tag, X } from "lucide-react";
import type { NoteSummary } from "./types";

function score(note: NoteSummary, rawQuery: string) {
  const query = rawQuery.trim().toLocaleLowerCase();
  if (!query) return 1;
  const title = note.title.toLocaleLowerCase();
  const path = note.path.toLocaleLowerCase();
  if (title === query) return 100;
  if (title.startsWith(query)) return 70;
  if (title.includes(query)) return 50;
  if (path.includes(query)) return 30;
  if (note.aliases.some((alias) => alias.toLocaleLowerCase().includes(query))) return 20;
  const characters = [...query];
  let cursor = 0;
  for (const character of title) if (character === characters[cursor]) cursor += 1;
  return cursor === characters.length ? 10 : 0;
}

/** The alias that earned a note its place, so an alias hit is not a mystery. */
function matchedAlias(note: NoteSummary, rawQuery: string) {
  const query = rawQuery.trim().toLocaleLowerCase();
  if (!query) return undefined;
  if (note.title.toLocaleLowerCase().includes(query)) return undefined;
  return note.aliases.find((alias) => alias.toLocaleLowerCase().includes(query));
}

export function QuickSwitcher({ notes, onClose, onOpen, onSplit }: {
  notes: NoteSummary[];
  onClose: () => void;
  onOpen: (id: string) => void;
  onSplit: (id: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(0);
  const matches = useMemo(() => notes.map((note) => ({ note, score: score(note, query) }))
    .filter((entry) => entry.score > 0)
    .sort((left, right) => right.score - left.score || right.note.updatedAt.localeCompare(left.note.updatedAt))
    .slice(0, 50), [notes, query]);

  useEffect(() => setSelected(0), [query]);

  function choose(index: number, split = false) {
    const match = matches[index];
    if (!match) return;
    if (split) onSplit(match.note.id);
    else onOpen(match.note.id);
    onClose();
  }

  return <div className="overlay quick-overlay" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
    <section className="quick-switcher" role="dialog" aria-modal="true" aria-label="Quick switcher">
      <div className="quick-input"><Search size={18} /><input autoFocus value={query} onChange={(event) => setQuery(event.target.value)} onKeyDown={(event) => {
        if (event.key === "ArrowDown") { event.preventDefault(); setSelected((value) => Math.min(value + 1, matches.length - 1)); }
        if (event.key === "ArrowUp") { event.preventDefault(); setSelected((value) => Math.max(value - 1, 0)); }
        if (event.key === "Enter") { event.preventDefault(); choose(selected, event.altKey); }
        if (event.key === "Escape") onClose();
      }} placeholder="Open a note by title, path, or alias…" /><button onClick={onClose} aria-label="Close quick switcher"><X size={16} /></button></div>
      <div className="quick-results" role="listbox" aria-label="Matching notes">
        {matches.map(({ note }, index) => <button key={note.id} className={selected === index ? "selected" : ""} role="option" aria-selected={selected === index} onMouseEnter={() => setSelected(index)} onClick={() => choose(index)}>
          <FileText size={15} /><span><b>{note.title}</b><small>{matchedAlias(note, query) ? <><Tag size={9} /> {matchedAlias(note, query)}</> : note.path}</small></span><i>{note.tags.slice(0, 2).map((tag) => `#${tag}`).join(" ")}</i>
        </button>)}
        {!matches.length && <p>No note matches this name.</p>}
      </div>
      <footer><span><kbd>↑↓</kbd> select</span><span><kbd>↵</kbd> open</span><span><kbd>alt ↵</kbd> split right</span><b>{matches.length} nearby notes</b></footer>
    </section>
  </div>;
}
