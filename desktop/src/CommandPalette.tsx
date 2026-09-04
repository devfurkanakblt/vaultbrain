import { useEffect, useMemo, useRef, useState, type ComponentType } from "react";
import { Command, X } from "lucide-react";

export interface PaletteCommand {
  icon: ComponentType<{ size?: number }>;
  label: string;
  /** The shortcut that reaches the same command, when one exists. */
  keys?: string;
  /** A command the current workspace cannot run is shown, but not offered. */
  disabled?: boolean;
  action: () => void;
}

/**
 * Ranks a command against what has been typed. Consecutive text wins over a
 * scattered subsequence, so "new note" reaches "Create new note" before it
 * reaches "New note from a template".
 */
function score(command: PaletteCommand, rawQuery: string) {
  const query = rawQuery.trim().toLocaleLowerCase();
  if (!query) return 1;
  const label = command.label.toLocaleLowerCase();
  if (label === query) return 100;
  if (label.startsWith(query)) return 70;
  if (label.includes(query)) return 50;
  // A word-initial run: "cnn" reaches "Create new note".
  const initials = label.split(/[^\p{L}\p{N}]+/u).filter(Boolean).map((word) => word[0]).join("");
  if (initials.startsWith(query)) return 40;
  const characters = [...query];
  let cursor = 0;
  for (const character of label) if (character === characters[cursor]) cursor += 1;
  return cursor === characters.length ? 10 : 0;
}

export function CommandPalette({ commands, onClose }: { commands: PaletteCommand[]; onClose: () => void }) {
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(0);
  const list = useRef<HTMLDivElement>(null);

  const matches = useMemo(() => commands
    .map((command) => ({ command, score: score(command, query) }))
    .filter((entry) => entry.score > 0)
    .sort((left, right) => right.score - left.score)
    .map((entry) => entry.command), [commands, query]);

  useEffect(() => setSelected(0), [query]);

  // Keep the highlighted row on screen once the list is longer than the panel.
  useEffect(() => {
    // Guarded: a test renderer has elements without a scroller attached.
    list.current?.querySelector<HTMLElement>(".selected")?.scrollIntoView?.({ block: "nearest" });
  }, [selected]);

  function run(index: number) {
    const command = matches[index];
    if (!command || command.disabled) return;
    onClose();
    command.action();
  }

  return <div className="overlay palette-overlay" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
    <section className="palette" role="dialog" aria-modal="true" aria-label="Command palette">
      <div>
        <Command size={18} />
        <input
          autoFocus
          value={query}
          aria-label="Filter commands"
          aria-controls="palette-commands"
          placeholder="Type a command…"
          onChange={(event) => setQuery(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "ArrowDown") { event.preventDefault(); setSelected((value) => Math.min(value + 1, matches.length - 1)); }
            if (event.key === "ArrowUp") { event.preventDefault(); setSelected((value) => Math.max(value - 1, 0)); }
            if (event.key === "Enter") { event.preventDefault(); run(selected); }
            if (event.key === "Escape") onClose();
          }}
        />
        <button onClick={onClose} aria-label="Close command palette"><X size={16} /></button>
      </div>
      <div className="palette-list" id="palette-commands" role="listbox" aria-label="Commands" ref={list}>
        {matches.map((command, index) => <button
          key={command.label}
          role="option"
          aria-selected={selected === index}
          aria-disabled={command.disabled}
          className={`${selected === index ? "selected" : ""} ${command.disabled ? "is-unavailable" : ""}`}
          onMouseEnter={() => setSelected(index)}
          onClick={() => run(index)}
        ><command.icon size={16} /><span>{command.label}</span>{command.keys && <kbd>{command.keys}</kbd>}</button>)}
        {!matches.length && <p className="palette-empty">No command matches “{query.trim()}”.</p>}
      </div>
      <footer><span><kbd>↑↓</kbd> select</span><span><kbd>↵</kbd> run</span><b>{matches.length} of {commands.length}</b></footer>
    </section>
  </div>;
}
