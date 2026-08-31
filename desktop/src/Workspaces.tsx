import { useState } from "react";
import { LayoutGrid, Trash2, X } from "lucide-react";
import type { WorkspaceLayout } from "./types";

/**
 * Named layouts. A workspace is just the set of tabs and panes that were open,
 * so restoring one is re-opening notes — nothing is decrypted that the person
 * could not already open by hand.
 */
export function WorkspacesDialog({ layouts, tabCount, onClose, onSave, onOpen, onDelete }: {
  layouts: WorkspaceLayout[];
  tabCount: number;
  onClose: () => void;
  onSave: (name: string) => Promise<void>;
  onOpen: (layout: WorkspaceLayout) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
}) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await action();
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "That did not work.");
    } finally {
      setBusy(false);
    }
  }

  return <div className="overlay" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
    <section className="workspaces-dialog" role="dialog" aria-modal="true" aria-label="Workspaces">
      <header>
        <div className="new-note-icon"><LayoutGrid size={20} /></div>
        <button className="dialog-close" onClick={onClose} aria-label="Close workspaces"><X size={16} /></button>
      </header>
      <p className="eyebrow">SAVED LAYOUTS</p>
      <h2>Pick up where you left off.</h2>

      <div className="workspace-save">
        <input
          autoFocus
          aria-label="Workspace name"
          value={name}
          placeholder="Name this layout…"
          onChange={(event) => setName(event.target.value)}
          onKeyDown={(event) => { if (event.key === "Enter" && name.trim()) void run(async () => { await onSave(name.trim()); setName(""); }); }}
        />
        <button disabled={!name.trim() || busy} onClick={() => void run(async () => { await onSave(name.trim()); setName(""); })}>
          Save {tabCount} open {tabCount === 1 ? "tab" : "tabs"}
        </button>
      </div>
      {error && <p className="context-error" role="alert">{error}</p>}

      <ul className="workspace-list">
        {layouts.map((layout) => <li key={layout.id}>
          <button className="workspace-open" disabled={busy} aria-label={`Open ${layout.name}`} onClick={() => void run(() => onOpen(layout))}>
            <b>{layout.name}</b><small>{layout.tabs.length} {layout.tabs.length === 1 ? "tab" : "tabs"} · {layout.view}</small>
          </button>
          <button className="workspace-delete" disabled={busy} aria-label={`Delete ${layout.name}`} onClick={() => void run(() => onDelete(layout.id))}><Trash2 size={13} /></button>
        </li>)}
        {!layouts.length && <li className="workspace-empty">No layouts saved yet.</li>}
      </ul>
    </section>
  </div>;
}
