import { useState } from "react";
import { Copy, Hash, Link2, Plus, Sparkles, Tag, X } from "lucide-react";
import type { Backlink, NoteDocument, UnlinkedMention } from "./types";

export interface OutlineItem {
  level: number;
  text: string;
}

export function ContextPanel({ note, outline, backlinks, mentions, onOpen, onCopy, onAliases, onLink }: {
  note: NoteDocument;
  outline: OutlineItem[];
  backlinks: Backlink[];
  mentions: UnlinkedMention[];
  onOpen: (id: string) => void;
  onCopy: (label: string, value: string) => void;
  onAliases: (aliases: string[]) => void;
  onLink: (sourceId: string) => Promise<void>;
}) {
  const [draft, setDraft] = useState("");
  const [linking, setLinking] = useState("");
  const [error, setError] = useState("");

  function addAlias() {
    const value = draft.trim();
    if (!value) return;
    if (note.aliases.some((alias) => alias.toLocaleLowerCase() === value.toLocaleLowerCase())) {
      setError("That alias is already on this note.");
      return;
    }
    setError("");
    setDraft("");
    onAliases([...note.aliases, value]);
  }

  async function link(sourceId: string) {
    setLinking(sourceId);
    setError("");
    try {
      await onLink(sourceId);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Could not link that mention.");
    } finally {
      setLinking("");
    }
  }

  return <aside className="context-panel">
    <section><div className="context-heading"><span>PROPERTIES</span><i>{Object.keys(note.properties).length}</i></div>
      <dl className="property-list">{Object.entries(note.properties).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{String(value)}</dd>
        <button className="property-copy" aria-label={`Copy ${key}`} title="Copy to a self-clearing clipboard" onClick={() => onCopy(key, String(value))}><Copy size={11} /></button>
      </div>)}</dl>
      <div className="tag-list">{note.tags.map((tag) => <span key={tag}><Hash size={11} />{tag}</span>)}</div>
    </section>

    <section><div className="context-heading"><span>ALIASES</span><i>{note.aliases.length}</i></div>
      <div className="alias-list">{note.aliases.map((alias) => <span key={alias}><Tag size={11} />{alias}
        <button aria-label={`Remove alias ${alias}`} onClick={() => onAliases(note.aliases.filter((item) => item !== alias))}><X size={11} /></button>
      </span>)}</div>
      <div className="alias-add">
        <input
          aria-label="New alias"
          value={draft}
          placeholder="Another name for this note…"
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); addAlias(); } }}
        />
        <button onClick={addAlias} aria-label="Add alias"><Plus size={13} /></button>
      </div>
      <p className="context-hint">A note answers to every alias in search, links and the switcher.</p>
    </section>

    <section><div className="context-heading"><span>OUTLINE</span><i>{outline.length}</i></div>
      <ol className="outline-list">{outline.map((item, index) => <li key={`${item.text}-${index}`} style={{ paddingLeft: `${(item.level - 1) * 12}px` }}>{item.text}</li>)}</ol>
    </section>

    <section><div className="context-heading"><span>BACKLINKS</span><i>{backlinks.length}</i></div>
      <div className="backlink-list">{backlinks.length ? backlinks.map((item) => <button key={item.id} onClick={() => onOpen(item.id)}><Link2 size={13} /><span><b>{item.title}</b><small>{item.path}</small></span></button>) : <p>No notes point here yet.</p>}</div>
    </section>

    <section><div className="context-heading"><span>UNLINKED MENTIONS</span><i>{mentions.length}</i></div>
      {error && <p className="context-error" role="alert">{error}</p>}
      <div className="mention-list">{mentions.length ? mentions.map((mention) => <div key={mention.id} className="mention">
        <button className="mention-open" onClick={() => onOpen(mention.id)}><Sparkles size={13} /><span><b>{mention.title}</b><small>{mention.excerpt}</small></span></button>
        <button
          className="mention-link"
          disabled={linking === mention.id}
          onClick={() => void link(mention.id)}
          aria-label={`Link ${mention.count} mention${mention.count === 1 ? "" : "s"} in ${mention.title}`}
        >{linking === mention.id ? "Linking…" : `Link ${mention.count}×`}</button>
      </div>) : <p>Nothing names this note in passing.</p>}</div>
    </section>
  </aside>;
}
