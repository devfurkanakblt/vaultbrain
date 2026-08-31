import { useState } from "react";
import type { ReactNode } from "react";
import { ChevronDown, ChevronsDownUp, ChevronsUpDown, Copy, Hash, Link2, PanelRightClose, Plus, Puzzle, Sparkles, Tag, X } from "lucide-react";
import type { PluginPanel } from "./plugins/protocol";
import type { Backlink, NoteDocument, UnlinkedMention } from "./types";

const SECTIONS_KEY = "sbrain:context-sections";

/**
 * Which panel sections this device folded away. A missing entry means open, so
 * a fresh device and a corrupted value both land on everything visible. Section
 * names are structural, not vault content, so they stay in device storage
 * rather than the encrypted workspace state.
 */
function readFolded(): Record<string, boolean> {
  try {
    const raw = localStorage.getItem(SECTIONS_KEY);
    const parsed: unknown = raw ? JSON.parse(raw) : null;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const entries = Object.entries(parsed as Record<string, unknown>).filter(([, value]) => typeof value === "boolean");
    return Object.fromEntries(entries) as Record<string, boolean>;
  } catch {
    return {};
  }
}

/**
 * One panel card. Folding keeps the body mounted behind a height transition
 * and marks it inert, so a folded section cannot be reached by keyboard while
 * still animating open and closed.
 */
function Section({ label, badge, folded, onToggle, children }: {
  label: string;
  badge: ReactNode;
  folded: boolean;
  onToggle: () => void;
  children: ReactNode;
}) {
  return (
    <section className={`context-card ${folded ? "is-folded" : ""}`}>
      <button type="button" className="context-heading" aria-expanded={!folded} onClick={onToggle}>
        <span>{label}</span>
        <span className="context-heading-meta">
          {badge}
          <ChevronDown className="context-chevron" size={12} />
        </span>
      </button>
      <div className="context-card-slot">
        <div className="context-card-clip">
          <div className="context-card-inner" inert={folded}>{children}</div>
        </div>
      </div>
    </section>
  );
}

export interface OutlineItem {
  level: number;
  text: string;
  /** Zero-based line in the note body, so a click can reveal the heading. */
  line: number;
}

export function ContextPanel({ note, outline, backlinks, mentions, onOpen, onCopy, onAliases, onOutline, onClose, onLink, panels = [] }: {
  note: NoteDocument;
  outline: OutlineItem[];
  backlinks: Backlink[];
  mentions: UnlinkedMention[];
  onOpen: (id: string) => void;
  onCopy: (label: string, value: string) => void;
  onAliases: (aliases: string[]) => void;
  onOutline: (item: OutlineItem, index: number) => void;
  onClose: () => void;
  onLink: (sourceId: string) => Promise<void>;
  /** Contributed by sandboxed plugins. Rendered as text, never as markup. */
  panels?: PluginPanel[];
}) {
  const [folded, setFolded] = useState(readFolded);
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

  function remember(next: Record<string, boolean>) {
    try {
      localStorage.setItem(SECTIONS_KEY, JSON.stringify(next));
    } catch {
      /* a device that refuses storage still folds for this session */
    }
    return next;
  }

  function toggle(key: string) {
    setFolded((current) => remember({ ...current, [key]: !current[key] }));
  }

  function toggleAll() {
    const fold = !everyFolded;
    setFolded((current) => remember({ ...current, ...Object.fromEntries(sectionKeys.map((key) => [key, fold])) }));
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

  const sectionKeys = ["properties", "aliases", "outline", "backlinks", "mentions", ...panels.map((panel) => `plugin:${panel.pluginId}`)];
  const everyFolded = sectionKeys.every((key) => folded[key]);

  return <aside className="context-panel">
    <header className="context-panel-bar">
      <button
        type="button"
        className="context-panel-action"
        onClick={toggleAll}
        aria-label={everyFolded ? "Expand every section" : "Collapse every section"}
        title={everyFolded ? "Expand every section" : "Collapse every section"}
      >{everyFolded ? <ChevronsUpDown size={15} /> : <ChevronsDownUp size={15} />}</button>
      <button
        type="button"
        className="context-panel-action"
        onClick={onClose}
        aria-label="Hide the context panel"
        title="Hide the context panel"
      ><PanelRightClose size={15} /></button>
    </header>
    <Section label="PROPERTIES" badge={<i>{Object.keys(note.properties).length}</i>} folded={!!folded.properties} onToggle={() => toggle("properties")}>
      <dl className="property-list">{Object.entries(note.properties).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{String(value)}</dd>
        <button className="property-copy" aria-label={`Copy ${key}`} title="Copy to a self-clearing clipboard" onClick={() => onCopy(key, String(value))}><Copy size={11} /></button>
      </div>)}</dl>
      <div className="tag-list">{note.tags.map((tag) => <span key={tag}><Hash size={11} />{tag}</span>)}</div>
    </Section>

    <Section label="ALIASES" badge={<i>{note.aliases.length}</i>} folded={!!folded.aliases} onToggle={() => toggle("aliases")}>
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
    </Section>

    <Section label="OUTLINE" badge={<i>{outline.length}</i>} folded={!!folded.outline} onToggle={() => toggle("outline")}>
      <ol className="outline-list">{outline.map((item, index) => <li key={`${item.text}-${index}`} style={{ paddingLeft: `${(item.level - 1) * 12}px` }}>
        <button type="button" onClick={() => onOutline(item, index)}>{item.text}</button>
      </li>)}</ol>
    </Section>

    <Section label="BACKLINKS" badge={<i>{backlinks.length}</i>} folded={!!folded.backlinks} onToggle={() => toggle("backlinks")}>
      <div className="backlink-list">{backlinks.length ? backlinks.map((item) => <button key={item.id} onClick={() => onOpen(item.id)}><Link2 size={13} /><span><b>{item.title}</b><small>{item.path}</small></span></button>) : <p>No notes point here yet.</p>}</div>
    </Section>

    <Section label="UNLINKED MENTIONS" badge={<i>{mentions.length}</i>} folded={!!folded.mentions} onToggle={() => toggle("mentions")}>
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
    </Section>

    {panels.map((panel) => <Section
      key={panel.pluginId}
      label={panel.title.toUpperCase()}
      badge={<Puzzle size={12} />}
      folded={!!folded[`plugin:${panel.pluginId}`]}
      onToggle={() => toggle(`plugin:${panel.pluginId}`)}
    >
      <pre className="plugin-panel" title={`Contributed by ${panel.pluginName}`}>{panel.body}</pre>
    </Section>)}
  </aside>;
}
