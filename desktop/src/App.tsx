import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Archive,
  ArrowLeftRight,
  BookOpen,
  Check,
  ChevronDown,
  ChevronRight,
  CircleDot,
  Clock,
  Columns2,
  Command,
  Copy,
  FilePlus2,
  FileText,
  Folder,
  FolderOpen,
  LayoutGrid,
  LockKeyhole,
  Network,
  Palette,
  PanelRightClose,
  PanelRightOpen,
  Search,
  ShieldCheck,
  Sparkles,
  Star,
  TableProperties,
  X,
} from "lucide-react";
import { vaultBridge } from "./bridge";
import { ContextPanel } from "./ContextPanel";
import { KnowledgeGraph } from "./KnowledgeGraph";
import { PropertyTable } from "./PropertyTable";
import { QuickSwitcher } from "./QuickSwitcher";
import { clearOwnedClipboard, copyWithExpiry } from "./secure-clipboard";
import { ThemeEditor } from "./ThemeEditor";
import { WorkspacesDialog } from "./Workspaces";
import { applyTheme, clearTheme, DEFAULT_THEME, loadTheme, saveTheme, type ThemeSettings } from "./theme";
import { useVirtualWindow } from "./virtual";
import type { Backlink, Bookmark, KnowledgeGraph as GraphData, NoteDocument, NoteSummary, PropertyRow, SavedView, SaveState, SearchHit, UnlinkedMention, VaultInfo, WorkspaceLayout, WorkspaceState } from "./types";

const MarkdownEditor = lazy(() => import("./Editor").then((module) => ({ default: module.MarkdownEditor })));
const MarkdownPreview = lazy(() => import("./Preview"));

type ViewMode = "write" | "read";
type WorkspaceView = "notes" | "graph" | "properties";
type LockReason = "manual" | "inactivity";
type TreeRow =
  | { kind: "folder"; key: string; folder: string; count: number; open: boolean }
  | { kind: "note"; key: string; note: NoteSummary };

const IDLE_CHOICES = [1, 5, 15, 0];
const CLIPBOARD_TTL_MS = 30_000;
const TREE_ROW_HEIGHT = 30;

function relativeTime(iso: string) {
  const minutes = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 60000));
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  if (minutes < 1440) return `${Math.floor(minutes / 60)}h ago`;
  return `${Math.floor(minutes / 1440)}d ago`;
}

function summarize(note: NoteDocument): NoteSummary {
  return {
    id: note.id, path: note.path, title: note.title, aliases: note.aliases,
    tags: note.tags, updatedAt: note.updatedAt, revision: note.revision,
  };
}

function readIdlePreference() {
  const stored = Number(localStorage.getItem("sbrain:idle-lock"));
  return IDLE_CHOICES.includes(stored) ? stored : 5;
}

function folders(notes: NoteSummary[]) {
  const grouped = new Map<string, NoteSummary[]>();
  for (const note of notes) {
    const [folder = "Notes"] = note.path.split("/");
    const bucket = grouped.get(note.path.includes("/") ? folder : "Notes") ?? [];
    bucket.push(note);
    grouped.set(note.path.includes("/") ? folder : "Notes", bucket);
  }
  return [...grouped.entries()].sort(([a], [b]) => a.localeCompare(b));
}

function LockScreen({ notice, onUnlock }: { notice: string; onUnlock: (path: string, passphrase: string) => Promise<void> }) {
  const [path, setPath] = useState(localStorage.getItem("sbrain:last-vault") ?? "./vault/personal");
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await onUnlock(path, passphrase);
      setPassphrase("");
      localStorage.setItem("sbrain:last-vault", path);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="lock-screen">
      <div className="lock-grid" aria-hidden="true" />
      <section className={`unlock-panel ${busy ? "is-unlocking" : ""}`}>
        <div className="seal" aria-hidden="true">
          <span className="seal-ring seal-ring-one" />
          <span className="seal-ring seal-ring-two" />
          <LockKeyhole size={30} strokeWidth={1.45} />
        </div>
        <p className="eyebrow">SECOND BRAIN / LOCAL ARCHIVE</p>
        <h1>Your thoughts,<br /><em>under seal.</em></h1>
        <p className="unlock-copy">A fast workspace that stays yours. Unlocking happens on this device; the key never enters the interface.</p>
        {notice && <p className="lock-notice" role="status"><ShieldCheck size={14} />{notice}</p>}
        <form onSubmit={submit}>
          <label>
            <span>Vault location</span>
            <input value={path} onChange={(event) => setPath(event.target.value)} spellCheck={false} autoCapitalize="off" />
          </label>
          <label>
            <span>Passphrase</span>
            <input type="password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} autoFocus autoComplete="current-password" />
          </label>
          {error && <p className="form-error" role="alert">{error}</p>}
          <button className="unlock-button" disabled={busy || !path || !passphrase}>
            <span>{busy ? "Deriving session key…" : "Unlock workspace"}</span>
            <span className="button-mark">{busy ? <CircleDot className="spin" size={18} /> : <ShieldCheck size={18} />}</span>
          </button>
        </form>
        <div className="trust-line"><span /> AES-256-GCM · LOCAL ONLY · AUDITED ACCESS</div>
      </section>
      <aside className="lock-manifesto">
        <span className="manifesto-index">02</span>
        <blockquote>“Faster to recall.<br />Safer to trust.”</blockquote>
        <p>Nothing is uploaded to unlock this vault.</p>
      </aside>
    </main>
  );
}

export function App() {
  const [vault, setVault] = useState<VaultInfo>();
  const [notes, setNotes] = useState<NoteSummary[]>([]);
  const [active, setActive] = useState<NoteDocument>();
  const [secondary, setSecondary] = useState<NoteDocument>();
  const [openTabs, setOpenTabs] = useState<NoteSummary[]>([]);
  const [backlinks, setBacklinks] = useState<Backlink[]>([]);
  const [mode, setMode] = useState<ViewMode>("write");
  const [workspaceView, setWorkspaceView] = useState<WorkspaceView>("notes");
  const [graph, setGraph] = useState<GraphData>({ nodes: [], edges: [] });
  const [propertyRows, setPropertyRows] = useState<PropertyRow[]>([]);
  const [savedViews, setSavedViews] = useState<SavedView[]>([]);
  const [mentions, setMentions] = useState<UnlinkedMention[]>([]);
  const [bookmarks, setBookmarks] = useState<Bookmark[]>([]);
  const [layouts, setLayouts] = useState<WorkspaceLayout[]>([]);
  const [workspacesOpen, setWorkspacesOpen] = useState(false);
  const [saveState, setSaveState] = useState<SaveState>("saved");
  const [rightOpen, setRightOpen] = useState(true);
  const [expanded, setExpanded] = useState(new Set<string>());
  const [searchOpen, setSearchOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchHit[]>([]);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [quickOpen, setQuickOpen] = useState(false);
  const [newOpen, setNewOpen] = useState(false);
  const [notice, setNotice] = useState("");
  const [lockNotice, setLockNotice] = useState("");
  const [idleMinutes, setIdleMinutes] = useState(readIdlePreference);
  const [theme, setTheme] = useState<ThemeSettings>(loadTheme);
  const [themeOpen, setThemeOpen] = useState(false);
  const saveTimer = useRef<number | undefined>(undefined);

  const treeRows = useMemo<TreeRow[]>(() => folders(notes).flatMap(([folder, items]) => {
    const open = expanded.has(folder);
    const head: TreeRow = { kind: "folder", key: `folder:${folder}`, folder, count: items.length, open };
    return open ? [head, ...items.map((note): TreeRow => ({ kind: "note", key: note.id, note }))] : [head];
  }), [expanded, notes]);
  const tree = useVirtualWindow<HTMLElement>(treeRows.length, TREE_ROW_HEIGHT);

  useEffect(() => {
    applyTheme(theme);
    if (JSON.stringify(theme) === JSON.stringify(DEFAULT_THEME)) clearTheme(); else saveTheme(theme);
  }, [theme]);

  const refreshList = useCallback(async () => setNotes(await vaultBridge.listNotes()), []);

  const rememberTab = useCallback((note: NoteDocument) => {
    setOpenTabs((current) => current.some((tab) => tab.id === note.id)
      ? current.map((tab) => tab.id === note.id ? summarize(note) : tab)
      : [...current, summarize(note)]);
  }, []);

  const persistActive = useCallback(async () => {
    if (!active || (saveState !== "dirty" && saveState !== "error")) return true;
    setSaveState("saving");
    try {
      const saved = await vaultBridge.saveNote(active);
      setActive(saved);
      rememberTab(saved);
      setSaveState("saved");
      await refreshList();
      return true;
    } catch {
      setSaveState("error");
      return false;
    }
  }, [active, refreshList, rememberTab, saveState]);

  async function unlock(path: string, passphrase: string) {
    const info = await vaultBridge.unlock(path, passphrase);
    setVault(info);
    setLockNotice("");
    const listed = await vaultBridge.listNotes();
    setNotes(listed);
    setExpanded(new Set(listed.map((note) => note.path.split("/")[0])));
    const workspace = await vaultBridge.workspaceState();
    setBookmarks(workspace.bookmarks);
    setLayouts(workspace.layouts);
    if (listed[0]) await openNote(listed[0].id);
  }

  const openNote = useCallback(async (reference: string) => {
    if (active && active.id !== reference && !(await persistActive())) return;
    const note = await vaultBridge.getNote(reference);
    setActive(note);
    rememberTab(note);
    setSaveState("saved");
    const [links, named] = await Promise.all([vaultBridge.backlinks(note.id), vaultBridge.unlinkedMentions(note.id)]);
    setBacklinks(links);
    setMentions(named);
  }, [active, persistActive, rememberTab]);

  const openInSplit = useCallback(async (reference: string) => {
    const note = await vaultBridge.getNote(reference);
    setSecondary(note);
    rememberTab(note);
  }, [rememberTab]);

  const closeTab = useCallback(async (id: string) => {
    const index = openTabs.findIndex((tab) => tab.id === id);
    if (index < 0) return;
    if (active?.id === id && !(await persistActive())) return;
    const remaining = openTabs.filter((tab) => tab.id !== id);
    setOpenTabs(remaining);
    if (secondary?.id === id) setSecondary(undefined);
    if (active?.id !== id) return;
    const fallback = remaining[index] ?? remaining[index - 1];
    if (fallback) {
      const note = await vaultBridge.getNote(fallback.id);
      setActive(note);
      setSaveState("saved");
      setBacklinks(await vaultBridge.backlinks(note.id));
    } else {
      setActive(undefined);
      setBacklinks([]);
      setSaveState("saved");
    }
  }, [active, openTabs, persistActive, secondary]);

  const mutateActive = useCallback((change: Partial<NoteDocument>) => {
    setActive((current) => current ? { ...current, ...change } : current);
    setSaveState("dirty");
  }, []);

  const saveNow = useCallback(async () => { await persistActive(); }, [persistActive]);

  const copyGuarded = useCallback(async (label: string, value: string) => {
    try {
      await copyWithExpiry(value, CLIPBOARD_TTL_MS);
      setNotice(`${label} copied — the clipboard clears itself in ${CLIPBOARD_TTL_MS / 1000}s`);
    } catch (caught) {
      setNotice(caught instanceof Error ? caught.message : "Clipboard is unavailable.");
    }
  }, []);

  const lock = useCallback(async (reason: LockReason = "manual") => {
    if (active && (saveState === "dirty" || saveState === "error")) {
      setSaveState("saving");
      try {
        await vaultBridge.saveNote(active);
      } catch {
        setSaveState("error");
        return;
      }
    }
    await clearOwnedClipboard();
    await vaultBridge.lock();
    setVault(undefined); setNotes([]); setActive(undefined); setSecondary(undefined); setOpenTabs([]);
    setBacklinks([]); setMentions([]); setBookmarks([]); setLayouts([]); setWorkspacesOpen(false);
    setQuery(""); setResults([]); setNotice("");
    setSearchOpen(false); setPaletteOpen(false); setQuickOpen(false); setNewOpen(false); setThemeOpen(false);
    setWorkspaceView("notes"); setGraph({ nodes: [], edges: [] }); setPropertyRows([]); setSavedViews([]);
    setLockNotice(reason === "inactivity"
      ? `Locked automatically after ${idleMinutes} minute${idleMinutes === 1 ? "" : "s"} without activity. The clipboard was cleared too.`
      : "");
  }, [active, idleMinutes, saveState]);

  useEffect(() => {
    if (saveState !== "dirty") return;
    window.clearTimeout(saveTimer.current);
    saveTimer.current = window.setTimeout(() => void saveNow(), 700);
    return () => window.clearTimeout(saveTimer.current);
  }, [active?.body, active?.title, saveNow, saveState]);

  useEffect(() => {
    if (!notice) return;
    const timer = window.setTimeout(() => setNotice(""), 4200);
    return () => window.clearTimeout(timer);
  }, [notice]);

  useEffect(() => {
    if (!vault || idleMinutes <= 0) return;
    let timer = 0;
    const arm = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => void lock("inactivity"), idleMinutes * 60_000);
    };
    const events = ["keydown", "pointerdown", "wheel"] as const;
    for (const name of events) window.addEventListener(name, arm, true);
    arm();
    return () => {
      window.clearTimeout(timer);
      for (const name of events) window.removeEventListener(name, arm, true);
    };
  }, [idleMinutes, lock, vault]);

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      const control = event.ctrlKey || event.metaKey;
      const key = event.key.toLowerCase();
      if (control && key === "k") { event.preventDefault(); setPaletteOpen((value) => !value); }
      if (control && event.shiftKey && key === "f") { event.preventDefault(); setSearchOpen(true); }
      if (control && key === "o") { event.preventDefault(); setQuickOpen(true); }
      if (control && key === "s") { event.preventDefault(); void saveNow(); }
      if (control && key === "n") { event.preventDefault(); setNewOpen(true); }
      if (control && key === "e") { event.preventDefault(); setMode((value) => value === "write" ? "read" : "write"); }
      if (control && key === "l") { event.preventDefault(); void lock(); }
      if (control && key === "\\") { event.preventDefault(); if (active) void openInSplit(active.id); }
      if (control && key === "w") { event.preventDefault(); if (active) void closeTab(active.id); }
      if (event.key === "Escape") { setPaletteOpen(false); setSearchOpen(false); setNewOpen(false); setQuickOpen(false); setThemeOpen(false); }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [active, closeTab, lock, openInSplit, saveNow]);

  useEffect(() => {
    if (!query.trim()) { setResults([]); return; }
    const timer = window.setTimeout(async () => setResults(await vaultBridge.search(query)), 120);
    return () => window.clearTimeout(timer);
  }, [query]);

  const outline = useMemo(() => active?.body.split(/\r?\n/gu).flatMap((line) => {
    const match = /^(#{1,4})\s+(.+)/u.exec(line);
    return match ? [{ level: match[1].length, text: match[2] }] : [];
  }) ?? [], [active?.body]);

  async function create(path: string, title: string) {
    const note = await vaultBridge.createNote(path, title);
    await refreshList(); await openNote(note.id); setNewOpen(false);
  }

  async function showWorkspace(next: WorkspaceView) {
    setWorkspaceView(next);
    if (next === "graph") setGraph(await vaultBridge.graph());
    if (next === "properties") {
      const [rows, views] = await Promise.all([vaultBridge.propertyRows(), vaultBridge.savedViews()]);
      setPropertyRows(rows);
      setSavedViews(views);
    }
  }

  // A cell edit writes a whole note revision, so the open editor and the file
  // tree have to hear about it too — otherwise the next save would carry a
  // stale revision back to disk.
  async function editProperty(id: string, key: string, value: unknown) {
    const row = await vaultBridge.updateNoteProperty(id, key, value);
    setPropertyRows((rows) => rows.map((item) => (item.id === row.id ? row : item)));
    if (active?.id === id) setActive(await vaultBridge.getNote(id));
    await refreshList();
  }

  // Bookmarks and layouts live in one encrypted file, so every change writes the
  // whole small state back rather than needing a command per operation.
  async function commitWorkspace(next: WorkspaceState) {
    const stored = await vaultBridge.saveWorkspaceState(next);
    setBookmarks(stored.bookmarks);
    setLayouts(stored.layouts);
    return stored;
  }

  async function toggleBookmark() {
    if (!active) return;
    const pinned = bookmarks.some((bookmark) => bookmark.id === active.id);
    await commitWorkspace({
      version: 1,
      layouts,
      bookmarks: pinned
        ? bookmarks.filter((bookmark) => bookmark.id !== active.id)
        : [...bookmarks, { id: active.id, label: active.title, createdAt: "" }],
    });
    setNotice(pinned ? `Removed ${active.title} from bookmarks.` : `Bookmarked ${active.title}.`);
  }

  async function saveLayout(name: string) {
    const existing = layouts.find((layout) => layout.name.toLocaleLowerCase() === name.toLocaleLowerCase());
    const layout: WorkspaceLayout = {
      id: existing?.id ?? "",
      name,
      tabs: openTabs.map((tab) => tab.id),
      active: active?.id ?? null,
      secondary: secondary?.id ?? null,
      view: workspaceView,
      createdAt: existing?.createdAt ?? "",
      updatedAt: "",
    };
    await commitWorkspace({
      version: 1,
      bookmarks,
      layouts: existing ? layouts.map((item) => (item.id === existing.id ? layout : item)) : [...layouts, layout],
    });
    setNotice(`Saved the "${name}" workspace.`);
  }

  async function openLayout(layout: WorkspaceLayout) {
    if (!(await persistActive())) return;
    const known = new Map(notes.map((note) => [note.id, note]));
    setOpenTabs(layout.tabs.flatMap((id) => { const note = known.get(id); return note ? [note] : []; }));
    setSecondary(undefined);
    if (layout.active && known.has(layout.active)) await openNote(layout.active);
    if (layout.secondary && known.has(layout.secondary)) await openInSplit(layout.secondary);
    setWorkspaceView("notes");
    // Only the views this build knows about; a stored view name is not a cast.
    if (layout.view === "graph" || layout.view === "properties") await showWorkspace(layout.view);
    setWorkspacesOpen(false);
    setNotice(`Opened the "${layout.name}" workspace.`);
  }

  async function deleteLayout(id: string) {
    await commitWorkspace({ version: 1, bookmarks, layouts: layouts.filter((layout) => layout.id !== id) });
  }

  async function linkMention(sourceId: string) {
    if (!active) return;
    setMentions(await vaultBridge.linkMention(sourceId, active.id));
    setBacklinks(await vaultBridge.backlinks(active.id));
    await refreshList();
  }

  function openFromKnowledge(id: string) {
    setWorkspaceView("notes");
    void openNote(id);
  }

  function cycleIdleLock() {
    const next = IDLE_CHOICES[(IDLE_CHOICES.indexOf(idleMinutes) + 1) % IDLE_CHOICES.length];
    setIdleMinutes(next);
    localStorage.setItem("sbrain:idle-lock", String(next));
    setNotice(next ? `Auto-lock set to ${next} minute${next === 1 ? "" : "s"} of inactivity.` : "Auto-lock disabled for this device.");
  }

  async function promoteSplit() {
    if (!secondary) return;
    const promoted = secondary.id;
    setSecondary(active);
    await openNote(promoted);
  }

  if (!vault) return <LockScreen notice={lockNotice} onUnlock={unlock} />;

  return (
    <main className={`workspace-shell ${workspaceView !== "notes" || !rightOpen ? "without-context" : ""}`}>
      <header className="topbar" data-tauri-drag-region>
        <div className="brand-mark"><span>SB</span><i>02</i></div>
        <button className="vault-switch" title="Current encrypted vault">
          <Archive size={15} /><span>{vault.name}</span><ChevronDown size={13} />
        </button>
        <div className="topbar-center"><ShieldCheck size={14} /><span>Unlocked locally</span><i /></div>
        <div className="top-actions">
          <button onClick={() => setQuickOpen(true)} title="Quick switcher (Ctrl+O)"><FileText size={17} /></button>
          <button onClick={() => setSearchOpen(true)} title="Search vault (Ctrl+Shift+F)"><Search size={17} /></button>
          <button onClick={() => setPaletteOpen(true)} className="command-trigger"><Command size={15} /><kbd>⌘ K</kbd></button>
          <button onClick={() => void lock()} title="Lock vault"><LockKeyhole size={17} /></button>
        </div>
      </header>

      <aside className="nav-panel">
        <div className="nav-heading"><span>ARCHIVE</span><button onClick={() => setNewOpen(true)} title="New note"><FilePlus2 size={16} /></button></div>
        <div className="workspace-modes" role="group" aria-label="Workspace view">
          <button className={workspaceView === "notes" ? "active" : ""} onClick={() => void showWorkspace("notes")}><FileText size={14} /><span>Notes</span></button>
          <button className={workspaceView === "graph" ? "active" : ""} onClick={() => void showWorkspace("graph")}><Network size={14} /><span>Graph</span></button>
          <button className={workspaceView === "properties" ? "active" : ""} onClick={() => void showWorkspace("properties")}><TableProperties size={14} /><span>Data</span></button>
        </div>
        <button className="quick-find" onClick={() => setSearchOpen(true)}><Search size={15} /><span>Find anything…</span><kbd>⇧⌘F</kbd></button>
        {bookmarks.length > 0 && <div className="bookmark-block">
          <div className="nav-subheading"><span>BOOKMARKS</span><i>{bookmarks.length}</i></div>
          <nav aria-label="Bookmarked notes">{bookmarks.map((bookmark) => <button
            key={bookmark.id}
            className={active?.id === bookmark.id && workspaceView === "notes" ? "bookmark-row active" : "bookmark-row"}
            onClick={() => { setWorkspaceView("notes"); void openNote(bookmark.id); }}
          ><Star size={12} />{bookmark.label || bookmark.id}</button>)}</nav>
        </div>}
        <nav className="file-tree" aria-label="Vault notes" ref={tree.ref} onScroll={tree.onScroll}>
          <div style={{ height: tree.topPad }} aria-hidden="true" />
          {treeRows.slice(tree.start, tree.end).map((row) => row.kind === "folder"
            ? <button key={row.key} className="folder-row" aria-expanded={row.open} onClick={() => setExpanded((current) => {
                const next = new Set(current); row.open ? next.delete(row.folder) : next.add(row.folder); return next;
              })}>
                {row.open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                {row.open ? <FolderOpen size={15} /> : <Folder size={15} />}<span>{row.folder}</span><i>{row.count}</i>
              </button>
            : <button key={row.key} className={active?.id === row.note.id && workspaceView === "notes" ? "note-row active" : "note-row"} onClick={() => { setWorkspaceView("notes"); void openNote(row.note.id); }}>
                <FileText size={14} /><span>{row.note.title}</span>{row.note.tags.includes("evergreen") && <Sparkles size={12} />}
              </button>)}
          <div style={{ height: tree.bottomPad }} aria-hidden="true" />
        </nav>
        <div className="nav-footer">
          <div className="footer-controls">
            <button className="idle-lock" onClick={cycleIdleLock} title="Lock the vault after a period without activity">
              <Clock size={12} /><span>Auto-lock</span><b>{idleMinutes ? `${idleMinutes}m` : "off"}</b>
            </button>
            <button className="theme-open" onClick={() => setThemeOpen(true)} title="Customize theme"><Palette size={12} /></button>
          </div>
          <div className="capacity"><span style={{ width: "18%" }} /></div>
          <p><b>{notes.length}</b> encrypted notes <span>·</span> local</p>
        </div>
      </aside>

      {workspaceView === "notes" ? <section className="document-stage">
        {openTabs.length > 0 && <div className="tab-strip" role="tablist" aria-label="Open notes">
          {openTabs.map((tab) => <span key={tab.id} className={`tab ${active?.id === tab.id ? "active" : ""} ${secondary?.id === tab.id ? "in-split" : ""}`}>
            <button role="tab" aria-selected={active?.id === tab.id} onClick={() => void openNote(tab.id)} onAuxClick={(event) => { if (event.button === 1) void closeTab(tab.id); }}>
              <FileText size={12} /><span>{tab.title}</span>
            </button>
            <button className="tab-close" aria-label={`Close ${tab.title}`} onClick={() => void closeTab(tab.id)}><X size={11} /></button>
          </span>)}
          <button className="tab-add" onClick={() => setNewOpen(true)} aria-label="New note in a tab"><FilePlus2 size={13} /></button>
        </div>}

        <div className={`stage-panes ${secondary ? "is-split" : ""}`}>
          <article className="stage-pane" aria-label="Primary pane">
            {active ? <>
              <div className="document-toolbar">
                <div className="breadcrumbs"><span>{active.path.split("/").slice(0, -1).join(" / ") || "Notes"}</span><ChevronRight size={13} /><b>{active.path.split("/").at(-1)}</b></div>
                <div className="view-toggle" role="group" aria-label="Document view">
                  <button className={mode === "write" ? "active" : ""} onClick={() => setMode("write")}>Write</button>
                  <button className={mode === "read" ? "active" : ""} onClick={() => setMode("read")}>Read</button>
                </div>
                <div className="toolbar-actions">
                  <button
                    className={bookmarks.some((bookmark) => bookmark.id === active.id) ? "bookmarked" : ""}
                    onClick={() => void toggleBookmark()}
                    aria-pressed={bookmarks.some((bookmark) => bookmark.id === active.id)}
                    title={bookmarks.some((bookmark) => bookmark.id === active.id) ? "Remove bookmark" : "Bookmark this note"}
                  ><Star size={16} /></button>
                  <button onClick={() => void copyGuarded("Note", active.body)} title="Copy note to a self-clearing clipboard"><Copy size={16} /></button>
                  <button onClick={() => void openInSplit(active.id)} title="Open in split pane (Ctrl+\)"><Columns2 size={16} /></button>
                  <button className="context-toggle" onClick={() => setRightOpen((value) => !value)} title="Toggle context panel">
                    {rightOpen ? <PanelRightClose size={17} /> : <PanelRightOpen size={17} />}
                  </button>
                </div>
              </div>
              <div className="document-title-wrap">
                <input className="document-title" value={active.title} onChange={(event) => mutateActive({ title: event.target.value })} aria-label="Note title" />
                <div className="document-meta"><span>REV {String(active.revision).padStart(2, "0")}</span><i /> <span>{active.body.trim().split(/\s+/u).length} WORDS</span><i /> <span>UPDATED {relativeTime(active.updatedAt).toUpperCase()}</span></div>
              </div>
              <div className="document-body">
                <Suspense fallback={<div className="document-loading">Preparing document…</div>}>
                  {mode === "write" ? <MarkdownEditor value={active.body} onChange={(body) => mutateActive({ body })} /> :
                    <MarkdownPreview body={active.body} />}
                </Suspense>
              </div>
            </> : <div className="empty-stage"><BookOpen size={34} /><h2>The archive is quiet.</h2><p>Create a note to begin.</p></div>}
          </article>

          {secondary && <article className="stage-pane split-pane" aria-label="Split pane">
            <div className="document-toolbar">
              <div className="breadcrumbs"><span>SPLIT</span><ChevronRight size={13} /><b>{secondary.title}</b></div>
              <div className="toolbar-actions">
                <button onClick={() => void promoteSplit()} title="Swap this pane with the editor"><ArrowLeftRight size={16} /></button>
                <button onClick={() => setSecondary(undefined)} aria-label="Close split pane"><X size={16} /></button>
              </div>
            </div>
            <div className="document-body">
              <Suspense fallback={<div className="document-loading">Preparing document…</div>}>
                <MarkdownPreview body={secondary.body} />
              </Suspense>
            </div>
          </article>}
        </div>

        {active && <footer className="statusbar">
          <div className={`save-state ${saveState}`}><span />{saveState === "saved" ? "Encrypted & saved" : saveState === "saving" ? "Encrypting…" : saveState === "error" ? "Save failed" : "Unsaved changes"}</div>
          <div><span>UTF-8</span><span>MARKDOWN</span><span>Ln {active.body.split("\n").length}</span></div>
        </footer>}
      </section> : workspaceView === "graph" ? <KnowledgeGraph graph={graph} onOpen={openFromKnowledge} /> : <PropertyTable
        rows={propertyRows}
        views={savedViews}
        onOpen={openFromKnowledge}
        onSaveView={async (view) => setSavedViews(await vaultBridge.saveView(view))}
        onDeleteView={async (id) => setSavedViews(await vaultBridge.deleteView(id))}
        onEditProperty={editProperty}
      />}

      {workspaceView === "notes" && rightOpen && active && <ContextPanel
        note={active}
        outline={outline}
        backlinks={backlinks}
        mentions={mentions}
        onOpen={(id) => void openNote(id)}
        onCopy={(label, value) => void copyGuarded(label, value)}
        onAliases={(aliases) => mutateActive({ aliases })}
        onLink={linkMention} />}

      {notice && <div className="toast" role="status"><Check size={14} />{notice}</div>}

      {quickOpen && <QuickSwitcher notes={notes} onClose={() => setQuickOpen(false)}
        onOpen={(id) => { setWorkspaceView("notes"); void openNote(id); }}
        onSplit={(id) => { setWorkspaceView("notes"); void openInSplit(id); }} />}

      {searchOpen && <div className="overlay" onMouseDown={(event) => event.target === event.currentTarget && setSearchOpen(false)}>
        <section className="search-dialog" role="dialog" aria-modal="true" aria-label="Search vault">
          <div className="dialog-search"><Search size={20} /><input autoFocus value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search titles, text, tags…" /><button onClick={() => setSearchOpen(false)}><X size={17} /></button></div>
          <div className="search-results">{query && !results.length ? <p className="no-results">No encrypted notes match “{query}”.</p> : results.map((hit) => <button key={hit.id} onClick={() => { void openNote(hit.id); setSearchOpen(false); }}><div><FileText size={15} /><b>{hit.title}</b><span>{hit.path}</span><i>{Math.round(hit.score)}</i></div><p>{hit.excerpt}</p></button>)}</div>
          <footer><span><kbd>↵</kbd> open</span><span><kbd>esc</kbd> close</span><b>{results.length} results</b></footer>
        </section>
      </div>}

      {paletteOpen && <div className="overlay palette-overlay" onMouseDown={(event) => event.target === event.currentTarget && setPaletteOpen(false)}>
        <section className="palette" role="dialog" aria-modal="true" aria-label="Command palette"><div><Command size={18} /><input autoFocus placeholder="Type a command…" /><kbd>ESC</kbd></div>
          {[
            { icon: FilePlus2, label: "Create new note", keys: "⌘ N", action: () => setNewOpen(true) },
            { icon: FileText, label: "Quick switch to a note", keys: "⌘ O", action: () => setQuickOpen(true) },
            { icon: Search, label: "Search encrypted vault", keys: "⇧⌘ F", action: () => setSearchOpen(true) },
            { icon: Columns2, label: "Open current note in split pane", keys: "⌘ \\", action: () => { if (active) void openInSplit(active.id); } },
            { icon: Network, label: "Open local graph", keys: "", action: () => void showWorkspace("graph") },
            { icon: TableProperties, label: "Open property view", keys: "", action: () => void showWorkspace("properties") },
            { icon: BookOpen, label: mode === "write" ? "Switch to reading view" : "Switch to writing view", keys: "⌘ E", action: () => setMode(mode === "write" ? "read" : "write") },
            { icon: LayoutGrid, label: "Workspaces and saved layouts", keys: "", action: () => setWorkspacesOpen(true) },
            { icon: Palette, label: "Customize theme", keys: "", action: () => setThemeOpen(true) },
            { icon: Clock, label: "Change auto-lock delay", keys: "", action: () => cycleIdleLock() },
            { icon: LockKeyhole, label: "Lock workspace", keys: "⌘ L", action: () => void lock() },
          ].map((item, index) => <button key={item.label} className={index === 0 ? "selected" : ""} onClick={() => { item.action(); setPaletteOpen(false); }}><item.icon size={16} /><span>{item.label}</span>{item.keys && <kbd>{item.keys}</kbd>}</button>)}
        </section>
      </div>}

      {themeOpen && <ThemeEditor settings={theme} onChange={setTheme} onClose={() => setThemeOpen(false)} />}

      {newOpen && <NewNoteDialog onClose={() => setNewOpen(false)} onCreate={create} />}
      {workspacesOpen && <WorkspacesDialog
        layouts={layouts}
        tabCount={openTabs.length}
        onClose={() => setWorkspacesOpen(false)}
        onSave={saveLayout}
        onOpen={openLayout}
        onDelete={deleteLayout} />}
    </main>
  );
}

function NewNoteDialog({ onClose, onCreate }: { onClose: () => void; onCreate: (path: string, title: string) => Promise<void> }) {
  const [title, setTitle] = useState("");
  const [path, setPath] = useState("Inbox/");
  const [busy, setBusy] = useState(false);
  async function submit(event: React.FormEvent) {
    event.preventDefault(); setBusy(true);
    try { await onCreate(`${path}${title}`, title); } finally { setBusy(false); }
  }
  return <div className="overlay" onMouseDown={(event) => event.target === event.currentTarget && onClose()}><form className="new-note-dialog" onSubmit={submit}><div className="new-note-icon"><FilePlus2 size={20} /></div><p className="eyebrow">NEW ENCRYPTED NOTE</p><h2>Give the thought a home.</h2><label><span>Title</span><input autoFocus value={title} onChange={(event) => setTitle(event.target.value)} placeholder="Untitled idea" /></label><label><span>Folder</span><input value={path} onChange={(event) => setPath(event.target.value)} /></label><div><button type="button" onClick={onClose}>Cancel</button><button disabled={!title.trim() || busy}>{busy ? "Creating…" : "Create note"}</button></div></form></div>;
}
