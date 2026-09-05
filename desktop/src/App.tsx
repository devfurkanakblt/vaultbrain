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
  FolderKanban,
  FolderOpen,
  History,
  LayoutGrid,
  LockKeyhole,
  Network,
  Palette,
  PencilLine,
  PanelRightClose,
  PanelRightOpen,
  Paperclip,
  Puzzle,
  RefreshCw,
  Search,
  ShieldCheck,
  Sparkles,
  Star,
  Sun,
  TableProperties,
  Trash2,
  TriangleAlert,
  X,
} from "lucide-react";
import { AttachmentLibrary } from "./AttachmentLibrary";
import { vaultBridge } from "./bridge";
import { CommandPalette, type PaletteCommand } from "./CommandPalette";
import { useConfirm } from "./Confirm";
import { CanvasBoard } from "./CanvasBoard";
import { ContextPanel } from "./ContextPanel";
import type { OutlineItem } from "./ContextPanel";
import { KnowledgeGraph } from "./KnowledgeGraph";
import { HistoryDialog, RenameDialog, TemplateDialog, TrashDialog } from "./NoteLifecycle";
import { PluginManager } from "./PluginManager";
import { PluginHost } from "./plugins/host";
import type { PluginPanel, PluginRuntimeState, RegisteredCommand } from "./plugins/protocol";
import { PropertyTable } from "./PropertyTable";
import { QuickSwitcher } from "./QuickSwitcher";
import { clearOwnedClipboard, copyWithExpiry } from "./secure-clipboard";
import { SyncStatus } from "./SyncStatus";
import { ThemeEditor } from "./ThemeEditor";
import { WorkspacesDialog } from "./Workspaces";
import { applyTheme, clearTheme, DEFAULT_THEME, loadTheme, saveTheme, type ThemeSettings } from "./theme";
import { useVirtualWindow } from "./virtual";
import type { AttachmentInfo, Backlink, Bookmark, CanvasSummary, DeletedNote, KnowledgeGraph as GraphData, NoteDocument, NoteSummary, PluginSecurityPolicy, PluginSummary, PropertyRow, SavedView, SaveState, SearchHit, SyncStatusData, UnlinkedMention, NoticeTone, Notify, VaultInfo, WorkspaceLayout, WorkspaceState } from "./types";

const MarkdownEditor = lazy(() => import("./Editor").then((module) => ({ default: module.MarkdownEditor })));
const MarkdownPreview = lazy(() => import("./Preview"));

type ViewMode = "write" | "read";
type WorkspaceView = "notes" | "graph" | "properties" | "canvas" | "files" | "plugins" | "sync";
type LockReason = "manual" | "inactivity";
/**
 * A message and how it should read. Success and failure shared one green tick
 * before this, so a save that failed announced itself as a save that worked.
 */
type Notice = { text: string; tone: NoticeTone };
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
  const stored = Number(localStorage.getItem("vbrain:idle-lock"));
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

const DEFAULT_VAULT_PATH = "./vault/personal";
const VAULT_HISTORY_KEY = "vbrain:vaults";
const LEGACY_VAULT_KEY = "vbrain:last-vault";
const VAULT_HISTORY_LIMIT = 5;

/**
 * The vault paths this device has unlocked before, most recent first. Only
 * paths are kept, never a passphrase, and the list stays on this device: it is
 * a convenience for the person at the keyboard, not vault content.
 */
function readVaultHistory(): string[] {
  try {
    const stored = localStorage.getItem(VAULT_HISTORY_KEY);
    const parsed: unknown = stored ? JSON.parse(stored) : [];
    const paths = Array.isArray(parsed) ? parsed.filter((entry): entry is string => typeof entry === "string") : [];
    const legacy = localStorage.getItem(LEGACY_VAULT_KEY);
    if (legacy && !paths.includes(legacy)) paths.push(legacy);
    return paths.slice(0, VAULT_HISTORY_LIMIT);
  } catch {
    return [];
  }
}

function rememberVault(path: string) {
  try {
    const next = [path, ...readVaultHistory().filter((entry) => entry !== path)].slice(0, VAULT_HISTORY_LIMIT);
    localStorage.setItem(VAULT_HISTORY_KEY, JSON.stringify(next));
    localStorage.setItem(LEGACY_VAULT_KEY, path);
  } catch {
    /* a device that refuses storage still unlocks for this session */
  }
}

function LockScreen({ notice, onUnlock }: { notice: string; onUnlock: (path: string, passphrase: string) => Promise<void> }) {
  const history = useMemo(readVaultHistory, []);
  const [path, setPath] = useState(() => history[0] ?? DEFAULT_VAULT_PATH);
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [choosing, setChoosing] = useState(false);
  const [error, setError] = useState("");
  const target = path.trim();
  // The core creates a vault at any path it cannot open, so a typo reads as an
  // empty vault rather than an error. This device cannot tell the two apart
  // without unlocking, so it says plainly which paths it has seen before.
  const unfamiliar = target.length > 0 && !history.includes(target);
  // The field already shows where it points, so the list only earns its space
  // by offering somewhere else to go.
  const elsewhere = history.filter((entry) => entry !== target);

  async function chooseFolder() {
    setChoosing(true);
    setError("");
    try {
      const picked = await vaultBridge.pickVaultDirectory();
      if (picked) setPath(picked);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setChoosing(false);
    }
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await onUnlock(target, passphrase);
      setPassphrase("");
      rememberVault(target);
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
        <p className="eyebrow">VAULT BRAIN / LOCAL ARCHIVE</p>
        <h1>Your thoughts,<br /><em>under seal.</em></h1>
        <p className="unlock-copy">A fast workspace that stays yours. Unlocking happens on this device; the key never enters the interface.</p>
        {notice && <p className="lock-notice" role="status"><ShieldCheck size={14} />{notice}</p>}
        <form onSubmit={submit}>
          <div className="field-with-action">
            <label>
              <span>Vault location</span>
              <input
                value={path}
                onChange={(event) => setPath(event.target.value)}
                spellCheck={false}
                autoCapitalize="off"
                className={unfamiliar ? "is-flagged" : undefined}
                aria-describedby={unfamiliar ? "vault-unfamiliar" : undefined}
              />
            </label>
            <button
              type="button"
              className="input-action"
              onClick={chooseFolder}
              disabled={choosing}
              title="Choose a folder on this computer"
              aria-label="Choose a vault folder"
            >
              {choosing ? <CircleDot className="spin" size={15} /> : <Folder size={15} />}
            </button>
          </div>
          <div className={`vault-hint-slot ${unfamiliar ? "is-open" : ""}`} aria-hidden={!unfamiliar}>
            <span className="vault-hint-link" aria-hidden="true" />
            <div className="vault-hint-clip">
              <p className="vault-hint" id="vault-unfamiliar">
                <FilePlus2 size={13} />
                <span>
                  This device has not opened <b>{target}</b> before. If a vault already lives there, your passphrase opens it. If not,
                  a new empty vault is created and sealed with the passphrase you type — so check the path before continuing.
                </span>
              </p>
            </div>
          </div>
          {elsewhere.length > 0 && (
            <div className="vault-recents">
              <span className="vault-recents-label">Switch to</span>
              <div className="vault-recent-list">
                {elsewhere.map((entry) => (
                  <button key={entry} type="button" className="vault-recent" onClick={() => setPath(entry)} title={entry}>
                    <FolderOpen size={12} />
                    <span>{entry}</span>
                  </button>
                ))}
              </div>
            </div>
          )}
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
  const [canvases, setCanvases] = useState<CanvasSummary[]>([]);
  const [attachments, setAttachments] = useState<AttachmentInfo[]>([]);
  const [mentions, setMentions] = useState<UnlinkedMention[]>([]);
  const [bookmarks, setBookmarks] = useState<Bookmark[]>([]);
  const [layouts, setLayouts] = useState<WorkspaceLayout[]>([]);
  const [workspacesOpen, setWorkspacesOpen] = useState(false);
  const [saveState, setSaveState] = useState<SaveState>("saved");
  const [rightOpen, setRightOpen] = useState(true);
  const [entering, setEntering] = useState(false);
  const [expanded, setExpanded] = useState(new Set<string>());
  const [searchOpen, setSearchOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchHit[]>([]);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [quickOpen, setQuickOpen] = useState(false);
  const [newOpen, setNewOpen] = useState(false);
  const [renameOpen, setRenameOpen] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [trashOpen, setTrashOpen] = useState(false);
  const [templateOpen, setTemplateOpen] = useState(false);
  const [templates, setTemplates] = useState<NoteSummary[]>([]);
  const [plugins, setPlugins] = useState<PluginSummary[]>([]);
  const [pluginPolicy, setPluginPolicy] = useState<PluginSecurityPolicy>({ version: 1, restrictedMode: false, revokedSigners: [] });
  const [pluginStates, setPluginStates] = useState<PluginRuntimeState[]>([]);
  const [pluginCommands, setPluginCommands] = useState<RegisteredCommand[]>([]);
  const [pluginPanels, setPluginPanels] = useState<PluginPanel[]>([]);
  const pluginHost = useRef<PluginHost>(undefined);
  const [reveal, setReveal] = useState<{ line: number; token: number }>();
  const revealToken = useRef(0);
  const documentBody = useRef<HTMLDivElement>(null);
  const [syncStatus, setSyncStatus] = useState<SyncStatusData | null>(null);
  const [syncRegistryVerified, setSyncRegistryVerified] = useState<boolean | null>(null);
  const [vaultMenuOpen, setVaultMenuOpen] = useState(false);
  const [notice, setNotice] = useState<Notice>();
  const report = useCallback<Notify>((text, tone = "info") => setNotice({ text, tone }), []);
  const fail = useCallback((caught: unknown, fallback = "Something went wrong.") => {
    setNotice({ text: caught instanceof Error ? caught.message : String(caught) || fallback, tone: "error" });
  }, []);
  const [confirm, confirmDialog] = useConfirm();
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
  const spread = useMemo(
    () => folders(notes).map(([folder, items]) => [folder, items.length] as const).sort((left, right) => right[1] - left[1]),
    [notes],
  );

  useEffect(() => {
    applyTheme(theme);
    if (JSON.stringify(theme) === JSON.stringify(DEFAULT_THEME)) clearTheme(); else saveTheme(theme);
  }, [theme]);

  const refreshList = useCallback(async () => setNotes(await vaultBridge.listNotes()), []);

  /**
   * The host's whole reach into the app. A plugin method that is not spelled
   * out here cannot be served at all, whatever its manifest claims — the
   * capability table decides what may be asked for, and this decides what
   * exists to answer.
   */
  const host = useCallback(() => {
    pluginHost.current ??= new PluginHost({
      authorize: (pluginId, revision) => vaultBridge.authorizePluginInstance(pluginId, revision),
      call: (context, method, params) => vaultBridge.pluginCall(context, method, params),
      onNotice: (name, message, tone) => setNotice({ text: `${name}: ${message}`, tone: tone ?? "info" }),
      onCommandsChanged: setPluginCommands,
      onPanelsChanged: setPluginPanels,
      onStateChanged: setPluginStates,
    });
    return pluginHost.current;
  }, []);

  /**
   * Source is fetched only for the plugins that are actually enabled, so a
   * disabled plugin's code never even enters the webview.
   */
  const refreshPlugins = useCallback(async () => {
    const [listed, policy] = await Promise.all([vaultBridge.plugins(), vaultBridge.pluginSecurityPolicy()]);
    setPlugins(listed);
    setPluginPolicy(policy);
    const runnable = await Promise.all(
      listed.filter((plugin) => plugin.enabled).map(async (summary) => ({
        summary,
        source: (await vaultBridge.getPlugin(summary.id)).source,
      }))
    );
    await host().sync([...runnable, ...listed.filter((plugin) => !plugin.enabled).map((summary) => ({ summary, source: "" }))]);
    return listed;
  }, [host]);

  // Canvas nodes point at attachments and notes by id, so the two lists are
  // reloaded together: a stale attachment list draws a live node as missing.
  const refreshAssets = useCallback(async () => {
    const [boards, files] = await Promise.all([vaultBridge.canvases(), vaultBridge.attachments()]);
    setCanvases(boards);
    setAttachments(files);
  }, []);

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

  const openDaily = useCallback(async () => {
    try {
      const daily = await vaultBridge.dailyNote();
      await refreshList();
      setWorkspaceView("notes");
      await openNote(daily.note.id);
      report(daily.created ? `Created today's note at ${daily.note.path}.` : `Opened today's note.`);
    } catch (caught) {
      fail(caught);
    }
  }, [openNote, refreshList]);

  const copyGuarded = useCallback(async (label: string, value: string) => {
    try {
      await copyWithExpiry(value, CLIPBOARD_TTL_MS);
      report(`${label} copied — the clipboard clears itself in ${CLIPBOARD_TTL_MS / 1000}s`);
    } catch (caught) {
      fail(caught, "Clipboard is unavailable.");
    }
  }, [fail, report]);

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
    setQuery(""); setResults([]); setNotice(undefined);
    setSearchOpen(false); setPaletteOpen(false); setQuickOpen(false); setNewOpen(false); setThemeOpen(false);
    setRenameOpen(false); setHistoryOpen(false); setTrashOpen(false); setTemplateOpen(false); setTemplates([]);
    pluginHost.current?.stopAll();
    setPlugins([]); setPluginStates([]); setPluginCommands([]); setPluginPanels([]);
    setWorkspaceView("notes"); setGraph({ nodes: [], edges: [] }); setPropertyRows([]); setSavedViews([]);
    setCanvases([]); setAttachments([]); setSyncStatus(null); setSyncRegistryVerified(null);
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

  // Two frames: the first paints the entry state, the second releases it so
  // the transition has a real style change to animate from.
  useEffect(() => {
    if (!active?.id) return;
    setEntering(true);
    let release = 0;
    const paint = window.requestAnimationFrame(() => {
      release = window.requestAnimationFrame(() => setEntering(false));
    });
    return () => {
      window.cancelAnimationFrame(paint);
      window.cancelAnimationFrame(release);
    };
  }, [active?.id]);

  useEffect(() => {
    if (!notice) return;
    // A failure is worth reading twice; a confirmation is not.
    const timer = window.setTimeout(() => setNotice(undefined), notice.tone === "error" ? 7000 : 4200);
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
      if (control && key === "d") { event.preventDefault(); void openDaily(); }
      if (event.key === "Escape") {
        setPaletteOpen(false); setSearchOpen(false); setNewOpen(false); setQuickOpen(false); setThemeOpen(false);
        setRenameOpen(false); setHistoryOpen(false); setTrashOpen(false); setTemplateOpen(false);
        setVaultMenuOpen(false);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [active, closeTab, lock, openDaily, openInSplit, saveNow]);

  useEffect(() => {
    if (!query.trim()) { setResults([]); return; }
    const timer = window.setTimeout(async () => setResults(await vaultBridge.search(query)), 120);
    return () => window.clearTimeout(timer);
  }, [query]);

  // Fenced blocks are skipped so a shell comment inside one is not mistaken for
  // a heading, which would both pad the outline and misalign reading-view jumps.
  const outline = useMemo<OutlineItem[]>(() => {
    const items: OutlineItem[] = [];
    let fenced = false;
    (active?.body.split(/\r?\n/gu) ?? []).forEach((line, index) => {
      if (/^\s*(?:```|~~~)/u.test(line)) {
        fenced = !fenced;
        return;
      }
      if (fenced) return;
      const match = /^(#{1,4})\s+(.+)/u.exec(line);
      if (match) items.push({ level: match[1].length, text: match[2], line: index });
    });
    return items;
  }, [active?.body]);

  /** Reveal a heading in whichever view is showing the note. */
  const revealHeading = useCallback((item: OutlineItem, index: number) => {
    if (mode === "write") {
      revealToken.current += 1;
      setReveal({ line: item.line, token: revealToken.current });
      return;
    }
    documentBody.current?.querySelectorAll("h1, h2, h3, h4").item(index)?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [mode]);

  async function create(path: string, title: string) {
    const note = await vaultBridge.createNote(path, title);
    await refreshList(); await openNote(note.id); setNewOpen(false);
  }

  // Every lifecycle write lands as a new revision in the vault, so the tree,
  // the open tabs and the editor all have to be told rather than left holding a
  // path or revision the vault has moved past.
  async function renameActive(path: string, title: string) {
    if (!active) return;
    if (!(await persistActive())) throw new Error("Save the current note before moving it.");
    const moved = await vaultBridge.renameNote(active.id, path, title);
    setActive(moved);
    rememberTab(moved);
    setSaveState("saved");
    await refreshList();
    setRenameOpen(false);
    report(`Moved to ${moved.path}.`);
  }

  async function deleteActive() {
    if (!active) return;
    if (!await confirm({
      title: `Delete “${active.title}”?`,
      body: "The note leaves the workspace, but its encrypted history stays in the vault — you can restore it from the deleted-notes list.",
      action: "Delete note",
    })) return;
    const removed = await vaultBridge.deleteNote(active.id);
    const remaining = openTabs.filter((tab) => tab.id !== removed.id);
    setOpenTabs(remaining);
    if (secondary?.id === removed.id) setSecondary(undefined);
    setActive(undefined);
    setBacklinks([]);
    setMentions([]);
    setSaveState("saved");
    await refreshList();
    if (remaining[0]) await openNote(remaining[0].id);
    report(`Deleted ${removed.title}. Restore it from the deleted-notes list.`);
  }

  async function restoreRevision(revision: number) {
    if (!active) return;
    const restored = await vaultBridge.restoreRevision(active.id, revision);
    setActive(restored);
    rememberTab(restored);
    setSaveState("saved");
    await refreshList();
    setHistoryOpen(false);
    report(`Restored revision ${revision} as revision ${restored.revision}.`);
  }

  async function restoreDeleted(note: DeletedNote) {
    const restored = await vaultBridge.restoreRevision(note.id, note.revision);
    await refreshList();
    setTrashOpen(false);
    setWorkspaceView("notes");
    await openNote(restored.id);
    report(`Restored ${restored.title}.`);
  }

  async function createFromTemplate(template: string, path: string, title: string, variables: Record<string, string>) {
    const note = await vaultBridge.createFromTemplate(template, path, title, variables);
    await refreshList();
    setTemplateOpen(false);
    setWorkspaceView("notes");
    await openNote(note.id);
    report(`Created ${note.path} from the template.`);
  }

  async function showTemplates() {
    try {
      setTemplates(await vaultBridge.templates());
      setTemplateOpen(true);
    } catch (caught) {
      fail(caught);
    }
  }

  async function showWorkspace(next: WorkspaceView) {
    setWorkspaceView(next);
    if (next === "graph") setGraph(await vaultBridge.graph());
    if (next === "properties") {
      const [rows, views] = await Promise.all([vaultBridge.propertyRows(), vaultBridge.savedViews()]);
      setPropertyRows(rows);
      setSavedViews(views);
    }
    if (next === "canvas" || next === "files") await refreshAssets();
    if (next === "plugins") await refreshPlugins();
    if (next === "sync") {
      const status = await vaultBridge.syncStatus();
      setSyncStatus(status);
      // The signature check is a second read, not part of the status payload:
      // a registry that parses is not the same as a registry the owner signed.
      setSyncRegistryVerified(status.enrolled ? await vaultBridge.syncVerifyRegistry() : null);
    }
  }

  async function installPlugin(manifest: unknown, source: string) {
    const installed = await vaultBridge.installPlugin(
      manifest as Parameters<typeof vaultBridge.installPlugin>[0],
      source
    );
    await refreshPlugins();
    report(`Installed ${installed.name}. It stays off until you turn it on.`);
  }

  async function togglePlugin(id: string, enabled: boolean) {
    const changed = await vaultBridge.setPluginEnabled(id, enabled);
    await refreshPlugins();
    report(`${changed.name} is now ${enabled ? "running" : "stopped"}.`);
  }

  async function removePlugin(plugin: PluginSummary) {
    if (!await confirm({
      title: `Remove ${plugin.name}?`,
      body: "The plugin stops immediately and the settings it stored in this vault are deleted with it.",
      action: "Remove plugin",
    })) return;
    await vaultBridge.deletePlugin(plugin.id);
    await refreshPlugins();
    report(`Removed ${plugin.name}.`);
  }

  async function setRestrictedPlugins(enabled: boolean) {
    await vaultBridge.setPluginRestrictedMode(enabled);
    await refreshPlugins();
    report(`Restricted plugin mode is ${enabled ? "on" : "off"}.`);
  }

  async function revokePluginSigner(plugin: PluginSummary) {
    if (!await confirm({
      title: `Revoke the signer of ${plugin.name}?`,
      body: "Every plugin signed with this key stops immediately, in this vault, until you restore the signer.",
      action: "Revoke signer",
    })) return;
    await vaultBridge.revokePluginSigner(plugin.id);
    await refreshPlugins();
    report(`${plugin.name}'s signer is revoked in this vault.`);
  }

  async function restorePluginSigner(keyId: string) {
    await vaultBridge.restorePluginSigner(keyId);
    await refreshPlugins();
    report("Plugin signer restored. Plugins remain off until you enable them.");
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
    report(pinned ? `Removed ${active.title} from bookmarks.` : `Bookmarked ${active.title}.`);
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
    report(`Saved the "${name}" workspace.`);
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
    if (layout.view === "graph" || layout.view === "properties" || layout.view === "canvas" || layout.view === "files") await showWorkspace(layout.view);
    setWorkspacesOpen(false);
    report(`Opened the "${layout.name}" workspace.`);
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
    localStorage.setItem("vbrain:idle-lock", String(next));
    report(next ? `Auto-lock set to ${next} minute${next === 1 ? "" : "s"} of inactivity.` : "Auto-lock disabled for this device.");
  }

  const commands = useMemo<PaletteCommand[]>(() => [
    { icon: FilePlus2, label: "Create new note", keys: "⌘ N", action: () => setNewOpen(true) },
    { icon: FileText, label: "Quick switch to a note", keys: "⌘ O", action: () => setQuickOpen(true) },
    { icon: Sun, label: "Open today's daily note", keys: "⌘ D", action: () => void openDaily() },
    { icon: Sparkles, label: "New note from a template", action: () => void showTemplates() },
    { icon: PencilLine, label: "Rename or move this note", disabled: !active, action: () => setRenameOpen(true) },
    { icon: History, label: "Browse this note's history", disabled: !active, action: () => setHistoryOpen(true) },
    { icon: Star, label: "Bookmark this note", disabled: !active, action: () => void toggleBookmark() },
    { icon: Trash2, label: "Restore a deleted note", action: () => setTrashOpen(true) },
    { icon: Puzzle, label: "Manage plugins", action: () => void showWorkspace("plugins") },
    ...pluginCommands.map((command) => ({
      icon: Puzzle,
      label: `${command.pluginName}: ${command.label}`,
      action: () => host().invoke(command),
    })),
    { icon: Search, label: "Search encrypted vault", keys: "⇧⌘ F", action: () => setSearchOpen(true) },
    { icon: Columns2, label: "Open current note in split pane", keys: "⌘ \\", disabled: !active, action: () => void openInSplit(active!.id) },
    { icon: Network, label: "Open local graph", action: () => void showWorkspace("graph") },
    { icon: TableProperties, label: "Open property view", action: () => void showWorkspace("properties") },
    { icon: FolderKanban, label: "Open canvas workspace", action: () => void showWorkspace("canvas") },
    { icon: Paperclip, label: "Open attachment library", action: () => void showWorkspace("files") },
    { icon: RefreshCw, label: "View sync status", action: () => void showWorkspace("sync") },
    { icon: BookOpen, label: mode === "write" ? "Switch to reading view" : "Switch to writing view", keys: "⌘ E", action: () => setMode(mode === "write" ? "read" : "write") },
    { icon: rightOpen ? PanelRightClose : PanelRightOpen, label: rightOpen ? "Hide the context panel" : "Show the context panel", action: () => setRightOpen((value) => !value) },
    { icon: LayoutGrid, label: "Workspaces and saved layouts", action: () => setWorkspacesOpen(true) },
    { icon: Palette, label: "Customize theme", action: () => setThemeOpen(true) },
    { icon: Clock, label: "Change auto-lock delay", action: () => cycleIdleLock() },
    { icon: LockKeyhole, label: "Lock workspace", keys: "⌘ L", action: () => void lock() },
  ], [active, host, lock, mode, openDaily, openInSplit, pluginCommands, rightOpen, showTemplates, showWorkspace, toggleBookmark]);

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
        <div className="brand-mark"><span>VB</span></div>
        <div className="vault-switch-wrap">
          <button
            className={`vault-switch ${vaultMenuOpen ? "is-open" : ""}`}
            onClick={() => setVaultMenuOpen((value) => !value)}
            aria-expanded={vaultMenuOpen}
            aria-haspopup="menu"
            title="Current encrypted vault"
          ><Archive size={15} /><span>{vault.name}</span><ChevronDown size={13} /></button>
          {vaultMenuOpen && <>
            <div className="menu-scrim" onPointerDown={() => setVaultMenuOpen(false)} />
            <div className="vault-menu" role="menu" aria-label="Vault">
              <p className="vault-menu-head"><b>{vault.name}</b><code>{vault.path}</code></p>
              <p className="vault-menu-stat">{vault.noteCount} encrypted {vault.noteCount === 1 ? "note" : "notes"} · unlocked on this device</p>
              <button role="menuitem" onClick={() => { setVaultMenuOpen(false); void copyGuarded("Vault path", vault.path); }}>
                <Copy size={14} />Copy vault path
              </button>
              <button role="menuitem" onClick={() => { setVaultMenuOpen(false); void lock(); }}>
                <LockKeyhole size={14} />Lock and switch vault
              </button>
            </div>
          </>}
        </div>
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
          <button className={workspaceView === "canvas" ? "active" : ""} onClick={() => void showWorkspace("canvas")}><FolderKanban size={14} /><span>Canvas</span></button>
          <button className={workspaceView === "files" ? "active" : ""} onClick={() => void showWorkspace("files")}><Paperclip size={14} /><span>Files</span></button>
          <button className={workspaceView === "plugins" ? "active" : ""} onClick={() => void showWorkspace("plugins")}><Puzzle size={14} /><span>Plugins</span></button>
          <button className={workspaceView === "sync" ? "active" : ""} onClick={() => void showWorkspace("sync")}><RefreshCw size={14} /><span>Sync</span></button>
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
                const next = new Set(current);
                if (row.open) next.delete(row.folder);
                else next.add(row.folder);
                return next;
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
          <div className="vault-spread" role="img" aria-label={spread.length
            ? `${notes.length} notes across ${spread.length} ${spread.length === 1 ? "folder" : "folders"}`
            : "An empty vault"}>
            {spread.map(([folder, count], index) => <span
              key={folder}
              style={{ flexGrow: count, opacity: 1 - Math.min(index, 5) * 0.13 }}
              title={`${folder} · ${count} ${count === 1 ? "note" : "notes"}`}
            />)}
          </div>
          <p><b>{notes.length}</b> encrypted {notes.length === 1 ? "note" : "notes"} <span>·</span> <b>{spread.length}</b> {spread.length === 1 ? "folder" : "folders"} <span>·</span> local</p>
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
          <article className={`stage-pane ${entering ? "is-entering" : ""}`} aria-label="Primary pane">
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
                  <button onClick={() => setRenameOpen(true)} title="Rename or move this note"><PencilLine size={16} /></button>
                  <button onClick={() => setHistoryOpen(true)} title="Encrypted revision history"><History size={16} /></button>
                  <button onClick={() => void deleteActive()} title="Delete this note"><Trash2 size={16} /></button>
                  <button onClick={() => void copyGuarded("Note", active.body)} title="Copy note to a self-clearing clipboard"><Copy size={16} /></button>
                  <button onClick={() => void openInSplit(active.id)} title="Open in split pane (Ctrl+\)"><Columns2 size={16} /></button>
                </div>
              </div>
              <div className="document-title-wrap">
                <input className="document-title" value={active.title} onChange={(event) => mutateActive({ title: event.target.value })} aria-label="Note title" />
                <div className="document-meta"><span>REV {String(active.revision).padStart(2, "0")}</span><i /> <span>{active.body.trim().split(/\s+/u).length} WORDS</span><i /> <span>UPDATED {relativeTime(active.updatedAt).toUpperCase()}</span></div>
              </div>
              <div className="document-body" ref={documentBody}>
                <Suspense fallback={<div className="document-loading">Preparing document…</div>}>
                  {mode === "write" ? <MarkdownEditor value={active.body} onChange={(body) => mutateActive({ body })} reveal={reveal} /> :
                    <MarkdownPreview body={active.body} />}
                </Suspense>
              </div>
            </> : <div className="empty-stage"><BookOpen size={32} strokeWidth={1.25} /><h2>The archive is quiet.</h2><p>Select a note to begin.</p></div>}
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
      </section> : workspaceView === "graph" ? <KnowledgeGraph graph={graph} onOpen={openFromKnowledge} />
      : workspaceView === "canvas" ? <CanvasBoard
        canvases={canvases}
        notes={notes}
        attachments={attachments}
        onRefresh={refreshAssets}
        onOpenNote={openFromKnowledge}
        onNotice={report}
      />
      : workspaceView === "files" ? <AttachmentLibrary
        attachments={attachments}
        onRefresh={refreshAssets}
        onNotice={report}
      />
      : workspaceView === "plugins" ? <PluginManager
        plugins={plugins}
        policy={pluginPolicy}
        states={pluginStates}
        onInstall={installPlugin}
        onToggle={togglePlugin}
        onRemove={removePlugin}
        onRestricted={setRestrictedPlugins}
        onRevoke={revokePluginSigner}
        onRestore={restorePluginSigner}
        onNotice={report}
      />
      : workspaceView === "sync" ? (syncStatus?.enrolled
        ? <SyncStatus status={syncStatus} registryVerified={syncRegistryVerified} />
        : <div className="sync-empty">
            <RefreshCw size={30} />
            <h3>This vault isn't enrolled in sync</h3>
            <p>Enroll a device from the CLI to see the registry, checkpoint and change counts here. The desktop app never enrolls, revokes, or mutates sync state itself.</p>
          </div>)
      : <PropertyTable
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
        onOutline={revealHeading}
        onClose={() => setRightOpen(false)}
        onLink={linkMention}
        panels={pluginPanels} />}

      {workspaceView === "notes" && !rightOpen && active && <button
        className="context-reopen"
        onClick={() => setRightOpen(true)}
        aria-label="Show the context panel"
        title="Show the context panel"
      ><PanelRightOpen size={15} /></button>}

      {workspaceView === "notes" && !active && <div className="context-reserve" aria-hidden="true" />}

      {notice && <div className={`toast ${notice.tone}`} role={notice.tone === "error" ? "alert" : "status"}>
        {notice.tone === "error" ? <TriangleAlert size={14} /> : <Check size={14} />}{notice.text}
      </div>}

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

      {paletteOpen && <CommandPalette commands={commands} onClose={() => setPaletteOpen(false)} />}

      {themeOpen && <ThemeEditor settings={theme} onChange={setTheme} onClose={() => setThemeOpen(false)} />}

      {newOpen && <NewNoteDialog onClose={() => setNewOpen(false)} onCreate={create} />}
      {renameOpen && active && <RenameDialog note={active} onClose={() => setRenameOpen(false)} onRename={renameActive} />}
      {historyOpen && active && <HistoryDialog note={active} onClose={() => setHistoryOpen(false)} onRestore={restoreRevision} />}
      {trashOpen && <TrashDialog onClose={() => setTrashOpen(false)} onRestore={restoreDeleted} />}
      {templateOpen && <TemplateDialog templates={templates} onClose={() => setTemplateOpen(false)} onCreate={createFromTemplate} />}
      {confirmDialog}

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
