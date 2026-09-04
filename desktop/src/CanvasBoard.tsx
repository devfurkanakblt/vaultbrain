import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ArrowRight, FileImage, FileText, FolderKanban, Group, Link2, LoaderCircle, Maximize2, MousePointer2, Plus, Save, StickyNote, Trash2, X, ZoomIn, ZoomOut } from "lucide-react";
import { vaultBridge } from "./bridge";
import { useConfirm } from "./Confirm";
import type { AttachmentInfo, CanvasDocument, CanvasEdge, CanvasNode, CanvasSummary, NoteSummary, Notify } from "./types";

interface CanvasBoardProps {
  canvases: CanvasSummary[];
  notes: NoteSummary[];
  attachments: AttachmentInfo[];
  onRefresh: () => Promise<void>;
  onOpenNote: (id: string) => void;
  onNotice: Notify;
}

const SURFACE_WIDTH = 3200;
const SURFACE_HEIGHT = 2200;
const MIN_ZOOM = 0.2;
const MAX_ZOOM = 2.5;
/** Breathing room left around the nodes when the board is fitted to the frame. */
const FIT_PADDING = 80;

/**
 * Where the frame sits over the board: `x`/`y` are the surface coordinates
 * under the frame's top-left corner, so a surface point `s` is drawn at
 * `(s - view) * zoom`. Keeping the anchor in surface space rather than in
 * scroll pixels is what lets a wheel zoom hold the point under the cursor.
 */
interface Viewport {
  x: number;
  y: number;
  zoom: number;
}

const ORIGIN: Viewport = { x: 0, y: 0, zoom: 1 };

function clampZoom(zoom: number) {
  return Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, zoom));
}

function nodeId() {
  return `n_${crypto.randomUUID().replaceAll("-", "").slice(0, 12)}`;
}

function edgeId() {
  return `e_${crypto.randomUUID().replaceAll("-", "").slice(0, 12)}`;
}

function nextPosition(count: number) {
  return { x: 100 + (count % 5) * 280, y: 100 + Math.floor(count / 5) * 210 };
}

/** Clamp a freshly placed node inside the surface it has to live on. */
function place(x: number, y: number, width: number, height: number) {
  return {
    x: Math.round(Math.max(0, Math.min(SURFACE_WIDTH - width, x))),
    y: Math.round(Math.max(0, Math.min(SURFACE_HEIGHT - height, y))),
  };
}

export function CanvasBoard({ canvases, notes, attachments, onRefresh, onOpenNote, onNotice }: CanvasBoardProps) {
  const [canvas, setCanvas] = useState<CanvasDocument>();
  const [selected, setSelected] = useState<string>();
  const [connecting, setConnecting] = useState<string>();
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [createTitle, setCreateTitle] = useState("");
  const [createPath, setCreatePath] = useState("Boards/");
  const [noteChoice, setNoteChoice] = useState("");
  const [attachmentChoice, setAttachmentChoice] = useState("");
  const [linkOpen, setLinkOpen] = useState(false);
  const [linkUrl, setLinkUrl] = useState("");
  const [view, setView] = useState<Viewport>(ORIGIN);
  const saveTimer = useRef<number | undefined>(undefined);
  const frame = useRef<HTMLDivElement>(null);
  const pan = useRef<{ pointerX: number; pointerY: number; view: Viewport; moved: boolean } | null>(null);
  const [confirm, confirmDialog] = useConfirm();

  const noteById = useMemo(() => new Map(notes.map((note) => [note.id, note])), [notes]);
  const attachmentById = useMemo(() => new Map(attachments.map((item) => [item.id, item])), [attachments]);

  useEffect(() => {
    if (!dirty || !canvas) return;
    window.clearTimeout(saveTimer.current);
    saveTimer.current = window.setTimeout(() => void save(), 900);
    return () => window.clearTimeout(saveTimer.current);
  }, [canvas, dirty]);

  /** Zoom about a point in client coordinates, so it stays put on screen. */
  const zoomAt = useCallback((clientX: number, clientY: number, factor: number) => {
    const box = frame.current?.getBoundingClientRect();
    if (!box) return;
    setView((current) => {
      const zoom = clampZoom(current.zoom * factor);
      if (zoom === current.zoom) return current;
      const offsetX = clientX - box.left;
      const offsetY = clientY - box.top;
      return {
        zoom,
        x: current.x + offsetX / current.zoom - offsetX / zoom,
        y: current.y + offsetY / current.zoom - offsetY / zoom,
      };
    });
  }, []);

  /** Zoom about the middle of the frame, for the buttons and the keyboard. */
  const zoomCentre = useCallback((factor: number) => {
    const box = frame.current?.getBoundingClientRect();
    if (!box) return;
    zoomAt(box.left + box.width / 2, box.top + box.height / 2, factor);
  }, [zoomAt]);

  const fit = useCallback((nodes: CanvasNode[] | undefined) => {
    const box = frame.current?.getBoundingClientRect();
    if (!box || !box.width || !box.height) return;
    // An empty board has nothing to frame, so it opens at its own scale
    // rather than zoomed out to show an expanse of nothing.
    if (!nodes?.length) {
      setView(ORIGIN);
      return;
    }
    const left = Math.min(...nodes.map((node) => node.x));
    const top = Math.min(...nodes.map((node) => node.y));
    const right = Math.max(...nodes.map((node) => node.x + node.width));
    const bottom = Math.max(...nodes.map((node) => node.y + node.height));
    const zoom = clampZoom(Math.min(
      box.width / (right - left + FIT_PADDING * 2),
      box.height / (bottom - top + FIT_PADDING * 2),
    ));
    // Centre what is left over, so a small board does not cling to one corner.
    setView({
      zoom,
      x: left - FIT_PADDING - (box.width / zoom - (right - left + FIT_PADDING * 2)) / 2,
      y: top - FIT_PADDING - (box.height / zoom - (bottom - top + FIT_PADDING * 2)) / 2,
    });
  }, []);

  // React registers `wheel` passively at the root, so a React onWheel cannot
  // call preventDefault. Bind it here instead, where the board can claim it.
  useEffect(() => {
    const element = frame.current;
    if (!element) return;
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      zoomAt(event.clientX, event.clientY, Math.exp(-event.deltaY * 0.0015));
    };
    element.addEventListener("wheel", onWheel, { passive: false });
    return () => element.removeEventListener("wheel", onWheel);
  }, [zoomAt, canvas]);

  function startPan(event: React.PointerEvent<HTMLDivElement>) {
    // Only the empty board pans; a pointer that landed on a node is that
    // node's to handle.
    if (event.target !== event.currentTarget || event.button !== 0) return;
    pan.current = { pointerX: event.clientX, pointerY: event.clientY, view, moved: false };
    event.currentTarget.setPointerCapture(event.pointerId);
  }

  function movePan(event: React.PointerEvent<HTMLDivElement>) {
    const start = pan.current;
    if (!start) return;
    const dx = event.clientX - start.pointerX;
    const dy = event.clientY - start.pointerY;
    if (!start.moved && Math.hypot(dx, dy) < 3) return;
    start.moved = true;
    setView({ ...start.view, x: start.view.x - dx / start.view.zoom, y: start.view.y - dy / start.view.zoom });
  }

  function endPan(event: React.PointerEvent<HTMLDivElement>) {
    const start = pan.current;
    pan.current = null;
    if (event.currentTarget.hasPointerCapture?.(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId);
    // A press that never travelled was a click on the board: clear the selection.
    if (start && !start.moved && event.target === event.currentTarget) setSelected(undefined);
  }

  async function open(reference: string) {
    try {
      const opened = await vaultBridge.getCanvas(reference);
      setCanvas(opened);
      setSelected(undefined);
      setConnecting(undefined);
      setDirty(false);
      // Frame the board before it is seen, so a wide canvas does not open on
      // an empty corner of its own surface.
      requestAnimationFrame(() => fit(opened.nodes));
    } catch (error) {
      onNotice(error instanceof Error ? error.message : String(error), "error");
    }
  }

  async function save() {
    if (!canvas || saving) return;
    setSaving(true);
    window.clearTimeout(saveTimer.current);
    try {
      const stored = await vaultBridge.saveCanvas({
        id: canvas.id,
        path: canvas.path,
        title: canvas.title,
        nodes: canvas.nodes,
        edges: canvas.edges,
        createdAt: canvas.createdAt,
        baseRevision: canvas.revision,
      });
      setCanvas(stored);
      setDirty(false);
      await onRefresh();
    } catch (error) {
      onNotice(error instanceof Error ? error.message : String(error), "error");
    } finally {
      setSaving(false);
    }
  }

  async function create(event: React.FormEvent) {
    event.preventDefault();
    setSaving(true);
    try {
      const title = createTitle.trim();
      const created = await vaultBridge.saveCanvas({ path: `${createPath}${title}`, title, nodes: [], edges: [] });
      setCanvas(created);
      setView(ORIGIN);
      setCreateOpen(false);
      setCreateTitle("");
      setDirty(false);
      await onRefresh();
    } catch (error) {
      onNotice(error instanceof Error ? error.message : String(error), "error");
    } finally {
      setSaving(false);
    }
  }

  function change(mutator: (current: CanvasDocument) => CanvasDocument) {
    setCanvas((current) => current ? mutator(current) : current);
    setDirty(true);
  }

  function addNode(node: CanvasNode) {
    change((current) => ({ ...current, nodes: [...current.nodes, node], nodeCount: current.nodes.length + 1 }));
    setSelected(node.id);
  }

  function addText() {
    if (!canvas) return;
    addNode({ id: nodeId(), type: "text", text: "New thought", ...nextPosition(canvas.nodes.length), width: 240, height: 150 });
  }

  function addGroup() {
    if (!canvas) return;
    addNode({ id: nodeId(), type: "group", label: "Theme", ...nextPosition(canvas.nodes.length), width: 520, height: 340, color: "5" });
  }

  function addNote() {
    if (!canvas || !noteChoice) return;
    const note = noteById.get(noteChoice);
    if (!note) return;
    addNode({ id: nodeId(), type: "file", file: note.path, noteId: note.id, ...nextPosition(canvas.nodes.length), width: 260, height: 120 });
    setNoteChoice("");
  }

  function addAttachment() {
    if (!canvas || !attachmentChoice) return;
    const attachment = attachmentById.get(attachmentChoice);
    if (!attachment) return;
    addNode({ id: nodeId(), type: "file", file: attachment.filename, attachmentId: attachment.id, ...nextPosition(canvas.nodes.length), width: 260, height: 140 });
    setAttachmentChoice("");
  }

  function addLink(event: React.FormEvent) {
    event.preventDefault();
    if (!canvas) return;
    const url = linkUrl.trim();
    if (!/^https?:\/\//iu.test(url)) {
      onNotice("Canvas links must begin with http:// or https://.", "error");
      return;
    }
    addNode({ id: nodeId(), type: "link", url, ...nextPosition(canvas.nodes.length), width: 280, height: 100 });
    setLinkUrl("");
    setLinkOpen(false);
  }

  function selectNode(id: string) {
    if (connecting && connecting !== id && canvas) {
      const edge: CanvasEdge = { id: edgeId(), fromNode: connecting, toNode: id, fromSide: "right", toSide: "left", toEnd: "arrow" };
      change((current) => ({ ...current, edges: [...current.edges, edge], edgeCount: current.edges.length + 1 }));
      setConnecting(undefined);
    }
    setSelected(id);
  }

  function removeSelected() {
    if (!canvas || !selected) return;
    change((current) => ({
      ...current,
      nodes: current.nodes.filter((node) => node.id !== selected),
      edges: current.edges.filter((edge) => edge.fromNode !== selected && edge.toNode !== selected),
      nodeCount: current.nodes.length - 1,
      edgeCount: current.edges.filter((edge) => edge.fromNode !== selected && edge.toNode !== selected).length,
    }));
    setSelected(undefined);
    setConnecting(undefined);
  }

  function startDrag(event: React.PointerEvent, id: string) {
    if (!canvas) return;
    event.currentTarget.setPointerCapture(event.pointerId);
    selectNode(id);
    const node = canvas.nodes.find((item) => item.id === id);
    if (!node) return;
    const origin = { pointerX: event.clientX, pointerY: event.clientY, x: node.x, y: node.y, zoom: view.zoom };
    const move = (moveEvent: PointerEvent) => change((current) => ({
      ...current,
      nodes: current.nodes.map((item) => item.id === id ? {
        ...item,
        // Screen travel is zoomed travel: divide it back out or the card
        // outruns the cursor on a zoomed-in board and lags on a zoomed-out one.
        ...place(
          origin.x + (moveEvent.clientX - origin.pointerX) / origin.zoom,
          origin.y + (moveEvent.clientY - origin.pointerY) / origin.zoom,
          item.width,
          item.height,
        ),
      } : item),
    }));
    const stop = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", stop);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", stop, { once: true });
  }

  async function removeCanvas() {
    if (!canvas) return;
    if (!await confirm({
      title: `Delete the canvas “${canvas.title}”?`,
      body: "The board leaves the workspace. Its encrypted history is retained in the vault, and the notes and files it pointed at are untouched.",
      action: "Delete canvas",
    })) return;
    try {
      await vaultBridge.deleteCanvas(canvas.id);
      setCanvas(undefined);
      setSelected(undefined);
      await onRefresh();
      onNotice("Canvas deleted.");
    } catch (error) {
      onNotice(error instanceof Error ? error.message : String(error), "error");
    }
  }

  const positions = new Map(canvas?.nodes.map((node) => [node.id, node]) ?? []);

  return <section className="canvas-workspace" aria-label="Canvas workspace">
    <aside className="canvas-list">
      <header><div><p className="eyebrow">SPATIAL INDEX</p><h2>Canvases</h2></div><button onClick={() => setCreateOpen(true)} title="New canvas"><Plus size={16} /></button></header>
      <nav>{canvases.map((item) => <button key={item.id} className={canvas?.id === item.id ? "active" : ""} onClick={() => void open(item.id)}>
        <FolderKanban size={15} /><span><b>{item.title}</b><small>{item.nodeCount} nodes · r{item.revision}</small></span><ArrowRight size={13} />
      </button>)}</nav>
      {!canvases.length && <div className="canvas-list-empty"><FolderKanban size={24} /><p>Your first canvas can connect notes, files, and freeform ideas.</p></div>}
    </aside>
    {canvas ? <div className="canvas-stage">
      <header className="canvas-toolbar">
        <div className="canvas-title"><input value={canvas.title} onChange={(event) => change((current) => ({ ...current, title: event.target.value }))} /><span>{canvas.path} · revision {canvas.revision}</span></div>
        <div className="canvas-tools">
          <button onClick={addText} title="Add text card"><StickyNote size={15} />Text</button>
          <button onClick={addGroup} title="Add group"><Group size={15} />Group</button>
          <button onClick={() => setLinkOpen(true)} title="Add web link"><Link2 size={15} />Link</button>
          <span className="canvas-picker"><select aria-label="Note to add" value={noteChoice} onChange={(event) => setNoteChoice(event.target.value)}><option value="">Add note…</option>{notes.map((note) => <option value={note.id} key={note.id}>{note.title}</option>)}</select><button onClick={addNote} disabled={!noteChoice} title="Add the selected note"><FileText size={15} /></button></span>
          <span className="canvas-picker"><select aria-label="Attachment to add" value={attachmentChoice} onChange={(event) => setAttachmentChoice(event.target.value)}><option value="">Add file…</option>{attachments.map((item) => <option value={item.id} key={item.id}>{item.filename}</option>)}</select><button onClick={addAttachment} disabled={!attachmentChoice} title="Add the selected file"><FileImage size={15} /></button></span>
          <i />
          <button className={connecting ? "active" : ""} disabled={!selected} onClick={() => setConnecting(connecting ? undefined : selected)} title="Connect selected node"><Link2 size={15} />{connecting ? "Choose target" : "Connect"}</button>
          <button disabled={!selected} onClick={removeSelected} title="Delete selected node"><Trash2 size={15} /></button>
          <button className="canvas-save" onClick={() => void save()} disabled={!dirty || saving}>{saving ? <LoaderCircle className="spin" size={15} /> : <Save size={15} />}{dirty ? "Save" : "Saved"}</button>
          <button onClick={() => void removeCanvas()} title="Delete canvas"><X size={15} /></button>
        </div>
      </header>
      <div
        className="canvas-viewport"
        ref={frame}
        onPointerDown={startPan}
        onPointerMove={movePan}
        onPointerUp={endPan}
        onPointerCancel={endPan}
        style={{
          // The grid rides along with the board, so the dots read as the
          // surface moving rather than as a texture painted on the window.
          backgroundSize: `${22 * view.zoom}px ${22 * view.zoom}px`,
          backgroundPosition: `${-view.x * view.zoom}px ${-view.y * view.zoom}px`,
        }}
      >
        <div className="canvas-zoom" role="group" aria-label="Board zoom">
          <button onClick={() => zoomCentre(1 / 1.25)} disabled={view.zoom <= MIN_ZOOM} title="Zoom out"><ZoomOut size={15} /></button>
          <button className="canvas-zoom-level" onClick={() => setView((current) => ({ ...current, zoom: 1 }))} title="Reset to 100%">{Math.round(view.zoom * 100)}%</button>
          <button onClick={() => zoomCentre(1.25)} disabled={view.zoom >= MAX_ZOOM} title="Zoom in"><ZoomIn size={15} /></button>
          <button onClick={() => fit(canvas.nodes)} title="Fit board to the frame"><Maximize2 size={15} /></button>
        </div>
        <div
          className="canvas-surface"
          style={{
            width: SURFACE_WIDTH,
            height: SURFACE_HEIGHT,
            transform: `translate(${-view.x * view.zoom}px, ${-view.y * view.zoom}px) scale(${view.zoom})`,
          }}
        >
          <svg className="canvas-edges" width={SURFACE_WIDTH} height={SURFACE_HEIGHT} aria-hidden="true"><defs><marker id="canvas-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" /></marker></defs>{canvas.edges.map((edge) => {
            const from = positions.get(edge.fromNode); const to = positions.get(edge.toNode);
            if (!from || !to) return null;
            const x1 = from.x + from.width / 2; const y1 = from.y + from.height / 2;
            const x2 = to.x + to.width / 2; const y2 = to.y + to.height / 2;
            const bend = Math.max(60, Math.abs(x2 - x1) * .45);
            return <path key={edge.id} d={`M ${x1} ${y1} C ${x1 + bend} ${y1}, ${x2 - bend} ${y2}, ${x2} ${y2}`} markerEnd={edge.toEnd === "none" ? undefined : "url(#canvas-arrow)"} />;
          })}</svg>
          {canvas.nodes.map((node) => <article key={node.id} className={`canvas-node canvas-node-${node.type} ${selected === node.id ? "selected" : ""} ${connecting === node.id ? "connecting" : ""}`} style={{ left: node.x, top: node.y, width: node.width, height: node.height }} onClick={(event) => { event.stopPropagation(); selectNode(node.id); }}>
            <header onPointerDown={(event) => startDrag(event, node.id)}><MousePointer2 size={12} /><span>{node.type}</span><code>{node.id.slice(-5)}</code></header>
            {node.type === "text" ? <textarea value={node.text} aria-label="Canvas text" onChange={(event) => change((current) => ({ ...current, nodes: current.nodes.map((item) => item.id === node.id && item.type === "text" ? { ...item, text: event.target.value } : item) }))} />
              : node.type === "group" ? <input value={node.label ?? ""} aria-label="Group label" onChange={(event) => change((current) => ({ ...current, nodes: current.nodes.map((item) => item.id === node.id && item.type === "group" ? { ...item, label: event.target.value } : item) }))} />
              : node.type === "link" ? <a href={node.url} target="_blank" rel="noreferrer"><Link2 size={18} /><span>{new URL(node.url).hostname}</span><small>{node.url}</small></a>
              : node.noteId ? <button className="canvas-file-content" onDoubleClick={() => onOpenNote(node.noteId!)}><FileText size={20} /><span>{noteById.get(node.noteId)?.title ?? node.file}</span><small>{noteById.get(node.noteId)?.path ?? "Missing note"}</small></button>
              : <div className="canvas-file-content"><FileImage size={20} /><span>{attachmentById.get(node.attachmentId ?? "")?.filename ?? node.file}</span><small>{attachmentById.has(node.attachmentId ?? "") ? "Encrypted attachment" : "Missing attachment"}</small></div>}
          </article>)}
        </div>
      </div>
    </div> : <div className="canvas-welcome"><div><FolderKanban size={34} /><p className="eyebrow">VISUAL THINKING, ENCRYPTED</p><h2>Arrange the archive in space.</h2><p>Connect notes, attachments, links, and working thoughts without moving them out of your vault.</p><button onClick={() => setCreateOpen(true)}><Plus size={16} /> Create a canvas</button></div></div>}
    {linkOpen && <div className="overlay" onMouseDown={(event) => event.target === event.currentTarget && setLinkOpen(false)}>
      <form className="new-note-dialog canvas-create" onSubmit={addLink}>
        <div className="new-note-icon"><Link2 size={20} /></div>
        <p className="eyebrow">NEW BOARD LINK</p>
        <h2>Point at something outside.</h2>
        <label><span>Address</span><input autoFocus value={linkUrl} onChange={(event) => setLinkUrl(event.target.value)} placeholder="https://" aria-label="Link address" /></label>
        <p className="lifecycle-hint">Only <code>http://</code> and <code>https://</code> addresses are stored on a board.</p>
        <div><button type="button" onClick={() => setLinkOpen(false)}>Cancel</button><button disabled={!linkUrl.trim()}>Add link</button></div>
      </form>
    </div>}
    {confirmDialog}
    {createOpen && <div className="overlay" onMouseDown={(event) => event.target === event.currentTarget && setCreateOpen(false)}><form className="new-note-dialog canvas-create" onSubmit={(event) => void create(event)}><div className="new-note-icon"><FolderKanban size={20} /></div><p className="eyebrow">NEW ENCRYPTED CANVAS</p><h2>Make room for the idea.</h2><label><span>Title</span><input autoFocus value={createTitle} onChange={(event) => setCreateTitle(event.target.value)} placeholder="Product map" /></label><label><span>Folder</span><input value={createPath} onChange={(event) => setCreatePath(event.target.value)} /></label><div><button type="button" onClick={() => setCreateOpen(false)}>Cancel</button><button disabled={!createTitle.trim() || saving}>{saving ? "Creating…" : "Create canvas"}</button></div></form></div>}
  </section>;
}
