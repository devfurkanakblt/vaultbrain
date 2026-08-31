import { useEffect, useState } from "react";
import { Clock, FileText, History, LoaderCircle, PencilLine, RotateCcw, Sparkles, Trash2 } from "lucide-react";
import { vaultBridge } from "./bridge";
import type { DeletedNote, NoteDocument, NoteSummary, RevisionInfo } from "./types";

function stamp(iso: string) {
  const when = new Date(iso);
  return Number.isNaN(when.getTime()) ? iso : when.toLocaleString();
}

function Overlay({ label, onClose, children }: { label: string; onClose: () => void; children: React.ReactNode }) {
  return <div className="overlay" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
    <section className="lifecycle-dialog" role="dialog" aria-modal="true" aria-label={label}>{children}</section>
  </div>;
}

export function RenameDialog({ note, onClose, onRename }: {
  note: NoteDocument;
  onClose: () => void;
  onRename: (path: string, title: string) => Promise<void>;
}) {
  const [path, setPath] = useState(note.path.replace(/\.md$/iu, ""));
  const [title, setTitle] = useState(note.title);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await onRename(path.trim(), title.trim());
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
      setBusy(false);
    }
  }

  return <Overlay label="Rename or move note" onClose={onClose}>
    <header className="lifecycle-head"><PencilLine size={18} /><div><p className="eyebrow">MOVE OR RETITLE</p><h2>Where should this live?</h2></div></header>
    <form className="lifecycle-form" onSubmit={submit}>
      <label><span>Logical path</span><input autoFocus value={path} onChange={(event) => setPath(event.target.value)} spellCheck={false} /></label>
      <label><span>Title</span><input value={title} onChange={(event) => setTitle(event.target.value)} /></label>
      <p className="lifecycle-hint">Links that name the old title stay as written, so they become unresolved mentions you can relink from the context panel.</p>
      {error && <p className="form-error" role="alert">{error}</p>}
      <div className="lifecycle-actions">
        <button type="button" onClick={onClose}>Cancel</button>
        <button disabled={busy || !path.trim() || !title.trim()}>{busy ? "Moving…" : "Move note"}</button>
      </div>
    </form>
  </Overlay>;
}

export function HistoryDialog({ note, onClose, onRestore }: {
  note: NoteDocument;
  onClose: () => void;
  onRestore: (revision: number) => Promise<void>;
}) {
  const [revisions, setRevisions] = useState<RevisionInfo[]>([]);
  const [selected, setSelected] = useState<number>();
  const [preview, setPreview] = useState<NoteDocument>();
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let live = true;
    void (async () => {
      try {
        const listed = await vaultBridge.noteRevisions(note.id);
        if (!live) return;
        setRevisions(listed);
        setSelected(listed.find((entry) => !entry.current)?.revision ?? listed[0]?.revision);
      } catch (caught) {
        if (live) setError(caught instanceof Error ? caught.message : String(caught));
      } finally {
        if (live) setBusy(false);
      }
    })();
    return () => { live = false; };
  }, [note.id]);

  useEffect(() => {
    if (selected === undefined) return;
    let live = true;
    void (async () => {
      try {
        const document = await vaultBridge.noteRevision(note.id, selected);
        if (live) setPreview(document);
      } catch (caught) {
        if (live) setError(caught instanceof Error ? caught.message : String(caught));
      }
    })();
    return () => { live = false; };
  }, [note.id, selected]);

  return <Overlay label="Note history" onClose={onClose}>
    <header className="lifecycle-head"><History size={18} /><div><p className="eyebrow">ENCRYPTED HISTORY</p><h2>{note.title}</h2></div></header>
    {error && <p className="form-error" role="alert">{error}</p>}
    <div className="history-body">
      <nav aria-label="Revisions">
        {busy && <p className="lifecycle-hint">Decrypting revisions…</p>}
        {!busy && !revisions.length && <p className="lifecycle-hint">This note has no archived revisions yet.</p>}
        {revisions.map((entry) => <button
          key={entry.revision}
          className={selected === entry.revision ? "active" : ""}
          onClick={() => setSelected(entry.revision)}
        >
          <b>Revision {entry.revision}</b>
          <small><Clock size={10} />{stamp(entry.updatedAt)}</small>
          {entry.current && <i>current</i>}
        </button>)}
      </nav>
      <article>
        {preview ? <>
          <div className="history-meta"><span>{preview.path}</span><span>{preview.body.trim().split(/\s+/u).length} words</span></div>
          <pre>{preview.body}</pre>
        </> : <p className="lifecycle-hint">Choose a revision to read it.</p>}
      </article>
    </div>
    <div className="lifecycle-actions">
      <button type="button" onClick={onClose}>Close</button>
      <button
        disabled={selected === undefined || revisions.find((entry) => entry.revision === selected)?.current}
        onClick={() => selected !== undefined && void onRestore(selected)}
      ><RotateCcw size={14} /> Restore revision {selected ?? ""}</button>
    </div>
  </Overlay>;
}

export function TrashDialog({ onClose, onRestore }: {
  onClose: () => void;
  onRestore: (note: DeletedNote) => Promise<void>;
}) {
  const [deleted, setDeleted] = useState<DeletedNote[]>([]);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let live = true;
    void (async () => {
      try {
        const listed = await vaultBridge.deletedNotes();
        if (live) setDeleted(listed);
      } catch (caught) {
        if (live) setError(caught instanceof Error ? caught.message : String(caught));
      } finally {
        if (live) setBusy(false);
      }
    })();
    return () => { live = false; };
  }, []);

  return <Overlay label="Deleted notes" onClose={onClose}>
    <header className="lifecycle-head"><Trash2 size={18} /><div><p className="eyebrow">RECOVERABLE</p><h2>Deleted notes</h2></div></header>
    {error && <p className="form-error" role="alert">{error}</p>}
    <div className="trash-list">
      {busy && <p className="lifecycle-hint"><LoaderCircle className="spin" size={13} /> Reading encrypted history…</p>}
      {!busy && !deleted.length && <p className="lifecycle-hint">Nothing has been deleted from this vault.</p>}
      {deleted.map((note) => <div className="trash-row" key={note.id}>
        <FileText size={15} />
        <span><b>{note.title}</b><small>{note.path} · revision {note.revision} · {stamp(note.updatedAt)}</small></span>
        <button onClick={() => void onRestore(note)}><RotateCcw size={13} /> Restore</button>
      </div>)}
    </div>
    <div className="lifecycle-actions"><button type="button" onClick={onClose}>Close</button></div>
  </Overlay>;
}

/** `key=value` lines become the `{{key}}` variables the template renderer sees. */
function parseVariables(text: string) {
  const variables: Record<string, string> = {};
  for (const line of text.split(/\r?\n/u)) {
    const at = line.indexOf("=");
    if (at <= 0) continue;
    const name = line.slice(0, at).trim();
    if (name) variables[name] = line.slice(at + 1).trim();
  }
  return variables;
}

export function TemplateDialog({ templates, onClose, onCreate }: {
  templates: NoteSummary[];
  onClose: () => void;
  onCreate: (template: string, path: string, title: string, variables: Record<string, string>) => Promise<void>;
}) {
  const [template, setTemplate] = useState(templates[0]?.id ?? "");
  const [folder, setFolder] = useState("Notes/");
  const [title, setTitle] = useState("");
  const [variables, setVariables] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await onCreate(template, `${folder}${title.trim()}`, title.trim(), parseVariables(variables));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
      setBusy(false);
    }
  }

  return <Overlay label="New note from template" onClose={onClose}>
    <header className="lifecycle-head"><Sparkles size={18} /><div><p className="eyebrow">FROM TEMPLATE</p><h2>Start from a shape you trust.</h2></div></header>
    {templates.length ? <form className="lifecycle-form" onSubmit={submit}>
      <label><span>Template</span><select value={template} onChange={(event) => setTemplate(event.target.value)}>
        {templates.map((item) => <option key={item.id} value={item.id}>{item.title}</option>)}
      </select></label>
      <label><span>Title</span><input autoFocus value={title} onChange={(event) => setTitle(event.target.value)} placeholder="Kickoff" /></label>
      <label><span>Folder</span><input value={folder} onChange={(event) => setFolder(event.target.value)} /></label>
      <label><span>Variables</span><textarea rows={3} value={variables} onChange={(event) => setVariables(event.target.value)} placeholder={"client=Acme\nowner=You"} /></label>
      <p className="lifecycle-hint">Templates understand <code>{"{{title}}"}</code>, <code>{"{{path}}"}</code>, <code>{"{{date:YYYY-MM-DD}}"}</code>, <code>{"{{time:HH:mm}}"}</code> and any name you set above.</p>
      {error && <p className="form-error" role="alert">{error}</p>}
      <div className="lifecycle-actions">
        <button type="button" onClick={onClose}>Cancel</button>
        <button disabled={busy || !template || !title.trim()}>{busy ? "Rendering…" : "Create note"}</button>
      </div>
    </form> : <>
      <p className="lifecycle-hint">No note in this vault carries the <code>template</code> tag yet. Tag any note <code>template</code> and it will appear here.</p>
      <div className="lifecycle-actions"><button type="button" onClick={onClose}>Close</button></div>
    </>}
  </Overlay>;
}
