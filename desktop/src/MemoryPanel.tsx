import { Brain, Check, CirclePause, CirclePlay, FileText, Link2Off, Pin, RotateCcw, Trash2, TriangleAlert, X } from "lucide-react";
import { useState } from "react";
import type { MemoryReviewCandidate, MemoryScope, MemoryStatusData } from "./types";

type Notice = (text: string, tone?: "info" | "error") => void;

export function MemoryPanel({ status, review, onRefresh, onPairBegin, onPairComplete, onPairCancel, onDisconnect, onPause, onExclude, onApprove, onReject, onPin, onForget, onRelearn, onOpenNote, onNotice }: {
  status: MemoryStatusData | null;
  review: MemoryReviewCandidate[];
  onRefresh: () => Promise<void>;
  onPairBegin: () => Promise<{ pairingId: string; state: "awaitingConfirmation" }>;
  onPairComplete: (pairingId: string) => Promise<void>;
  onPairCancel: (pairingId: string) => Promise<void>;
  onDisconnect: () => Promise<void>;
  onPause: (paused: boolean) => Promise<void>;
  onExclude: (scope: MemoryScope) => Promise<void>;
  onApprove: (id: string) => Promise<void>;
  onReject: (id: string) => Promise<void>;
  onPin: (id: string, pinned: boolean) => Promise<void>;
  onForget: (id: string) => Promise<void>;
  onRelearn: (id: string) => Promise<void>;
  onOpenNote: (id: string) => Promise<void>;
  onNotice: Notice;
}) {
  const [pairingId, setPairingId] = useState<string>();
  const [scope, setScope] = useState<MemoryScope["kind"]>("session");
  const [scopeId, setScopeId] = useState("");
  const [busy, setBusy] = useState<string>();
  const unavailable = !status || status.state === "disabled" || status.state === "unsupported" || status.state === "locked";

  async function run(label: string, operation: () => Promise<void>) {
    setBusy(label);
    try { await operation(); } catch (caught) { onNotice(caught instanceof Error ? caught.message : "Memory operation was refused.", "error"); }
    finally { setBusy(undefined); }
  }

  return <section className="memory-view" aria-label="Personal memory">
    <header className="memory-header">
      <div><h2><Brain size={20} /> Personal memory</h2><p>Optional, per-vault memory. It begins only after owner pairing and never imports old conversations.</p></div>
      <button type="button" onClick={() => void run("refresh", onRefresh)} disabled={busy !== undefined}>Refresh</button>
    </header>

    {!status ? <p className="memory-empty" role="status">Reading memory status…</p> : <>
      <div className="memory-summary" aria-live="polite">
        <span><b>Status</b><code>{status.state}</code></span><span><b>Pairing</b><code>{status.paired ? "owner paired" : "not paired"}</code></span>
        <span><b>Queue</b><code>{status.queued}</code></span><span><b>Review</b><code>{status.review}</code></span>
        <span><b>Failed / expired</b><code>{status.failed} / {status.expired}</code></span>
      </div>
      {status.enrolledAt && <p className="memory-detail">Capture cutoff: {new Date(status.enrolledAt).toLocaleString()}. {status.model ? `Worker: ${status.model}.` : "No worker is configured."}</p>}
      {status.compatibilityReasons.length > 0 && <aside className="memory-warning"><TriangleAlert size={16} /><div><b>Memory is not ready</b>{status.compatibilityReasons.map((reason) => <p key={reason}>{reason}</p>)}</div></aside>}

      {!status.paired && <div className="memory-controls"><h3>Connect a local client</h3><p>Pairing needs confirmation from this unlocked vault owner. No passphrase, vault key, or pairing material is displayed here.</p>
        {!pairingId ? <button type="button" onClick={() => void run("pair", async () => { const next = await onPairBegin(); setPairingId(next.pairingId); })} disabled={busy !== undefined || unavailable}>Begin owner pairing</button>
          : <div className="memory-pairing" role="status"><p>Waiting for the owner confirmation. Continue only after you have reviewed the local pairing request.</p><button type="button" onClick={() => void run("complete", async () => { await onPairComplete(pairingId); setPairingId(undefined); })} disabled={busy !== undefined}>Complete pairing</button><button type="button" onClick={() => void run("cancel", async () => { await onPairCancel(pairingId); setPairingId(undefined); })} disabled={busy !== undefined}>Cancel pairing</button></div>}
      </div>}

      {status.paired && <div className="memory-controls"><h3>Queue and scope</h3><p>Pausing stops new processing. Excluding a scope cancels its pending work; it does not alter historical transcripts.</p><div><button type="button" onClick={() => void run("pause", () => onPause(!status.paused))} disabled={busy !== undefined}>{status.paused ? <><CirclePlay size={15} /> Resume queue</> : <><CirclePause size={15} /> Pause queue</>}</button><button type="button" onClick={() => void run("disconnect", onDisconnect)} disabled={busy !== undefined}><Link2Off size={15} /> Disconnect</button></div><label>Exclude scope<select value={scope} onChange={(event) => setScope(event.target.value as MemoryScope["kind"])}><option value="session">Conversation</option><option value="project">Project</option></select></label><label>Scope ID<input value={scopeId} onChange={(event) => setScopeId(event.target.value)} autoComplete="off" /></label><button type="button" onClick={() => void run("exclude", async () => { if (!scopeId.trim()) { onNotice("Enter the conversation or project ID to exclude.", "error"); return; } await onExclude({ kind: scope, id: scopeId.trim() }); setScopeId(""); })} disabled={busy !== undefined || !scopeId.trim()}>Exclude selected scope</button></div>}

      <div className="memory-review"><h3>Owner review <small>{review.length} shown</small></h3>{review.length === 0 ? <p>No candidates need review.</p> : <ul>{review.map((candidate) => <Candidate key={candidate.id} candidate={candidate} busy={busy !== undefined} onApprove={onApprove} onReject={onReject} onPin={onPin} onForget={onForget} onRelearn={onRelearn} onOpenNote={onOpenNote} run={run} />)}</ul>}</div>
      <footer className="memory-caveat">Only bounded, secret-filtered text may reach an owner-configured local worker. Forget removes a fact from future recall but does not promise deletion from revisions, backups, or provider history. Relearning always requires an explicit owner action.</footer>
    </>}
  </section>;
}

function Candidate({ candidate, busy, onApprove, onReject, onPin, onForget, onRelearn, onOpenNote, run }: { candidate: MemoryReviewCandidate; busy: boolean; onApprove: (id: string) => Promise<void>; onReject: (id: string) => Promise<void>; onPin: (id: string, pinned: boolean) => Promise<void>; onForget: (id: string) => Promise<void>; onRelearn: (id: string) => Promise<void>; onOpenNote: (id: string) => Promise<void>; run: (label: string, operation: () => Promise<void>) => Promise<void> }) {
  return <li className="memory-candidate"><header><div><b>{candidate.title}</b><small>{candidate.kind} · {candidate.sourceKind}{candidate.sensitive ? " · sensitive review" : ""}</small></div></header><p>{candidate.body}</p>{candidate.evidence.length > 0 && <details><summary>Source references ({candidate.evidence.length})</summary>{candidate.evidence.map((item) => <blockquote key={item.messageId}>{item.quote}</blockquote>)}</details>}<div className="memory-actions">{candidate.targetId && <button type="button" onClick={() => void run(`open:${candidate.id}`, () => onOpenNote(candidate.targetId!))} disabled={busy}><FileText size={14} /> Open note</button>}<button type="button" onClick={() => void run(`approve:${candidate.id}`, () => onApprove(candidate.id))} disabled={busy}><Check size={14} /> Approve</button><button type="button" onClick={() => void run(`reject:${candidate.id}`, () => onReject(candidate.id))} disabled={busy}><X size={14} /> Reject</button><button type="button" onClick={() => void run(`pin:${candidate.id}`, () => onPin(candidate.id, true))} disabled={busy}><Pin size={14} /> Pin</button><button type="button" onClick={() => void run(`forget:${candidate.id}`, () => onForget(candidate.id))} disabled={busy}><Trash2 size={14} /> Forget</button><button type="button" onClick={() => void run(`relearn:${candidate.id}`, () => onRelearn(candidate.id))} disabled={busy}><RotateCcw size={14} /> Relearn</button></div></li>;
}
