import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { ShieldAlert, TriangleAlert } from "lucide-react";

export interface ConfirmRequest {
  /** The question, as a sentence. */
  title: string;
  /** What the answer costs, and what it does not. */
  body: string;
  /** The affirmative button. Name the act — never "OK". */
  action: string;
  /** `danger` paints the affirmative button with the theme's warning colour. */
  tone?: "danger" | "neutral";
}

/**
 * A confirmation the app draws for itself.
 *
 * `window.confirm` blocks the whole webview, arrives in the operating system's
 * chrome rather than the vault's, cannot say which note it is about in the
 * app's own voice, and cannot be reached by a test without stubbing a global.
 * This returns a promise instead, so a caller still reads top to bottom.
 */
export function useConfirm(): [(request: ConfirmRequest) => Promise<boolean>, ReactNode] {
  const [request, setRequest] = useState<ConfirmRequest>();
  const settle = useRef<((value: boolean) => void) | undefined>(undefined);

  const ask = useCallback((next: ConfirmRequest) => new Promise<boolean>((resolve) => {
    // A second question asked while one is still open answers the first with
    // "no" rather than leaving its promise pending for the life of the session.
    settle.current?.(false);
    settle.current = resolve;
    setRequest(next);
  }), []);

  const answer = useCallback((value: boolean) => {
    settle.current?.(value);
    settle.current = undefined;
    setRequest(undefined);
  }, []);

  // A caller that unmounts mid-question must not strand its promise either.
  useEffect(() => () => settle.current?.(false), []);

  return [ask, request ? <ConfirmDialog request={request} onAnswer={answer} /> : null];
}

function ConfirmDialog({ request, onAnswer }: { request: ConfirmRequest; onAnswer: (value: boolean) => void }) {
  const affirmative = useRef<HTMLButtonElement>(null);
  const danger = request.tone !== "neutral";

  useEffect(() => {
    affirmative.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        // Stop the workspace's own Escape handler from closing the dialog
        // underneath at the same time, which would answer and navigate at once.
        event.stopPropagation();
        onAnswer(false);
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [onAnswer]);

  return <div className="overlay confirm-overlay" onMouseDown={(event) => event.target === event.currentTarget && onAnswer(false)}>
    <section className={`confirm-dialog ${danger ? "is-danger" : ""}`} role="alertdialog" aria-modal="true" aria-label={request.title}>
      <div className="confirm-mark">{danger ? <TriangleAlert size={19} /> : <ShieldAlert size={19} />}</div>
      <h2>{request.title}</h2>
      <p>{request.body}</p>
      <div className="confirm-actions">
        <button type="button" onClick={() => onAnswer(false)}>Cancel</button>
        <button type="button" ref={affirmative} className="confirm-go" onClick={() => onAnswer(true)}>{request.action}</button>
      </div>
    </section>
  </div>;
}
