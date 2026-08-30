import { useEffect, useRef } from "react";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { markdown } from "@codemirror/lang-markdown";
import { defaultHighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { EditorState } from "@codemirror/state";
import {
  drawSelection,
  dropCursor,
  EditorView,
  highlightActiveLine,
  highlightSpecialChars,
  keymap,
  lineNumbers,
} from "@codemirror/view";

interface EditorProps {
  value: string;
  onChange: (value: string) => void;
}

const theme = EditorView.theme({
  "&": { height: "100%", background: "transparent", color: "var(--ink)" },
  ".cm-scroller": {
    overflow: "auto",
    fontFamily: "var(--font-editor)",
    fontSize: "var(--reading-size, 17px)",
    lineHeight: "1.72",
    padding: "32px 0 120px",
  },
  ".cm-content": { maxWidth: "760px", margin: "0 auto", padding: "0 48px", caretColor: "var(--acid-deep)" },
  ".cm-line": { padding: "0" },
  ".cm-gutters": { background: "transparent", color: "var(--muted-2)", border: "0", paddingLeft: "10px" },
  ".cm-activeLineGutter": { background: "transparent", color: "var(--ink-soft)" },
  ".cm-activeLine": { background: "color-mix(in srgb, var(--acid) 6%, transparent)" },
  ".cm-selectionBackground, &.cm-focused .cm-selectionBackground": { background: "rgba(151, 181, 63, .22)" },
  ".cm-cursor": { borderLeftColor: "var(--acid-deep)", borderLeftWidth: "2px" },
  ".ͼb": { color: "#8b3e2f" },
  ".ͼc": { color: "#46633d" },
  ".ͼd": { color: "#765d23" },
  ".ͼe": { color: "#315d69" },
  ".ͼi": { color: "#707165", fontStyle: "italic" },
});

export function MarkdownEditor({ value, onChange }: EditorProps) {
  const host = useRef<HTMLDivElement>(null);
  const viewRef = useRef<EditorView | undefined>(undefined);
  const changeRef = useRef(onChange);
  changeRef.current = onChange;

  useEffect(() => {
    if (!host.current) return;
    const state = EditorState.create({
      doc: value,
      extensions: [
        lineNumbers(),
        highlightSpecialChars(),
        history(),
        drawSelection(),
        dropCursor(),
        highlightActiveLine(),
        markdown(),
        syntaxHighlighting(defaultHighlightStyle),
        keymap.of([indentWithTab, ...defaultKeymap, ...historyKeymap]),
        EditorView.lineWrapping,
        theme,
        EditorView.updateListener.of((update) => {
          if (update.docChanged) changeRef.current(update.state.doc.toString());
        }),
      ],
    });
    const view = new EditorView({ state, parent: host.current });
    viewRef.current = view;
    return () => view.destroy();
  }, []);

  useEffect(() => {
    const view = viewRef.current;
    if (!view || view.state.doc.toString() === value) return;
    view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: value } });
  }, [value]);

  return <div className="editor-host" ref={host} aria-label="Markdown editor" />;
}
