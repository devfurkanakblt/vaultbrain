import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ContextPanel } from "./ContextPanel";
import type { NoteDocument, UnlinkedMention } from "./types";

const note: NoteDocument = {
  version: 1,
  id: "note-a",
  path: "Atlas/Least exposure.md",
  title: "Least exposure",
  aliases: ["North star"],
  tags: ["security"],
  properties: { status: "living" },
  createdAt: "2026-08-30T08:00:00.000Z",
  updatedAt: "2026-08-30T08:00:00.000Z",
  revision: 3,
  body: "# Least exposure\n\n## Constraints\n\nBody text.",
};

const mention: UnlinkedMention = {
  id: "note-b",
  path: "Atlas/Notes.md",
  title: "Notes",
  aliases: [],
  tags: [],
  updatedAt: "2026-08-30T09:00:00.000Z",
  revision: 1,
  name: "Least exposure",
  count: 2,
  excerpt: "…Least exposure matters here…",
};

function renderPanel(overrides: Partial<Parameters<typeof ContextPanel>[0]> = {}) {
  const props = {
    note,
    outline: [{ level: 2, text: "Constraints" }],
    backlinks: [],
    mentions: [mention],
    onOpen: vi.fn(),
    onCopy: vi.fn(),
    onAliases: vi.fn(),
    onLink: vi.fn(async () => {}),
    ...overrides,
  };
  render(<ContextPanel {...props} />);
  return props;
}

afterEach(cleanup);

describe("aliases", () => {
  it("adds an alias on Enter", () => {
    const props = renderPanel();
    const input = screen.getByLabelText("New alias");
    fireEvent.change(input, { target: { value: "  Minimum exposure  " } });
    fireEvent.keyDown(input, { key: "Enter" });

    expect(props.onAliases).toHaveBeenCalledWith(["North star", "Minimum exposure"]);
    expect(input).toHaveValue("");
  });

  it("removes an alias", () => {
    const props = renderPanel();
    fireEvent.click(screen.getByLabelText("Remove alias North star"));
    expect(props.onAliases).toHaveBeenCalledWith([]);
  });

  it("refuses a duplicate alias whatever its casing", () => {
    const props = renderPanel();
    fireEvent.change(screen.getByLabelText("New alias"), { target: { value: "north STAR" } });
    fireEvent.click(screen.getByLabelText("Add alias"));

    expect(screen.getByRole("alert")).toHaveTextContent(/already on this note/iu);
    expect(props.onAliases).not.toHaveBeenCalled();
  });

  it("ignores an empty alias", () => {
    const props = renderPanel();
    fireEvent.change(screen.getByLabelText("New alias"), { target: { value: "   " } });
    fireEvent.click(screen.getByLabelText("Add alias"));
    expect(props.onAliases).not.toHaveBeenCalled();
  });
});

describe("unlinked mentions", () => {
  it("shows the matching text and how many times it appears", () => {
    renderPanel();
    expect(screen.getByText("Notes")).toBeInTheDocument();
    expect(screen.getByText("…Least exposure matters here…")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Link 2 mentions in Notes" })).toHaveTextContent("Link 2×");
  });

  it("links every mention in one source note", async () => {
    const props = renderPanel();
    fireEvent.click(screen.getByRole("button", { name: "Link 2 mentions in Notes" }));
    await waitFor(() => expect(props.onLink).toHaveBeenCalledWith("note-b"));
  });

  it("reports a failed link instead of pretending it worked", async () => {
    renderPanel({ onLink: vi.fn(async () => { throw new Error("vault is locked"); }) });
    fireEvent.click(screen.getByRole("button", { name: "Link 2 mentions in Notes" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("vault is locked");
  });

  it("says so plainly when nothing mentions the note", () => {
    renderPanel({ mentions: [] });
    expect(screen.getByText("Nothing names this note in passing.")).toBeInTheDocument();
  });
});
