import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { NoteDocument, PropertyRow, SavedView, SearchHit } from "./types";
import { DEFAULT_THEME, presetSettings, shade } from "./theme";

const sampleNote: NoteDocument = {
  version: 1,
  id: "0d17d6a9-55af-4cd3-b46a-9c76067c1934",
  path: "Atlas/Product principles.md",
  title: "Product principles",
  aliases: ["North star"],
  tags: ["product", "evergreen"],
  properties: { status: "living" },
  createdAt: "2026-08-30T08:00:00.000Z",
  updatedAt: "2026-08-30T08:00:00.000Z",
  revision: 7,
  body: "# Product principles\n\nFast, private, and linked to [[Least exposure]].",
};

const bridgeMock = vi.hoisted(() => ({
  unlock: vi.fn(),
  lock: vi.fn(),
  listNotes: vi.fn(),
  getNote: vi.fn(),
  saveNote: vi.fn(),
  createNote: vi.fn(),
  search: vi.fn(),
  backlinks: vi.fn(),
  graph: vi.fn(),
  propertyRows: vi.fn(),
  updateNoteProperty: vi.fn(),
  savedViews: vi.fn(),
  saveView: vi.fn(),
  deleteView: vi.fn(),
}));

vi.mock("./bridge", () => ({ vaultBridge: bridgeMock }));
vi.mock("./Editor", () => ({
  MarkdownEditor: ({ value, onChange }: { value: string; onChange: (value: string) => void }) => (
    <textarea aria-label="Markdown body" value={value} onChange={(event) => onChange(event.target.value)} />
  ),
}));

import { App } from "./App";

const secondNote: NoteDocument = {
  ...sampleNote,
  id: "25fe29c4-eb56-408b-aa11-2cf3ba650762",
  path: "Security/Least exposure.md",
  title: "Least exposure",
  body: "# Least exposure\n\nDiscovery and resolution stay separate.",
};

function withTwoNotes() {
  bridgeMock.listNotes.mockResolvedValue([{ ...sampleNote }, { ...secondNote }]);
  bridgeMock.getNote.mockImplementation(async (reference: string) =>
    reference === secondNote.id ? { ...secondNote } : { ...sampleNote });
}

function stubClipboard() {
  let held = "";
  const writeText = vi.fn(async (value: string) => { held = value; });
  const readText = vi.fn(async () => held);
  Object.defineProperty(navigator, "clipboard", { value: { writeText, readText }, configurable: true });
  return { writeText, readText };
}

afterEach(cleanup);

async function unlockWorkspace(opened = "Product principles") {
  render(<App />);
  fireEvent.change(screen.getByLabelText("Passphrase"), { target: { value: "safe passphrase" } });
  fireEvent.click(screen.getByRole("button", { name: /unlock workspace/i }));
  await screen.findByDisplayValue(opened);
}

function manyNotes(count: number) {
  return Array.from({ length: count }, (_, index) => ({
    ...sampleNote,
    id: `note-${index}`,
    path: `Atlas/Note ${index}.md`,
    title: `Note ${index}`,
  }));
}

describe("desktop workspace", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.clearAllMocks();
    bridgeMock.unlock.mockResolvedValue({ name: "personal", path: "./vault/personal", noteCount: 1 });
    bridgeMock.listNotes.mockResolvedValue([{ ...sampleNote }]);
    bridgeMock.getNote.mockResolvedValue({ ...sampleNote });
    bridgeMock.saveNote.mockImplementation(async (note: NoteDocument) => ({ ...note, revision: note.revision + 1 }));
    bridgeMock.createNote.mockResolvedValue({ ...sampleNote, id: "f377c38e-256a-4337-895a-a29b72ebde78", title: "Fresh thought" });
    bridgeMock.search.mockResolvedValue([]);
    bridgeMock.backlinks.mockResolvedValue([]);
    bridgeMock.graph.mockResolvedValue({ nodes: [{ id: sampleNote.id, title: sampleNote.title, path: sampleNote.path, tags: sampleNote.tags, degree: 0, cluster: 0 }], edges: [] });
    bridgeMock.propertyRows.mockResolvedValue([{ id: sampleNote.id, path: sampleNote.path, title: sampleNote.title, tags: sampleNote.tags, properties: sampleNote.properties, updatedAt: sampleNote.updatedAt }]);
    bridgeMock.lock.mockResolvedValue(undefined);
    bridgeMock.savedViews.mockResolvedValue([]);
    bridgeMock.deleteView.mockResolvedValue([]);
    bridgeMock.saveView.mockImplementation(async (view: SavedView) => [
      { ...view, id: view.id || "view-1", createdAt: sampleNote.createdAt, updatedAt: sampleNote.updatedAt },
    ]);
    bridgeMock.updateNoteProperty.mockImplementation(async (id: string, key: string, value: unknown) => ({
      id, path: sampleNote.path, title: sampleNote.title, tags: sampleNote.tags,
      properties: { ...sampleNote.properties, [key]: value }, updatedAt: sampleNote.updatedAt,
    }));
  });

  it("unlocks locally and opens the first encrypted note", async () => {
    await unlockWorkspace();
    expect(bridgeMock.unlock).toHaveBeenCalledWith("./vault/personal", "safe passphrase");
    expect(screen.getByRole("navigation", { name: "Vault notes" })).toBeInTheDocument();
    expect(screen.getByText("Encrypted & saved")).toBeInTheDocument();
  });

  it("searches notes and opens a result", async () => {
    const hit: SearchHit = { ...sampleNote, score: 20, excerpt: "Private by construction" };
    bridgeMock.search.mockResolvedValue([hit]);
    await unlockWorkspace();

    fireEvent.click(screen.getByTitle(/search vault/i));
    fireEvent.change(screen.getByPlaceholderText(/search titles/i), { target: { value: "private" } });
    await waitFor(() => expect(bridgeMock.search).toHaveBeenCalledWith("private"));
    expect(await screen.findByText("Private by construction")).toBeInTheDocument();
  });

  it("creates a note from the keyboard-first dialog", async () => {
    await unlockWorkspace();
    fireEvent.keyDown(window, { key: "n", ctrlKey: true });
    fireEvent.change(screen.getByPlaceholderText("Untitled idea"), { target: { value: "Fresh thought" } });
    fireEvent.click(screen.getByRole("button", { name: "Create note" }));
    await waitFor(() => expect(bridgeMock.createNote).toHaveBeenCalledWith("Inbox/Fresh thought", "Fresh thought"));
  });

  it("saves an edited title on demand and can lock the workspace", async () => {
    await unlockWorkspace();
    fireEvent.change(screen.getByLabelText("Note title"), { target: { value: "Sharper principles" } });
    expect(screen.getByText("Unsaved changes")).toBeInTheDocument();
    fireEvent.keyDown(window, { key: "s", ctrlKey: true });
    await waitFor(() => expect(bridgeMock.saveNote).toHaveBeenCalledWith(expect.objectContaining({ title: "Sharper principles" })));

    fireEvent.click(screen.getByTitle("Lock vault"));
    await screen.findByRole("button", { name: /unlock workspace/i });
    expect(bridgeMock.lock).toHaveBeenCalledOnce();
  });

  it("persists a dirty note before navigating away", async () => {
    withTwoNotes();
    await unlockWorkspace();

    fireEvent.change(screen.getByLabelText("Note title"), { target: { value: "Unsaved principle" } });
    fireEvent.click(screen.getByRole("button", { name: "Least exposure" }));
    await screen.findByDisplayValue("Least exposure");

    expect(bridgeMock.saveNote).toHaveBeenCalledWith(expect.objectContaining({ title: "Unsaved principle" }));
    expect(bridgeMock.saveNote.mock.invocationCallOrder[0]).toBeLessThan(bridgeMock.getNote.mock.invocationCallOrder.at(-1)!);
  });

  it("opens value-minimized graph and typed property views", async () => {
    await unlockWorkspace();
    fireEvent.click(screen.getByRole("button", { name: "Graph" }));
    expect(await screen.findByRole("region", { name: "Knowledge graph" })).toBeInTheDocument();
    expect(bridgeMock.graph).toHaveBeenCalledOnce();

    fireEvent.click(screen.getByRole("button", { name: "Data" }));
    const propertyView = await screen.findByRole("region", { name: "Property table" });
    expect(within(propertyView).getByRole("button", { name: "Product principles" })).toBeInTheDocument();
    expect(bridgeMock.propertyRows).toHaveBeenCalledOnce();
  });
  it("colours the global graph by community and only draws what fits", async () => {
    const nodes = Array.from({ length: 6 }, (_, index) => ({
      id: `graph-${index}`,
      title: `Node ${index}`,
      path: `Atlas/Node ${index}.md`,
      tags: [],
      degree: 2,
      cluster: index < 3 ? 0 : 1,
    }));
    bridgeMock.graph.mockResolvedValue({
      nodes,
      edges: [
        { source: "graph-0", target: "graph-1" }, { source: "graph-1", target: "graph-2" }, { source: "graph-2", target: "graph-0" },
        { source: "graph-3", target: "graph-4" }, { source: "graph-4", target: "graph-5" }, { source: "graph-5", target: "graph-3" },
      ],
    });
    await unlockWorkspace();

    fireEvent.click(screen.getByRole("button", { name: "Graph" }));
    const view = await screen.findByRole("region", { name: "Knowledge graph" });
    expect(await within(view).findByText(/6 of 6 notes drawn/u)).toBeInTheDocument();
    expect(within(view).getByText(/2 communities/u)).toBeInTheDocument();

    const communities = within(view).getByRole("group", { name: "Communities" });
    fireEvent.click(within(communities).getByRole("button", { name: /Community 2/u }));
    expect(await within(view).findByText(/3 of 3 notes drawn/u)).toBeInTheDocument();
  });

  it("stores a property query in the vault and writes an edited cell back through the bridge", async () => {
    await unlockWorkspace();
    fireEvent.click(screen.getByRole("button", { name: "Data" }));
    const table = await screen.findByRole("region", { name: "Property table" });
    await waitFor(() => expect(bridgeMock.savedViews).toHaveBeenCalledOnce());

    fireEvent.change(within(table).getByLabelText("View name"), { target: { value: "Living notes" } });
    fireEvent.click(within(table).getByRole("button", { name: "Save view" }));
    await waitFor(() => expect(bridgeMock.saveView).toHaveBeenCalledWith(expect.objectContaining({ name: "Living notes" })));
    expect(await within(table).findByRole("option", { name: "Living notes" })).toBeInTheDocument();

    fireEvent.doubleClick(within(table).getByText("living"));
    const cell = await within(table).findByLabelText("status for Product principles");
    fireEvent.change(cell, { target: { value: "archived" } });
    fireEvent.keyDown(cell, { key: "Enter" });

    await waitFor(() => expect(bridgeMock.updateNoteProperty).toHaveBeenCalledWith(sampleNote.id, "status", "archived"));
    expect(await within(table).findByText("archived")).toBeInTheDocument();
  });

  it("keeps opened notes in tabs and closes the active one back to its neighbour", async () => {
    withTwoNotes();
    await unlockWorkspace();

    fireEvent.click(screen.getByRole("button", { name: "Least exposure" }));
    await screen.findByDisplayValue("Least exposure");
    expect(within(screen.getByRole("tablist", { name: "Open notes" })).getAllByRole("tab")).toHaveLength(2);

    fireEvent.click(screen.getByRole("button", { name: "Close Least exposure" }));
    await screen.findByDisplayValue("Product principles");
    expect(within(screen.getByRole("tablist", { name: "Open notes" })).getAllByRole("tab")).toHaveLength(1);
  });

  it("persists a dirty note before its tab is closed", async () => {
    withTwoNotes();
    await unlockWorkspace();

    fireEvent.change(screen.getByLabelText("Note title"), { target: { value: "Closing draft" } });
    fireEvent.click(screen.getByRole("button", { name: "Close Product principles" }));

    await waitFor(() => expect(bridgeMock.saveNote).toHaveBeenCalledWith(expect.objectContaining({ title: "Closing draft" })));
    expect(await screen.findByText("The archive is quiet.")).toBeInTheDocument();
  });

  it("opens a note from the keyboard quick switcher and splits it into a second pane", async () => {
    withTwoNotes();
    await unlockWorkspace();

    fireEvent.keyDown(window, { key: "o", ctrlKey: true });
    const switcher = await screen.findByRole("dialog", { name: "Quick switcher" });
    const field = within(switcher).getByPlaceholderText(/open a note by title/i);
    fireEvent.change(field, { target: { value: "least" } });
    fireEvent.keyDown(field, { key: "Enter" });
    await screen.findByDisplayValue("Least exposure");

    fireEvent.keyDown(window, { key: "o", ctrlKey: true });
    const reopened = await screen.findByRole("dialog", { name: "Quick switcher" });
    const nextField = within(reopened).getByPlaceholderText(/open a note by title/i);
    fireEvent.change(nextField, { target: { value: "principles" } });
    fireEvent.keyDown(nextField, { key: "Enter", altKey: true });

    const split = await screen.findByLabelText("Split pane");
    expect(within(split).getByText("Product principles")).toBeInTheDocument();
    expect(screen.getByDisplayValue("Least exposure")).toBeInTheDocument();
  });

  it("copies a value into a self-clearing clipboard and wipes it when the vault locks", async () => {
    const clipboard = stubClipboard();
    await unlockWorkspace();

    fireEvent.click(screen.getByTitle("Copy note to a self-clearing clipboard"));
    await waitFor(() => expect(clipboard.writeText).toHaveBeenCalledWith(sampleNote.body));
    expect(await screen.findByText(/clipboard clears itself in 30s/i)).toBeInTheDocument();

    fireEvent.click(screen.getByTitle("Lock vault"));
    await screen.findByRole("button", { name: /unlock workspace/i });
    expect(clipboard.writeText).toHaveBeenLastCalledWith("");
  });

  it("locks the workspace after the configured idle window and says so", async () => {
    localStorage.setItem("sbrain:idle-lock", "1");
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      await unlockWorkspace();
      expect(screen.getByTitle(/lock the vault after a period without activity/i)).toHaveTextContent("1m");

      await vi.advanceTimersByTimeAsync(60_000);
      await waitFor(() => expect(bridgeMock.lock).toHaveBeenCalled());
      expect(await screen.findByText(/locked automatically after 1 minute/i)).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it("keeps the vault open past the idle window while auto-lock is disabled", async () => {
    localStorage.setItem("sbrain:idle-lock", "0");
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      await unlockWorkspace();
      await vi.advanceTimersByTimeAsync(20 * 60_000);
      expect(bridgeMock.lock).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });
  it("renders only a window of a large vault's file tree", async () => {
    const notes = manyNotes(4000);
    bridgeMock.listNotes.mockResolvedValue(notes);
    bridgeMock.getNote.mockImplementation(async (reference: string) => notes.find((note) => note.id === reference) ?? notes[0]);
    await unlockWorkspace("Note 0");

    const tree = screen.getByRole("navigation", { name: "Vault notes" });
    expect(within(tree).getAllByRole("button").length).toBeLessThan(40);
    expect(within(tree).getByRole("button", { name: /^Atlas/u })).toBeInTheDocument();
    expect(within(tree).queryByRole("button", { name: "Note 900" })).toBeNull();

    fireEvent.scroll(tree, { target: { scrollTop: 900 * 30 } });
    expect(await within(tree).findByRole("button", { name: "Note 900" })).toBeInTheDocument();
    expect(within(tree).queryByRole("button", { name: "Note 0" })).toBeNull();
    expect(within(tree).getAllByRole("button").length).toBeLessThan(40);
  });

  it("renders only a window of the property view for a large vault", async () => {
    const rows: PropertyRow[] = manyNotes(3000).map((note) => ({
      id: note.id, path: note.path, title: note.title, tags: [], properties: { status: "living" }, updatedAt: note.updatedAt,
    }));
    bridgeMock.propertyRows.mockResolvedValue(rows);
    await unlockWorkspace();

    fireEvent.click(screen.getByRole("button", { name: "Data" }));
    const table = await screen.findByRole("region", { name: "Property table" });
    expect(within(table).getByText(/3000 notes/u)).toBeInTheDocument();
    expect(within(table).getAllByRole("row").length).toBeLessThan(50);
    expect(within(table).getByRole("button", { name: "Note 0" })).toBeInTheDocument();
  });

  it("edits, persists and resets the workspace theme", async () => {
    await unlockWorkspace();
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    const palette = await screen.findByRole("dialog", { name: "Command palette" });
    fireEvent.click(within(palette).getByRole("button", { name: "Customize theme" }));
    const editor = await screen.findByRole("dialog", { name: "Theme editor" });

    fireEvent.click(within(editor).getByRole("button", { name: /slate/i }));
    await waitFor(() => expect(document.documentElement.style.getPropertyValue("--paper")).toBe(presetSettings("slate").surface));

    fireEvent.change(within(editor).getByLabelText("Accent hex"), { target: { value: "#ff8800" } });
    await waitFor(() => expect(document.documentElement.style.getPropertyValue("--acid")).toBe("#ff8800"));
    expect(document.documentElement.style.getPropertyValue("--acid-deep")).toBe(shade("#ff8800", -0.34));
    expect(JSON.parse(localStorage.getItem("sbrain:theme")!)).toMatchObject({ accent: "#ff8800", preset: "custom" });

    fireEvent.click(within(editor).getByRole("button", { name: /reset to archive/i }));
    await waitFor(() => expect(document.documentElement.style.getPropertyValue("--acid")).toBe(DEFAULT_THEME.accent));
    expect(localStorage.getItem("sbrain:theme")).toBeNull();
  });

  it("warns when an edited theme drops below readable contrast", async () => {
    await unlockWorkspace();
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    const palette = await screen.findByRole("dialog", { name: "Command palette" });
    fireEvent.click(within(palette).getByRole("button", { name: "Customize theme" }));
    const editor = await screen.findByRole("dialog", { name: "Theme editor" });

    expect(within(editor).getByText(/· AA$/u)).toBeInTheDocument();
    fireEvent.change(within(editor).getByLabelText("Ink hex"), { target: { value: "#e9e6dc" } });
    expect(await within(editor).findByText(/below AA$/u)).toBeInTheDocument();
  });
});
