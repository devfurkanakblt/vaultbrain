import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AttachmentInfo, CanvasDocument, CanvasInput, NoteDocument, PropertyRow, SavedView, SearchHit, WorkspaceState } from "./types";
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
  pickVaultDirectory: vi.fn(),
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
  unlinkedMentions: vi.fn(),
  linkMention: vi.fn(),
  workspaceState: vi.fn(),
  saveWorkspaceState: vi.fn(),
  savedViews: vi.fn(),
  saveView: vi.fn(),
  deleteView: vi.fn(),
  canvases: vi.fn(),
  getCanvas: vi.fn(),
  saveCanvas: vi.fn(),
  deleteCanvas: vi.fn(),
  renameNote: vi.fn(),
  deleteNote: vi.fn(),
  deletedNotes: vi.fn(),
  noteRevisions: vi.fn(),
  noteRevision: vi.fn(),
  restoreRevision: vi.fn(),
  templates: vi.fn(),
  createFromTemplate: vi.fn(),
  dailyNote: vi.fn(),
  attachments: vi.fn(),
  addAttachment: vi.fn(),
  readAttachment: vi.fn(),
  deleteAttachment: vi.fn(),
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

const sampleAttachment: AttachmentInfo = {
  id: "8ad0a1e1c4f04b0f9b5c1de0f2a37c5b8ad0a1e1c4f04b0f9b5c1de0f2a37c5b",
  filename: "diagram.png",
  mime: "image/png",
  size: 2048,
  chunks: 1,
  createdAt: "2026-08-30T08:00:00.000Z",
};

const sampleCanvas: CanvasDocument = {
  version: 1,
  id: "c2f0a4d6-1f6c-4f0f-9a5e-6b7f0f21c8aa",
  path: "Boards/Product map.canvas",
  title: "Product map",
  nodes: [],
  edges: [],
  nodeCount: 0,
  edgeCount: 0,
  createdAt: "2026-08-30T08:00:00.000Z",
  updatedAt: "2026-08-30T08:00:00.000Z",
  revision: 3,
};

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
    bridgeMock.unlinkedMentions.mockResolvedValue([]);
    bridgeMock.linkMention.mockResolvedValue([]);
    bridgeMock.workspaceState.mockResolvedValue({ version: 1, bookmarks: [], layouts: [] });
    bridgeMock.saveWorkspaceState.mockImplementation(async (state: WorkspaceState) => ({
      ...state,
      layouts: state.layouts.map((layout, index) => ({ ...layout, id: layout.id || `layout-${index}` })),
    }));
    bridgeMock.deleteView.mockResolvedValue([]);
    bridgeMock.saveView.mockImplementation(async (view: SavedView) => [
      { ...view, id: view.id || "view-1", createdAt: sampleNote.createdAt, updatedAt: sampleNote.updatedAt },
    ]);
    bridgeMock.canvases.mockResolvedValue([{
      id: sampleCanvas.id, path: sampleCanvas.path, title: sampleCanvas.title,
      nodeCount: 0, edgeCount: 0, updatedAt: sampleCanvas.updatedAt, revision: sampleCanvas.revision,
    }]);
    bridgeMock.getCanvas.mockResolvedValue({ ...sampleCanvas });
    bridgeMock.saveCanvas.mockImplementation(async (input: CanvasInput) => ({
      ...sampleCanvas, ...input, title: input.title ?? sampleCanvas.title,
      nodeCount: input.nodes.length, edgeCount: input.edges.length,
      revision: (input.baseRevision ?? 0) + 1,
    }));
    bridgeMock.renameNote.mockImplementation(async (_reference: string, path: string, title?: string) => ({
      ...sampleNote, path: path.endsWith(".md") ? path : `${path}.md`,
      title: title ?? sampleNote.title, revision: sampleNote.revision + 1,
    }));
    bridgeMock.deleteNote.mockResolvedValue({
      id: sampleNote.id, path: sampleNote.path, title: sampleNote.title, aliases: sampleNote.aliases,
      tags: sampleNote.tags, updatedAt: sampleNote.updatedAt, revision: sampleNote.revision,
    });
    bridgeMock.deletedNotes.mockResolvedValue([{
      id: "b7d9e2a6-4f13-4a55-9c2e-0f3a1d5b7c88", path: "Inbox/Removed.md",
      title: "Removed thought", revision: 4, updatedAt: sampleNote.updatedAt,
    }]);
    bridgeMock.noteRevisions.mockResolvedValue([
      { revision: 7, updatedAt: sampleNote.updatedAt, current: true },
      { revision: 6, updatedAt: "2026-08-29T08:00:00.000Z", current: false },
    ]);
    bridgeMock.noteRevision.mockImplementation(async (_reference: string, revision: number) => ({
      ...sampleNote, revision, body: `# Product principles\n\nRevision ${revision} text.`,
    }));
    bridgeMock.restoreRevision.mockImplementation(async (_reference: string, revision: number) => ({
      ...sampleNote, revision: 8, body: `# Product principles\n\nRevision ${revision} text.`,
    }));
    bridgeMock.templates.mockResolvedValue([{
      id: "3a0f8f2d-19b2-4f61-9d2a-7c8b5e2f1a04", path: "Templates/Meeting.md", title: "Meeting",
      aliases: [], tags: ["template"], updatedAt: sampleNote.updatedAt, revision: 2,
    }]);
    bridgeMock.createFromTemplate.mockResolvedValue({
      ...sampleNote, id: "9f2b1c34-77aa-4a0e-bd51-1c6f8a3d2b90",
      path: "Meetings/Kickoff.md", title: "Kickoff", revision: 1,
    });
    bridgeMock.dailyNote.mockResolvedValue({
      note: { ...sampleNote, id: "5c1a7e90-88fd-4f2b-9f0c-2a4e6b8d1c33", path: "Daily/2026-08-30.md", title: "2026-08-30", revision: 1 },
      created: true,
    });
    bridgeMock.attachments.mockResolvedValue([{ ...sampleAttachment }]);
    bridgeMock.addAttachment.mockResolvedValue({ ...sampleAttachment });
    bridgeMock.readAttachment.mockResolvedValue({ info: { ...sampleAttachment }, data: "AQID" });
    bridgeMock.deleteAttachment.mockResolvedValue({ ...sampleAttachment });
    bridgeMock.updateNoteProperty.mockImplementation(async (id: string, key: string, value: unknown) => ({
      id, path: sampleNote.path, title: sampleNote.title, tags: sampleNote.tags,
      properties: { ...sampleNote.properties, [key]: value }, updatedAt: sampleNote.updatedAt,
    }));
  });

  it("unlocks locally and opens the first encrypted note", async () => {
    await unlockWorkspace();
    expect(bridgeMock.unlock).toHaveBeenCalledWith("./vault/personal", "safe passphrase");
    expect(screen.getByText("VB")).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "Vault notes" })).toBeInTheDocument();
    expect(screen.getByText("Encrypted & saved")).toBeInTheDocument();
  });

  it("fills the vault path from the native folder chooser", async () => {
    bridgeMock.pickVaultDirectory.mockResolvedValue("D:/Vaults/Field notes");
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Choose a vault folder" }));
    await waitFor(() => expect(screen.getByLabelText("Vault location")).toHaveValue("D:/Vaults/Field notes"));
  });

  it("leaves the vault path alone when the folder chooser is dismissed", async () => {
    bridgeMock.pickVaultDirectory.mockResolvedValue(null);
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Choose a vault folder" }));
    await waitFor(() => expect(bridgeMock.pickVaultDirectory).toHaveBeenCalled());
    expect(screen.getByLabelText("Vault location")).toHaveValue("./vault/personal");
  });

  it("remembers unlocked vault paths and flags one this device has not opened", async () => {
    render(<App />);
    const location = screen.getByLabelText("Vault location");
    expect(location).toHaveAccessibleDescription(/has not opened/iu);

    fireEvent.change(screen.getByLabelText("Passphrase"), { target: { value: "safe passphrase" } });
    fireEvent.click(screen.getByRole("button", { name: /unlock workspace/i }));
    await screen.findByDisplayValue("Product principles");
    expect(JSON.parse(localStorage.getItem("vbrain:vaults")!)).toEqual(["./vault/personal"]);

    cleanup();
    render(<App />);
    const reopened = screen.getByLabelText("Vault location");
    expect(reopened).not.toHaveAccessibleDescription();
    // The one remembered vault is the one already in the field, so the list has
    // nowhere else to offer and stays out of the way.
    expect(screen.queryByRole("button", { name: "./vault/personal" })).not.toBeInTheDocument();

    fireEvent.change(reopened, { target: { value: "D:/Vaults/Work" } });
    expect(reopened).toHaveAccessibleDescription(/has not opened/iu);
    fireEvent.click(screen.getByRole("button", { name: "./vault/personal" }));
    expect(screen.getByLabelText("Vault location")).toHaveValue("./vault/personal");
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

  it("pins the open note to the sidebar and unpins it again", async () => {
    await unlockWorkspace();
    expect(screen.queryByRole("navigation", { name: "Bookmarked notes" })).toBeNull();

    fireEvent.click(screen.getByTitle("Bookmark this note"));
    await waitFor(() => expect(bridgeMock.saveWorkspaceState).toHaveBeenCalledWith(expect.objectContaining({
      bookmarks: [expect.objectContaining({ id: sampleNote.id, label: sampleNote.title })],
    })));

    const pinned = await screen.findByRole("navigation", { name: "Bookmarked notes" });
    expect(within(pinned).getByRole("button", { name: "Product principles" })).toBeInTheDocument();

    fireEvent.click(screen.getByTitle("Remove bookmark"));
    await waitFor(() => expect(screen.queryByRole("navigation", { name: "Bookmarked notes" })).toBeNull());
  });

  it("saves the open tabs as a named workspace and reopens it", async () => {
    withTwoNotes();
    await unlockWorkspace();
    fireEvent.click(screen.getByRole("button", { name: "Least exposure" }));
    await screen.findByDisplayValue("Least exposure");

    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    const palette = await screen.findByRole("dialog", { name: "Command palette" });
    fireEvent.click(within(palette).getByRole("option", { name: "Workspaces and saved layouts" }));

    const dialog = await screen.findByRole("dialog", { name: "Workspaces" });
    fireEvent.change(within(dialog).getByLabelText("Workspace name"), { target: { value: "Morning review" } });
    fireEvent.click(within(dialog).getByRole("button", { name: /save 2 open tabs/iu }));

    await waitFor(() => expect(bridgeMock.saveWorkspaceState).toHaveBeenCalledWith(expect.objectContaining({
      layouts: [expect.objectContaining({ name: "Morning review", tabs: [sampleNote.id, secondNote.id], active: secondNote.id })],
    })));
    expect(await within(dialog).findByRole("button", { name: "Open Morning review" })).toBeInTheDocument();

    fireEvent.click(within(dialog).getByRole("button", { name: "Open Morning review" }));
    expect(await screen.findByText(/opened the "morning review" workspace/iu)).toBeInTheDocument();
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
    localStorage.setItem("vbrain:idle-lock", "1");
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
    localStorage.setItem("vbrain:idle-lock", "0");
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
    fireEvent.click(within(palette).getByRole("option", { name: "Customize theme" }));
    const editor = await screen.findByRole("dialog", { name: "Theme editor" });

    fireEvent.click(within(editor).getByRole("button", { name: /slate/i }));
    await waitFor(() => expect(document.documentElement.style.getPropertyValue("--paper")).toBe(presetSettings("slate").surface));

    fireEvent.change(within(editor).getByLabelText("Accent hex"), { target: { value: "#ff8800" } });
    await waitFor(() => expect(document.documentElement.style.getPropertyValue("--acid")).toBe("#ff8800"));
    expect(document.documentElement.style.getPropertyValue("--acid-deep")).toBe(shade("#ff8800", -0.34));
    expect(JSON.parse(localStorage.getItem("vbrain:theme")!)).toMatchObject({ accent: "#ff8800", preset: "custom" });

    fireEvent.click(within(editor).getByRole("button", { name: /reset to/i }));
    await waitFor(() => expect(document.documentElement.style.getPropertyValue("--acid")).toBe(DEFAULT_THEME.accent));
    expect(localStorage.getItem("vbrain:theme")).toBeNull();
  });

  it("opens a canvas, adds a node and writes the board back encrypted", async () => {
    await unlockWorkspace();
    fireEvent.click(screen.getByRole("button", { name: "Canvas" }));
    await waitFor(() => expect(bridgeMock.canvases).toHaveBeenCalled());
    expect(bridgeMock.attachments).toHaveBeenCalled();

    fireEvent.click(await screen.findByRole("button", { name: /Product map/u }));
    await waitFor(() => expect(bridgeMock.getCanvas).toHaveBeenCalledWith(sampleCanvas.id));

    fireEvent.click(screen.getByTitle("Add text card"));
    fireEvent.change(await screen.findByLabelText("Canvas text"), { target: { value: "Pricing thesis" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(bridgeMock.saveCanvas).toHaveBeenCalled());
    const written = bridgeMock.saveCanvas.mock.calls.at(-1)![0] as CanvasInput;
    expect(written.id).toBe(sampleCanvas.id);
    expect(written.baseRevision).toBe(sampleCanvas.revision);
    expect(written.nodes).toHaveLength(1);
    expect(written.nodes[0]).toMatchObject({ type: "text", text: "Pricing thesis" });
  });

  it("places a vault note on the canvas as a linked file node", async () => {
    withTwoNotes();
    await unlockWorkspace();
    fireEvent.click(screen.getByRole("button", { name: "Canvas" }));
    fireEvent.click(await screen.findByRole("button", { name: /Product map/u }));
    await screen.findByDisplayValue("Product map");

    fireEvent.change(screen.getByLabelText("Note to add"), { target: { value: secondNote.id } });
    fireEvent.click(screen.getByTitle("Add the selected note"));
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(bridgeMock.saveCanvas).toHaveBeenCalled());
    const written = bridgeMock.saveCanvas.mock.calls.at(-1)![0] as CanvasInput;
    expect(written.nodes[0]).toMatchObject({ type: "file", noteId: secondNote.id, file: secondNote.path });
  });

  it("encrypts a chosen file into the attachment library", async () => {
    await unlockWorkspace();
    fireEvent.click(screen.getByRole("button", { name: "Files" }));
    await waitFor(() => expect(bridgeMock.attachments).toHaveBeenCalled());
    expect(await screen.findByText("diagram.png")).toBeInTheDocument();

    const picker = document.querySelector<HTMLInputElement>('input[type="file"]')!;
    fireEvent.change(picker, {
      target: { files: [new File([new Uint8Array([1, 2, 3])], "sketch.png", { type: "image/png" })] },
    });

    await waitFor(() => expect(bridgeMock.addAttachment).toHaveBeenCalledWith("sketch.png", "image/png", "AQID"));
    expect(await screen.findByText(/1 attachment encrypted and stored/u)).toBeInTheDocument();
  });

  it("never renders active HTML attachment content in an iframe", async () => {
    const html = { ...sampleAttachment, filename: "attack.html", mime: "text/html" };
    bridgeMock.attachments.mockResolvedValue([html]);
    bridgeMock.readAttachment.mockResolvedValue({
      info: html,
      data: btoa('<script>window.__TAURI_INTERNALS__.invoke("get_note")</script>'),
    });
    await unlockWorkspace();
    fireEvent.click(screen.getByRole("button", { name: "Files" }));
    fireEvent.click(await screen.findByRole("button", { name: /attack\.html/u }));

    const dialog = await screen.findByRole("dialog", { name: "Preview attack.html" });
    expect(dialog.querySelector("iframe")).toBeNull();
    expect(within(dialog).getByText(/not rendered inline/u)).toBeInTheDocument();
  });

  it("renders plain text as inert text rather than browser content", async () => {
    const text = { ...sampleAttachment, filename: "notes.txt", mime: "text/plain" };
    bridgeMock.attachments.mockResolvedValue([text]);
    bridgeMock.readAttachment.mockResolvedValue({ info: text, data: btoa("<b>literal</b>") });
    await unlockWorkspace();
    fireEvent.click(screen.getByRole("button", { name: "Files" }));
    fireEvent.click(await screen.findByRole("button", { name: /notes\.txt/u }));

    const dialog = await screen.findByRole("dialog", { name: "Preview notes.txt" });
    expect(within(dialog).getByText("<b>literal</b>")).toBeInTheDocument();
    expect(dialog.querySelector("b")?.textContent).not.toBe("literal");
  });

  it("drops canvases and attachments from memory when the vault locks", async () => {
    await unlockWorkspace();
    fireEvent.click(screen.getByRole("button", { name: "Files" }));
    expect(await screen.findByText("diagram.png")).toBeInTheDocument();

    fireEvent.keyDown(window, { key: "l", ctrlKey: true });
    await waitFor(() => expect(bridgeMock.lock).toHaveBeenCalled());
    expect(screen.queryByText("diagram.png")).not.toBeInTheDocument();

    bridgeMock.attachments.mockClear();
    fireEvent.change(screen.getByLabelText("Passphrase"), { target: { value: "safe passphrase" } });
    fireEvent.click(screen.getByRole("button", { name: /unlock workspace/i }));
    await screen.findByDisplayValue("Product principles");
    expect(bridgeMock.attachments).not.toHaveBeenCalled();
  });

  it("moves a note to a new path and keeps the editor on it", async () => {
    await unlockWorkspace();
    fireEvent.click(screen.getByTitle("Rename or move this note"));
    const dialog = await screen.findByRole("dialog", { name: "Rename or move note" });
    expect(within(dialog).getByLabelText("Logical path")).toHaveValue("Atlas/Product principles");

    fireEvent.change(within(dialog).getByLabelText("Logical path"), { target: { value: "Archive/Principles" } });
    fireEvent.change(within(dialog).getByLabelText("Title"), { target: { value: "Principles" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Move note" }));

    await waitFor(() => expect(bridgeMock.renameNote).toHaveBeenCalledWith(sampleNote.id, "Archive/Principles", "Principles"));
    expect(await screen.findByDisplayValue("Principles")).toBeInTheDocument();
    expect(await screen.findByText(/Moved to Archive\/Principles\.md/u)).toBeInTheDocument();
  });

  it("deletes the open note and clears it from the workspace", async () => {
    bridgeMock.listNotes.mockResolvedValueOnce([{ ...sampleNote }]).mockResolvedValue([]);
    await unlockWorkspace();

    fireEvent.click(screen.getByTitle("Delete this note"));
    const ask = await screen.findByRole("alertdialog", { name: /Delete .Product principles/u });
    expect(within(ask).getByText(/its encrypted history stays in the vault/u)).toBeInTheDocument();
    fireEvent.click(within(ask).getByRole("button", { name: "Delete note" }));

    await waitFor(() => expect(bridgeMock.deleteNote).toHaveBeenCalledWith(sampleNote.id));
    expect(await screen.findByText("The archive is quiet.")).toBeInTheDocument();
    expect(screen.getByText(/Restore it from the deleted-notes list/u)).toBeInTheDocument();
  });

  it("keeps the note when a delete is declined", async () => {
    await unlockWorkspace();

    fireEvent.click(screen.getByTitle("Delete this note"));
    const ask = await screen.findByRole("alertdialog", { name: /Delete .Product principles/u });
    fireEvent.click(within(ask).getByRole("button", { name: "Cancel" }));

    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument());
    expect(bridgeMock.deleteNote).not.toHaveBeenCalled();
    expect(screen.getByDisplayValue("Product principles")).toBeInTheDocument();
  });

  it("reads an archived revision and restores it forward", async () => {
    await unlockWorkspace();
    fireEvent.click(screen.getByTitle("Encrypted revision history"));
    const dialog = await screen.findByRole("dialog", { name: "Note history" });

    // The newest non-current revision is selected, so history opens on a diff.
    await waitFor(() => expect(bridgeMock.noteRevision).toHaveBeenCalledWith(sampleNote.id, 6));
    expect(await within(dialog).findByText(/Revision 6 text/u)).toBeInTheDocument();
    expect(within(dialog).getByText("current")).toBeInTheDocument();

    fireEvent.click(within(dialog).getByRole("button", { name: /Restore revision 6/u }));
    await waitFor(() => expect(bridgeMock.restoreRevision).toHaveBeenCalledWith(sampleNote.id, 6));
    expect(await screen.findByText(/Restored revision 6 as revision 8/u)).toBeInTheDocument();
  });

  it("restores a deleted note from its encrypted history", async () => {
    await unlockWorkspace();
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    const palette = await screen.findByRole("dialog", { name: "Command palette" });
    fireEvent.click(within(palette).getByRole("option", { name: "Restore a deleted note" }));

    const dialog = await screen.findByRole("dialog", { name: "Deleted notes" });
    expect(await within(dialog).findByText("Removed thought")).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole("button", { name: /restore/i }));

    await waitFor(() => expect(bridgeMock.restoreRevision).toHaveBeenCalledWith("b7d9e2a6-4f13-4a55-9c2e-0f3a1d5b7c88", 4));
  });

  it("renders a template into a new note with caller variables", async () => {
    const rendered = { ...sampleNote, id: "9f2b1c34-77aa-4a0e-bd51-1c6f8a3d2b90", path: "Meetings/Kickoff.md", title: "Kickoff", revision: 1 };
    bridgeMock.getNote.mockImplementation(async (reference: string) =>
      reference === rendered.id ? { ...rendered } : { ...sampleNote });
    await unlockWorkspace();
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    const palette = await screen.findByRole("dialog", { name: "Command palette" });
    fireEvent.click(within(palette).getByRole("option", { name: "New note from a template" }));

    const dialog = await screen.findByRole("dialog", { name: "New note from template" });
    await waitFor(() => expect(bridgeMock.templates).toHaveBeenCalled());
    fireEvent.change(within(dialog).getByLabelText("Title"), { target: { value: "Kickoff" } });
    fireEvent.change(within(dialog).getByLabelText("Folder"), { target: { value: "Meetings/" } });
    fireEvent.change(within(dialog).getByLabelText("Variables"), { target: { value: "client=Acme\nowner = You" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Create note" }));

    await waitFor(() => expect(bridgeMock.createFromTemplate).toHaveBeenCalledWith(
      "3a0f8f2d-19b2-4f61-9d2a-7c8b5e2f1a04", "Meetings/Kickoff", "Kickoff",
      { client: "Acme", owner: "You" },
    ));
    expect(await screen.findByDisplayValue("Kickoff")).toBeInTheDocument();
  });

  it("opens today's daily note from the keyboard", async () => {
    const daily = { ...sampleNote, id: "5c1a7e90-88fd-4f2b-9f0c-2a4e6b8d1c33", path: "Daily/2026-08-30.md", title: "2026-08-30", revision: 1 };
    bridgeMock.getNote.mockImplementation(async (reference: string) =>
      reference === daily.id ? { ...daily } : { ...sampleNote });
    await unlockWorkspace();
    fireEvent.keyDown(window, { key: "d", ctrlKey: true });

    await waitFor(() => expect(bridgeMock.dailyNote).toHaveBeenCalled());
    expect(await screen.findByDisplayValue("2026-08-30")).toBeInTheDocument();
    expect(screen.getByText(/Created today's note at Daily\/2026-08-30\.md/u)).toBeInTheDocument();
  });

  it("warns instead of failing when no note is tagged as a template", async () => {
    bridgeMock.templates.mockResolvedValue([]);
    await unlockWorkspace();
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    const palette = await screen.findByRole("dialog", { name: "Command palette" });
    fireEvent.click(within(palette).getByRole("option", { name: "New note from a template" }));

    const dialog = await screen.findByRole("dialog", { name: "New note from template" });
    expect(within(dialog).getByText(/No note in this vault carries the/u)).toBeInTheDocument();
    expect(within(dialog).queryByRole("button", { name: "Create note" })).not.toBeInTheDocument();
  });

  it("filters the command palette and runs what the keyboard lands on", async () => {
    await unlockWorkspace();
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    const palette = await screen.findByRole("dialog", { name: "Command palette" });
    const field = within(palette).getByLabelText("Filter commands");

    fireEvent.change(field, { target: { value: "theme" } });
    const narrowed = within(palette).getAllByRole("option");
    expect(narrowed).toHaveLength(1);
    expect(narrowed[0]).toHaveTextContent("Customize theme");

    fireEvent.keyDown(field, { key: "Enter" });
    expect(await screen.findByRole("dialog", { name: "Theme editor" })).toBeInTheDocument();
  });

  it("moves the palette selection with the arrow keys and says when nothing matches", async () => {
    await unlockWorkspace();
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    const palette = await screen.findByRole("dialog", { name: "Command palette" });
    const field = within(palette).getByLabelText("Filter commands");

    fireEvent.change(field, { target: { value: "note" } });
    const options = within(palette).getAllByRole("option");
    expect(options[0]).toHaveAttribute("aria-selected", "true");

    // Down one, then run: the second match, not the first.
    fireEvent.keyDown(field, { key: "ArrowDown" });
    expect(within(palette).getAllByRole("option")[1]).toHaveAttribute("aria-selected", "true");
    fireEvent.keyDown(field, { key: "Enter" });
    expect(await screen.findByRole("dialog", { name: "Quick switcher" })).toBeInTheDocument();

    fireEvent.keyDown(window, { key: "Escape" });
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    const reopened = await screen.findByRole("dialog", { name: "Command palette" });
    fireEvent.change(within(reopened).getByLabelText("Filter commands"), { target: { value: "xylophone" } });
    expect(within(reopened).queryAllByRole("option")).toHaveLength(0);
    expect(within(reopened).getByText(/No command matches/u)).toBeInTheDocument();
  });

  it("reads a failure as an alert instead of a confirmation", async () => {
    bridgeMock.dailyNote.mockRejectedValueOnce(new Error("Daily folder is read-only."));
    await unlockWorkspace();
    fireEvent.keyDown(window, { key: "d", ctrlKey: true });

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Daily folder is read-only.");
    expect(alert).toHaveClass("error");
    // A success still arrives as a plain status, not an alert.
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("opens the vault menu and locks the workspace from it", async () => {
    await unlockWorkspace();
    fireEvent.click(screen.getByTitle("Current encrypted vault"));

    const menu = await screen.findByRole("menu", { name: "Vault" });
    expect(within(menu).getByText("./vault/personal")).toBeInTheDocument();
    fireEvent.click(within(menu).getByRole("menuitem", { name: /Lock and switch vault/u }));

    await waitFor(() => expect(bridgeMock.lock).toHaveBeenCalled());
    expect(await screen.findByLabelText("Passphrase")).toBeInTheDocument();
  });

  it("reports how the vault divides across folders", async () => {
    bridgeMock.listNotes.mockResolvedValue([
      { ...sampleNote },
      { ...sampleNote, id: "n2", path: "Atlas/Second.md", title: "Second" },
      { ...sampleNote, id: "n3", path: "Journal/Today.md", title: "Today" },
    ]);
    await unlockWorkspace();

    const bar = await screen.findByRole("img", { name: "3 notes across 2 folders" });
    const segments = bar.querySelectorAll("span");
    expect(segments).toHaveLength(2);
    // Widest folder first, so the bar reads as a ranking.
    expect(segments[0]).toHaveAttribute("title", "Atlas · 2 notes");
    expect(segments[1]).toHaveAttribute("title", "Journal · 1 note");
  });

  it("zooms the canvas board and returns it to its own scale", async () => {
    await unlockWorkspace();
    fireEvent.click(screen.getByRole("button", { name: "Canvas" }));
    fireEvent.click(await screen.findByRole("button", { name: /Product map/u }));
    await waitFor(() => expect(bridgeMock.getCanvas).toHaveBeenCalledWith(sampleCanvas.id));

    const level = await screen.findByTitle("Reset to 100%");
    expect(level).toHaveTextContent("100%");

    fireEvent.click(screen.getByTitle("Zoom in"));
    expect(level).toHaveTextContent("125%");
    fireEvent.click(screen.getByTitle("Zoom in"));
    expect(level).toHaveTextContent("156%");

    fireEvent.click(level);
    expect(level).toHaveTextContent("100%");

    fireEvent.click(screen.getByTitle("Zoom out"));
    expect(level).toHaveTextContent("80%");
  });

  it("asks in the app's own dialog before deleting a canvas", async () => {
    await unlockWorkspace();
    fireEvent.click(screen.getByRole("button", { name: "Canvas" }));
    fireEvent.click(await screen.findByRole("button", { name: /Product map/u }));
    await waitFor(() => expect(bridgeMock.getCanvas).toHaveBeenCalled());

    fireEvent.click(screen.getByTitle("Delete canvas"));
    const ask = await screen.findByRole("alertdialog", { name: /Delete the canvas/u });
    fireEvent.click(within(ask).getByRole("button", { name: "Cancel" }));
    expect(bridgeMock.deleteCanvas).not.toHaveBeenCalled();

    fireEvent.click(screen.getByTitle("Delete canvas"));
    const again = await screen.findByRole("alertdialog", { name: /Delete the canvas/u });
    fireEvent.click(within(again).getByRole("button", { name: "Delete canvas" }));
    await waitFor(() => expect(bridgeMock.deleteCanvas).toHaveBeenCalledWith(sampleCanvas.id));
  });

  it("keeps a board link to http and https addresses", async () => {
    await unlockWorkspace();
    fireEvent.click(screen.getByRole("button", { name: "Canvas" }));
    fireEvent.click(await screen.findByRole("button", { name: /Product map/u }));
    await waitFor(() => expect(bridgeMock.getCanvas).toHaveBeenCalled());

    fireEvent.click(screen.getByTitle("Add web link"));
    const field = await screen.findByLabelText("Link address");
    fireEvent.change(field, { target: { value: "notes://secret" } });
    fireEvent.click(screen.getByRole("button", { name: "Add link" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/must begin with http/u);

    fireEvent.change(screen.getByLabelText("Link address"), { target: { value: "https://example.com/plan" } });
    fireEvent.click(screen.getByRole("button", { name: "Add link" }));
    expect(await screen.findByText("example.com")).toBeInTheDocument();
  });

  it("warns when an edited theme drops below readable contrast", async () => {
    await unlockWorkspace();
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    const palette = await screen.findByRole("dialog", { name: "Command palette" });
    fireEvent.click(within(palette).getByRole("option", { name: "Customize theme" }));
    const editor = await screen.findByRole("dialog", { name: "Theme editor" });

    expect(within(editor).getAllByText(/· AA$/u).length).toBeGreaterThan(0);
    fireEvent.change(within(editor).getByLabelText("Ink hex"), { target: { value: "#e9e6dc" } });
    expect(await within(editor).findByText(/below AA$/u)).toBeInTheDocument();
  });
});
