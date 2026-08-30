import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { parseCell, PropertyTable } from "./PropertyTable";
import type { PropertyRow, SavedView } from "./types";

const rows: PropertyRow[] = [
  {
    id: "note-a",
    path: "Atlas/Principles.md",
    title: "Principles",
    tags: ["product"],
    properties: { status: "living", confidence: 0.9, owners: ["you", "me"] },
    updatedAt: "2026-08-30T08:00:00.000Z",
  },
  {
    id: "note-b",
    path: "Security/Exposure.md",
    title: "Exposure",
    tags: ["security"],
    properties: { status: "reviewed", confidence: 0.4, owners: ["you"] },
    updatedAt: "2026-08-30T09:00:00.000Z",
  },
];

const savedView: SavedView = {
  id: "view-1",
  name: "Living only",
  filter: "living",
  tags: [],
  sort: "status",
  direction: "desc",
  columns: ["status"],
  createdAt: "2026-08-30T08:00:00.000Z",
  updatedAt: "2026-08-30T08:00:00.000Z",
};

function renderTable(overrides: Partial<Parameters<typeof PropertyTable>[0]> = {}) {
  const props = {
    rows,
    views: [] as SavedView[],
    onOpen: vi.fn(),
    onSaveView: vi.fn(async () => {}),
    onDeleteView: vi.fn(async () => {}),
    onEditProperty: vi.fn(async () => {}),
    ...overrides,
  };
  render(<PropertyTable {...props} />);
  return { props, table: screen.getByRole("region", { name: "Property table" }) };
}

afterEach(cleanup);

describe("property cell parsing", () => {
  it("infers the type the user clearly meant", () => {
    expect(parseCell("42", "old")).toBe(42);
    expect(parseCell("-3.5", "old")).toBe(-3.5);
    expect(parseCell("true", "old")).toBe(true);
    expect(parseCell("false", "old")).toBe(false);
    expect(parseCell("2026-08-30", "old")).toBe("2026-08-30");
    expect(parseCell("  spaced  ", "old")).toBe("spaced");
  });

  it("clears the property for an empty box and keeps arrays as arrays", () => {
    expect(parseCell("", "old")).toBeNull();
    expect(parseCell("null", "old")).toBeNull();
    expect(parseCell("you, me", ["you"])).toEqual(["you", "me"]);
  });
});

describe("property table", () => {
  it("edits a cell in place and writes the parsed value back", async () => {
    const { props, table } = renderTable();
    fireEvent.doubleClick(within(table).getByText("0.9"));

    const input = await within(table).findByLabelText("confidence for Principles");
    fireEvent.change(input, { target: { value: "0.75" } });
    fireEvent.keyDown(input, { key: "Enter" });

    await waitFor(() => expect(props.onEditProperty).toHaveBeenCalledWith("note-a", "confidence", 0.75));
  });

  it("leaves the old value on screen when the write fails and says why", async () => {
    const onEditProperty = vi.fn(async () => {
      throw new Error("vault is locked");
    });
    const { table } = renderTable({ onEditProperty });

    fireEvent.doubleClick(within(table).getByText("living"));
    const input = await within(table).findByLabelText("status for Principles");
    fireEvent.change(input, { target: { value: "archived" } });
    fireEvent.keyDown(input, { key: "Enter" });

    expect(await within(table).findByRole("alert")).toHaveTextContent("vault is locked");
    fireEvent.keyDown(input, { key: "Escape" });
    expect(within(table).getByText("living")).toBeInTheDocument();
  });

  it("abandons an edit on Escape without calling the vault", async () => {
    const { props, table } = renderTable();
    fireEvent.doubleClick(within(table).getByText("living"));
    const input = await within(table).findByLabelText("status for Principles");
    fireEvent.change(input, { target: { value: "archived" } });
    fireEvent.keyDown(input, { key: "Escape" });

    expect(props.onEditProperty).not.toHaveBeenCalled();
    expect(within(table).getByText("living")).toBeInTheDocument();
  });

  it("saves the current query under a name", async () => {
    const { props, table } = renderTable();
    fireEvent.change(within(table).getByLabelText("Filter properties"), { target: { value: "living" } });
    fireEvent.change(within(table).getByLabelText("View name"), { target: { value: "Living only" } });
    fireEvent.click(within(table).getByRole("button", { name: "Save view" }));

    await waitFor(() => expect(props.onSaveView).toHaveBeenCalledWith(expect.objectContaining({
      name: "Living only",
      filter: "living",
      sort: "title",
      direction: "asc",
    })));
  });

  it("refuses to save a nameless query", async () => {
    const { props, table } = renderTable();
    fireEvent.click(within(table).getByRole("button", { name: "Save view" }));
    expect(await within(table).findByRole("alert")).toHaveTextContent(/name the view/iu);
    expect(props.onSaveView).not.toHaveBeenCalled();
  });

  it("applies a saved query's filter, sort and columns", () => {
    const { table } = renderTable({ views: [savedView] });
    fireEvent.change(within(table).getByLabelText("Saved query"), { target: { value: savedView.id } });

    expect(within(table).getByLabelText("Filter properties")).toHaveValue("living");
    expect(within(table).getByText("Principles")).toBeInTheDocument();
    expect(within(table).queryByText("Exposure")).toBeNull();
    expect(within(table).queryByRole("button", { name: "Sort by confidence" })).toBeNull();
  });

  it("deletes the saved query it is showing", async () => {
    const { props, table } = renderTable({ views: [savedView] });
    fireEvent.change(within(table).getByLabelText("Saved query"), { target: { value: savedView.id } });
    fireEvent.click(within(table).getByRole("button", { name: /delete/iu }));
    await waitFor(() => expect(props.onDeleteView).toHaveBeenCalledWith(savedView.id));
  });

  it("sorts a column and reverses it on a second click", () => {
    const { table } = renderTable();
    const order = () => within(table).getAllByRole("row").slice(1).map((row) => row.textContent);

    fireEvent.click(within(table).getByRole("button", { name: "Sort by status" }));
    expect(order()[0]).toContain("Principles");

    fireEvent.click(within(table).getByRole("button", { name: "Sort by status" }));
    expect(order()[0]).toContain("Exposure");
  });
});
