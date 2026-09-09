import { createRef } from "react";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CanvasBoard, type CanvasBoardHandle } from "./CanvasBoard";
import type { CanvasDocument, CanvasInput } from "./types";

const bridgeMock = vi.hoisted(() => ({
  getCanvas: vi.fn(),
  saveCanvas: vi.fn(),
  deleteCanvas: vi.fn(),
}));
vi.mock("./bridge", () => ({ vaultBridge: bridgeMock }));

afterEach(cleanup);

const canvas: CanvasDocument = {
  version: 1,
  id: "board-1",
  path: "Boards/Release.canvas",
  title: "Release",
  nodes: [],
  edges: [],
  nodeCount: 0,
  edgeCount: 0,
  createdAt: "2026-09-09T08:00:00.000Z",
  updatedAt: "2026-09-09T08:00:00.000Z",
  revision: 1,
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

describe("CanvasBoard updater flush", () => {
  it("preserves and follows up an edit made while an earlier save is in flight", async () => {
    const first = deferred<CanvasDocument>();
    bridgeMock.getCanvas.mockResolvedValue({ ...canvas });
    bridgeMock.saveCanvas
      .mockImplementationOnce(() => first.promise)
      .mockImplementationOnce(async (input: CanvasInput) => ({
        ...canvas,
        ...input,
        revision: 3,
        updatedAt: "2026-09-09T08:02:00.000Z",
      }));
    const ref = createRef<CanvasBoardHandle>();
    render(
      <CanvasBoard
        ref={ref}
        canvases={[canvas]}
        notes={[]}
        attachments={[]}
        onRefresh={vi.fn(async () => undefined)}
        onOpenNote={vi.fn()}
        onNotice={vi.fn()}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /Release/u }));
    const title = await screen.findByDisplayValue("Release");
    fireEvent.change(title, { target: { value: "Release one" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(bridgeMock.saveCanvas).toHaveBeenCalledTimes(1));

    fireEvent.change(title, { target: { value: "Release two" } });
    let flush!: Promise<void>;
    await act(async () => {
      flush = ref.current!.flush();
      first.resolve({ ...canvas, title: "Release one", revision: 2, updatedAt: "2026-09-09T08:01:00.000Z" });
      await flush;
    });

    expect(bridgeMock.saveCanvas).toHaveBeenCalledTimes(2);
    expect(bridgeMock.saveCanvas.mock.calls[1][0]).toMatchObject({ title: "Release two", baseRevision: 2 });
    expect(screen.getByDisplayValue("Release two")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Saved" })).toBeDisabled();
  });
});
