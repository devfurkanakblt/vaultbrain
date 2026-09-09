import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { UpdatePanel } from "./UpdatePanel";
import { createUpdaterClient, type NativeUpdateSnapshot, type UpdateSnapshot, type UpdaterClient } from "./updater";
import { prepareUpdaterInstall } from "./update-install";

afterEach(cleanup);

const idle: UpdateSnapshot = { phase: "idle", currentVersion: "0.2.0" };

function client(overrides: Partial<UpdaterClient> = {}): UpdaterClient {
  return {
    status: vi.fn(async () => idle),
    check: vi.fn(async (): Promise<UpdateSnapshot> => ({ ...idle, phase: "up-to-date" })),
    download: vi.fn(async (): Promise<UpdateSnapshot> => ({ ...idle, phase: "ready", availableVersion: "0.3.0" })),
    cancel: vi.fn(async (): Promise<UpdateSnapshot> => ({ ...idle, phase: "cancelled" })),
    install: vi.fn(async () => undefined),
    subscribe: vi.fn(async () => () => undefined),
    ...overrides,
  };
}

describe("manual updater panel", () => {
  it("does no network operation until the user asks for a check", async () => {
    const updater = client();
    render(<UpdatePanel updater={updater} onPrepareInstall={vi.fn()} />);

    expect(updater.subscribe).toHaveBeenCalledOnce();
    expect(updater.status).toHaveBeenCalledOnce();
    expect(updater.check).not.toHaveBeenCalled();
    expect(updater.download).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Check for updates" }));
    await waitFor(() => expect(updater.check).toHaveBeenCalledOnce());
  });

  it("requires separate download and install consent and announces progress", async () => {
    let publish: (snapshot: UpdateSnapshot) => void = () => undefined;
    const updater = client({
      subscribe: vi.fn(async (listener) => {
        publish = listener;
        return () => undefined;
      }),
      check: vi.fn(async (): Promise<UpdateSnapshot> => ({
        ...idle,
        phase: "available",
        availableVersion: "0.3.0",
        notes: "Safer signed releases.",
      })),
    });
    const prepare = vi.fn(async () => undefined);
    render(<UpdatePanel updater={updater} onPrepareInstall={prepare} />);

    fireEvent.click(screen.getByRole("button", { name: "Check for updates" }));
    expect(await screen.findByText("Vault Brain v0.3.0 is available.")).toBeInTheDocument();
    expect(updater.download).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Download update" }));
    await waitFor(() => expect(updater.download).toHaveBeenCalledOnce());

    publish({
      ...idle,
      phase: "downloading",
      availableVersion: "0.3.0",
      downloadedBytes: 50,
      totalBytes: 100,
      canCancel: true,
    });
    expect(await screen.findByRole("progressbar", { name: "Update download progress" })).toHaveAttribute("value", "50");
    fireEvent.click(screen.getByRole("button", { name: "Cancel download" }));
    expect(await screen.findByText("Download cancelled.")).toBeInTheDocument();

    publish({ ...idle, phase: "ready", availableVersion: "0.3.0" });
    fireEvent.click(await screen.findByRole("button", { name: "Install and restart" }));
    const confirmation = screen.getByRole("group", { name: "Confirm update installation" });
    expect(updater.install).not.toHaveBeenCalled();
    fireEvent.click(within(confirmation).getByRole("button", { name: "Confirm install" }));
    await waitFor(() => expect(prepare).toHaveBeenCalledBefore(updater.install as ReturnType<typeof vi.fn>));
    expect(await screen.findByText("Restart required.")).toBeInTheDocument();
  });

  it("blocks native installation and preserves an actionable error when saving fails", async () => {
    const updater = client({
      check: vi.fn(async (): Promise<UpdateSnapshot> => ({ ...idle, phase: "ready", availableVersion: "0.3.0" })),
    });
    render(
      <UpdatePanel
        updater={updater}
        onPrepareInstall={vi.fn(async () => {
          throw new Error("Canvas save failed; edits remain open.");
        })}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Check for updates" }));
    fireEvent.click(await screen.findByRole("button", { name: "Install and restart" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm install" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Canvas save failed; edits remain open.");
    expect(updater.install).not.toHaveBeenCalled();
  });
});

describe("native updater adapter", () => {
  it("uses only the fixed native commands and normalizes the event payload", async () => {
    const calls: string[] = [];
    let nativeListener: ((event: { payload: NativeUpdateSnapshot }) => void) | undefined;
    const native: NativeUpdateSnapshot = {
      status: "downloaded",
      currentVersion: "0.2.0",
      version: "0.3.0",
      downloadedBytes: 42,
      totalBytes: 42,
      canCancel: false,
    };
    const invokeNative = async <T,>(command: string): Promise<T> => {
      calls.push(command);
      return native as T;
    };
    const listenNative = async <T,>(_event: string, listener: (event: { payload: T }) => void) => {
      nativeListener = listener as (event: { payload: NativeUpdateSnapshot }) => void;
      return () => undefined;
    };
    const adapter = createUpdaterClient(invokeNative, listenNative);
    const observed = vi.fn();
    await adapter.subscribe(observed);
    nativeListener?.({ payload: native });
    await adapter.status();
    await adapter.check();
    await adapter.download();
    await adapter.cancel();
    await adapter.install();

    expect(calls).toEqual(["update_status", "check_for_update", "download_update", "cancel_update", "install_update"]);
    expect(observed).toHaveBeenCalledWith(expect.objectContaining({ phase: "ready", availableVersion: "0.3.0" }));
  });
});

describe("installation save gate", () => {
  it("awaits note, canvas and vault lock in order", async () => {
    const order: string[] = [];
    await prepareUpdaterInstall(
      async () => {
        order.push("note");
        return true;
      },
      async () => {
        order.push("canvas");
      },
      async () => {
        order.push("lock");
      },
    );
    expect(order).toEqual(["note", "canvas", "lock"]);
  });

  it("does not lock when a canvas flush rejects", async () => {
    const lock = vi.fn(async () => undefined);
    await expect(
      prepareUpdaterInstall(
        async () => true,
        async () => {
          throw new Error("Canvas save failed.");
        },
        lock,
      ),
    ).rejects.toThrow("Canvas save failed.");
    expect(lock).not.toHaveBeenCalled();
  });
});
