import { describe, expect, it, vi } from "vitest";
import { PluginHost } from "./host";
import { sandboxSource } from "./sandbox";
import type { PluginSummary } from "../types";

/**
 * A stand-in for the worker. The real one runs the plugin; what matters here is
 * the host's side of the conversation — which calls it serves, which it
 * refuses, and when it gives up on a plugin.
 */
class FakeWorker {
  readonly sent: unknown[] = [];
  private handlers: Array<(event: { data: unknown }) => void> = [];
  terminated = false;

  addEventListener(type: string, handler: (event: never) => void) {
    if (type === "message") this.handlers.push(handler as (event: { data: unknown }) => void);
  }

  postMessage(message: unknown) {
    this.sent.push(message);
  }

  terminate() {
    this.terminated = true;
  }

  /** Pretend the plugin sent something to the host. */
  emit(data: unknown) {
    for (const handler of this.handlers) handler({ data });
  }

  lastReply() {
    return this.sent.filter((message) => (message as { kind: string }).kind === "reply").at(-1) as
      { ok: boolean; error?: string; value?: unknown } | undefined;
  }
}

function summary(overrides: Partial<PluginSummary> = {}): PluginSummary {
  return {
    id: "5c1a7e90-88fd-4f2b-9f0c-2a4e6b8d1c33",
    manifestId: "word-count",
    name: "Word count",
    version: "1.0.0",
    description: "",
    author: "someone",
    capabilities: ["notes:read"],
    enabled: true,
    signatureStatus: "unsigned",
    signed: false,
    sourceBytes: 12,
    updatedAt: "2026-08-31T08:00:00.000Z",
    revision: 1,
    ...overrides,
  };
}

function harness(overrides: Partial<PluginSummary> = {}) {
  const worker = new FakeWorker();
  const call = vi.fn(async () => "served");
  const onNotice = vi.fn();
  const onCommandsChanged = vi.fn();
  const onPanelsChanged = vi.fn();
  const onStateChanged = vi.fn();
  const host = new PluginHost({
    call,
    onNotice,
    onCommandsChanged,
    onPanelsChanged,
    onStateChanged,
    createWorker: () => ({ worker: worker as unknown as Worker, objectUrl: "test:worker" }),
  });
  return {
    host,
    worker,
    call,
    onNotice,
    onCommandsChanged,
    onPanelsChanged,
    onStateChanged,
    summary: summary(overrides),
  };
}

async function request(worker: FakeWorker, method: string, params: Record<string, unknown> = {}) {
  worker.emit({ kind: "request", id: 1, method, params });
  await new Promise((resolve) => setTimeout(resolve, 0));
  return worker.lastReply();
}

describe("plugin host", () => {
  it("serves a call the manifest asked for", async () => {
    const { host, worker, call, summary: installed } = harness();
    await host.sync([{ summary: installed, source: "// noop" }]);

    const reply = await request(worker, "notes.read", { reference: "note-1" });

    expect(call).toHaveBeenCalledWith("notes.read", { reference: "note-1" });
    expect(reply).toMatchObject({ ok: true, value: "served" });
  });

  it("refuses a call the manifest did not ask for, without reaching the app", async () => {
    const { host, worker, call, summary: installed } = harness({ capabilities: ["notes:read"] });
    await host.sync([{ summary: installed, source: "// noop" }]);

    const reply = await request(worker, "notes.update", { reference: "note-1", body: "rewritten" });

    expect(call).not.toHaveBeenCalled();
    expect(reply?.ok).toBe(false);
    expect(reply?.error).toMatch(/did not ask for the notes:write capability/u);
  });

  it("refuses a method that is not in the capability table at all", async () => {
    const {
      host,
      worker,
      call,
      summary: installed,
    } = harness({
      capabilities: ["notes:read", "notes:write", "storage", "commands", "ui:notice", "ui:panel"],
    });
    await host.sync([{ summary: installed, source: "// noop" }]);

    const reply = await request(worker, "vault.exportEverything");

    expect(call).not.toHaveBeenCalled();
    expect(reply?.error).toMatch(/Unknown plugin method/u);
  });

  it("drops a capability name this build does not know rather than honouring it", async () => {
    const {
      host,
      worker,
      call,
      summary: installed,
    } = harness({
      capabilities: ["notes:read", "network:all"],
    });
    await host.sync([{ summary: installed, source: "// noop" }]);

    expect(host.states()[0].capabilities).toEqual(["notes:read"]);
    const reply = await request(worker, "notes.update", { reference: "n", body: "x" });
    expect(call).not.toHaveBeenCalled();
    expect(reply?.ok).toBe(false);
  });

  it("scopes a storage call to the calling plugin", async () => {
    const { host, worker, call, summary: installed } = harness({ capabilities: ["storage"] });
    await host.sync([{ summary: installed, source: "// noop" }]);

    await request(worker, "storage.get", { key: "lastRun" });

    expect(call).toHaveBeenCalledWith("storage.get", { key: "lastRun", pluginId: installed.id });
  });

  it("stops a plugin that will not stop calling", async () => {
    const { host, worker, summary: installed } = harness();
    await host.sync([{ summary: installed, source: "// noop" }]);

    for (let index = 0; index < 601; index += 1) {
      worker.emit({ kind: "request", id: index, method: "notes.read", params: {} });
    }
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(worker.terminated).toBe(true);
    expect(host.states()[0]).toMatchObject({ status: "failed" });
    expect(host.states()[0].error).toMatch(/too many calls/u);
  });

  it("refuses to run a plugin whose sandbox could not be fully isolated", async () => {
    const { host, worker, summary: installed } = harness();
    await host.sync([{ summary: installed, source: "// noop" }]);

    worker.emit({ kind: "emit", event: "ready", payload: { sandboxIncomplete: true } });

    expect(worker.terminated).toBe(true);
    expect(host.states()[0]).toMatchObject({ status: "failed" });
  });

  it("takes a plugin's commands and panels away when it is disabled", async () => {
    const {
      host,
      worker,
      onCommandsChanged,
      onPanelsChanged,
      summary: installed,
    } = harness({
      capabilities: ["commands", "ui:panel"],
    });
    await host.sync([{ summary: installed, source: "// noop" }]);
    await request(worker, "commands.register", { id: "count", label: "Count words" });
    await request(worker, "ui.panel", { title: "Words", body: "12" });

    expect(onCommandsChanged).toHaveBeenLastCalledWith([
      { pluginId: installed.id, pluginName: "Word count", id: "count", label: "Count words" },
    ]);

    await host.sync([{ summary: { ...installed, enabled: false }, source: "" }]);

    expect(worker.terminated).toBe(true);
    expect(onCommandsChanged).toHaveBeenLastCalledWith([]);
    expect(onPanelsChanged).toHaveBeenLastCalledWith([]);
  });

  it("retires the old worker when a plugin's code changes", async () => {
    const workers: FakeWorker[] = [];
    const host = new PluginHost({
      call: vi.fn(async () => null),
      onNotice: vi.fn(),
      onCommandsChanged: vi.fn(),
      onPanelsChanged: vi.fn(),
      onStateChanged: vi.fn(),
      createWorker: () => {
        const worker = new FakeWorker();
        workers.push(worker);
        return { worker: worker as unknown as Worker, objectUrl: "test:worker" };
      },
    });
    const installed = summary();

    await host.sync([{ summary: installed, source: "// v1" }]);
    await host.sync([{ summary: { ...installed, revision: 2 }, source: "// v2" }]);

    expect(workers).toHaveLength(2);
    expect(workers[0].terminated).toBe(true);
    expect(workers[1].terminated).toBe(false);
  });
});

describe("sandbox source", () => {
  it("wraps the plugin so the bootstrap's internals are out of reach", () => {
    const script = sandboxSource("vbrain.ui.notice('hello');");

    expect(script).toContain("(function (vbrain) {");
    expect(script).toContain("vbrain.ui.notice('hello');");
    expect(script).toContain("self.__vbrainBridge");
  });

  it("removes the globals a plugin could otherwise reach the network with", () => {
    const script = sandboxSource("// noop");

    for (const global of ["fetch", "XMLHttpRequest", "WebSocket", "importScripts", "indexedDB"]) {
      expect(script).toContain(`"${global}"`);
    }
    // No eval anywhere: the plugin is loaded as a worker script instead, so the
    // app never has to grant 'unsafe-eval'.
    expect(script).not.toMatch(/\beval\s*\(/u);
  });
});
