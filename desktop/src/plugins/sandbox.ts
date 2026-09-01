/**
 * The worker side of a plugin.
 *
 * This file is never imported by the running app. Its bootstrap is stringified,
 * concatenated with the plugin's own source, and handed to a Worker as a blob,
 * so the plugin runs in a realm that never had a DOM and never had the app's
 * module graph.
 *
 * Why concatenate instead of `eval` the source at runtime: the app ships a
 * strict content-security policy, and `'unsafe-eval'` would have to be granted
 * to the whole webview to evaluate a string — weakening every other page
 * surface to enable one feature. A blob worker is *loaded* as a script instead,
 * which needs only `worker-src blob:`. The plugin therefore runs without eval
 * ever being enabled anywhere.
 *
 * What this buys, honestly: a plugin cannot quietly exfiltrate a note over
 * `fetch`, cannot pull in a second script at runtime, and cannot touch the
 * document. What it does not buy: protection from a plugin abusing what it was
 * granted. `notes:read` means the plugin reads your notes. The defence there is
 * the manifest the installer approved, not the sandbox.
 */

/**
 * The bootstrap plus one plugin, as a single worker script.
 *
 * The plugin body is wrapped in its own function, so the bootstrap's internals
 * — the pending-call map, the posting helper — stay inside a closure the plugin
 * has no name for. All it can reach is the frozen bridge left on `self`.
 */
export function sandboxSource(pluginSource: string): string {
  return [`(${bootstrap.toString()})();`, ";(function (vbrain) {", pluginSource, "\n})(self.__vbrainBridge);"].join(
    "\n",
  );
}

function bootstrap() {
  const scope = self as unknown as Record<string, unknown>;

  // Ambient authority a worker would otherwise have. Removing it is not a
  // guarantee against a determined escape — it is the difference between a
  // plugin that cannot reach the network and one that merely should not.
  for (const name of [
    "fetch",
    "XMLHttpRequest",
    "WebSocket",
    "EventSource",
    "importScripts",
    "indexedDB",
    "caches",
    "Notification",
    "SharedWorker",
    "Worker",
    "BroadcastChannel",
  ]) {
    try {
      delete scope[name];
      Object.defineProperty(scope, name, {
        configurable: false,
        enumerable: false,
        get() {
          throw new Error(`${name} is not available to plugins. Ask for a capability instead.`);
        },
      });
    } catch {
      // A global that refuses to be replaced is reported rather than silently
      // tolerated, so the host can decide what to do about a partial sandbox.
      scope.__vbrainSandboxIncomplete = true;
    }
  }

  let nextId = 1;
  const pending = new Map<number, { resolve: (value: unknown) => void; reject: (error: Error) => void }>();
  const commands = new Map<string, () => unknown>();

  const port = self as unknown as {
    postMessage: (message: unknown) => void;
    addEventListener: (type: string, handler: (event: unknown) => void) => void;
  };

  function call(method: string, params?: unknown): Promise<unknown> {
    const id = nextId++;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      port.postMessage({ kind: "request", id, method, params });
    });
  }

  function report(error: unknown) {
    port.postMessage({
      kind: "emit",
      event: "log",
      payload: error instanceof Error ? error.message : String(error),
    });
  }

  // The whole plugin API. Every method is a message; none is a live handle to
  // anything on the host side, so nothing here can be walked back into the app.
  const bridge = {
    notes: {
      list: () => call("notes.list"),
      metadata: (reference: string) => call("notes.metadata", { reference }),
      read: (reference: string) => call("notes.read", { reference }),
      create: (path: string, title: string) => call("notes.create", { path, title }),
      update: (reference: string, body: string) => call("notes.update", { reference, body }),
    },
    search: {
      query: (text: string) => call("search.query", { query: text }),
    },
    canvas: {
      list: () => call("canvas.list"),
      read: (reference: string) => call("canvas.read", { reference }),
      save: (input: unknown) => call("canvas.save", { input }),
    },
    attachments: {
      list: () => call("attachments.list"),
      read: (id: string) => call("attachments.read", { id }),
    },
    commands: {
      register: (id: string, label: string, run: () => unknown) => {
        commands.set(id, run);
        return call("commands.register", { id, label });
      },
    },
    ui: {
      notice: (message: string) => call("ui.notice", { message }),
      panel: (title: string, body: string) => call("ui.panel", { title, body }),
    },
    storage: {
      get: (key: string) => call("storage.get", { key }),
      set: (key: string, value: string) => call("storage.set", { key, value }),
    },
  };

  for (const group of Object.values(bridge)) Object.freeze(group);
  Object.freeze(bridge);
  Object.defineProperty(scope, "__vbrainBridge", {
    configurable: false,
    writable: false,
    enumerable: false,
    value: bridge,
  });

  port.addEventListener("message", (rawEvent: unknown) => {
    const message = (rawEvent as { data?: Record<string, unknown> }).data;
    if (!message || typeof message !== "object") return;

    if (message.kind === "reply") {
      const waiting = pending.get(message.id as number);
      if (!waiting) return;
      pending.delete(message.id as number);
      if (message.ok) waiting.resolve(message.value);
      else waiting.reject(new Error(String(message.error ?? "The host refused that call.")));
      return;
    }

    if (message.kind === "invoke") {
      const run = commands.get(String(message.command));
      if (!run) return;
      try {
        Promise.resolve(run()).catch(report);
      } catch (error) {
        report(error);
      }
    }
  });

  // Sent after the plugin body below has finished its top-level work, so the
  // host learns "ready" only once the plugin has had a chance to register.
  Promise.resolve().then(() =>
    port.postMessage({
      kind: "emit",
      event: "ready",
      payload: { sandboxIncomplete: scope.__vbrainSandboxIncomplete === true },
    }),
  );
}
