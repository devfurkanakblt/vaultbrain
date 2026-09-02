import { capabilityFor, isPluginCapability, permits, type PluginCapability, type PluginManifest } from "./manifest";
import type { PluginSummary } from "../types";
import { sandboxSource } from "./sandbox";
import type {
  HostToPlugin,
  PluginPanel,
  PluginRuntimeState,
  PluginToHost,
  RegisteredCommand,
} from "./protocol";

/**
 * The host half of the plugin runtime.
 *
 * Every message from a worker passes through `handle`, which looks the method
 * up in the shared capability table and refuses anything the plugin's manifest
 * did not ask for. An unknown method is refused too, so a host method added
 * without a capability entry is unreachable rather than accidentally public.
 *
 * The worker is not the security boundary — the Rust command layer is, and it
 * does not trust this file. What this layer provides is a plugin whose reach is
 * the list the person approved, and which can be stopped.
 */

/** Beyond this, a plugin is stopped rather than allowed to spin. */
const CALL_BUDGET_PER_MINUTE = 600;
const READY_TIMEOUT_MS = 5_000;
const HEARTBEAT_INTERVAL_MS = 2_000;
const HEARTBEAT_TIMEOUT_MS = 6_000;
const MAX_PANEL_BYTES = 16 * 1024;
const MAX_COMMANDS = 25;

/**
 * A summary arrives over IPC, so its capability strings are input, not a type.
 * Narrowing here means a name this build does not know can never become an
 * allowed one — it is dropped, and the plugin runs with less rather than more.
 */
function grantedCapabilities(summary: PluginSummary): PluginCapability[] {
  return summary.capabilities.filter(isPluginCapability);
}

function manifestOf(summary: PluginSummary): PluginManifest {
  return {
    manifestVersion: 1,
    id: summary.manifestId,
    name: summary.name,
    version: summary.version,
    description: summary.description,
    author: summary.author,
    capabilities: grantedCapabilities(summary),
  };
}

export interface PluginHostBindings {
  authorize: (pluginId: string, revision: number) => Promise<{ instanceToken: string }>;
  /** Every host method a plugin may reach, keyed exactly as the table names it. */
  call: (
    context: { pluginId: string; instanceToken: string; revision: number },
    method: string,
    params: Record<string, unknown>
  ) => Promise<unknown>;
  onNotice: (pluginName: string, message: string) => void;
  onCommandsChanged: (commands: RegisteredCommand[]) => void;
  onPanelsChanged: (panels: PluginPanel[]) => void;
  onStateChanged: (states: PluginRuntimeState[]) => void;
  /**
   * Overridden only by tests. The default is the blob worker; a seam here lets
   * the enforcement path be exercised without a real Worker, which is the part
   * that most needs testing.
   */
  createWorker?: (script: string) => { worker: Worker; objectUrl: string };
}

function blobWorker(script: string) {
  const objectUrl = URL.createObjectURL(new Blob([script], { type: "text/javascript" }));
  return { worker: new Worker(objectUrl), objectUrl };
}

interface RunningPlugin {
  summary: PluginSummary;
  manifest: PluginManifest;
  worker: Worker;
  objectUrl: string;
  state: PluginRuntimeState;
  callsThisMinute: number;
  windowStartedAt: number;
  readyTimer: number;
  heartbeatTimer: number;
  lastHeartbeatAt: number;
  instanceToken: string;
  inFlight: number;
}

export class PluginHost {
  private readonly running = new Map<string, RunningPlugin>();
  private commands: RegisteredCommand[] = [];
  private panels: PluginPanel[] = [];

  constructor(private readonly bindings: PluginHostBindings) {}

  states(): PluginRuntimeState[] {
    return [...this.running.values()].map((plugin) => plugin.state);
  }

  /**
   * Starts exactly the enabled set and stops everything else, so enabling,
   * disabling, updating and uninstalling all funnel through one path.
   */
  async sync(plugins: Array<{ summary: PluginSummary; source: string }>): Promise<void> {
    const wanted = new Map(plugins.filter((entry) => entry.summary.enabled).map((entry) => [entry.summary.id, entry]));
    for (const id of [...this.running.keys()]) {
      const next = wanted.get(id);
      const current = this.running.get(id);
      // A revision bump means the code changed, so the old worker is retired
      // rather than left running the version that is no longer installed.
      if (!next || (current && next.summary.revision !== current.summary.revision)) this.stop(id);
    }
    for (const [id, entry] of wanted) {
      if (!this.running.has(id)) await this.start(entry.summary, entry.source);
    }
    this.publishState();
  }

  stopAll(): void {
    for (const id of [...this.running.keys()]) this.stop(id);
    this.commands = [];
    this.panels = [];
    this.bindings.onCommandsChanged([]);
    this.bindings.onPanelsChanged([]);
    this.publishState();
  }

  invoke(command: RegisteredCommand): void {
    const plugin = this.running.get(command.pluginId);
    if (!plugin || plugin.state.status !== "ready") return;
    this.post(plugin, { kind: "invoke", command: command.id });
  }

  private async start(summary: PluginSummary, source: string): Promise<void> {
    const manifest = manifestOf(summary);
    try {
      const authorization = await this.bindings.authorize(summary.id, summary.revision);
      const spawn = this.bindings.createWorker ?? blobWorker;
      const { worker, objectUrl } = spawn(sandboxSource(source));
      const plugin: RunningPlugin = {
        summary,
        manifest,
        worker,
        objectUrl,
        state: {
          id: summary.id,
          name: summary.name,
          capabilities: manifest.capabilities,
          status: "starting",
        },
        callsThisMinute: 0,
        windowStartedAt: Date.now(),
        readyTimer: window.setTimeout(() => {
          this.fail(summary.id, "The plugin did not finish loading in time.");
        }, READY_TIMEOUT_MS),
        heartbeatTimer: 0,
        lastHeartbeatAt: Date.now(),
        instanceToken: authorization.instanceToken,
        inFlight: 0,
      };
      worker.addEventListener("message", (event: MessageEvent<PluginToHost>) => {
        void this.handle(plugin, event.data);
      });
      worker.addEventListener("error", (event) => {
        this.fail(summary.id, event.message || "The plugin crashed while loading.");
      });
      this.running.set(summary.id, plugin);
      plugin.heartbeatTimer = window.setInterval(() => {
        if (Date.now() - plugin.lastHeartbeatAt > HEARTBEAT_TIMEOUT_MS) {
          this.fail(summary.id, "The plugin stopped responding to runtime heartbeats.");
          return;
        }
        this.post(plugin, { kind: "ping", nonce: Date.now() });
      }, HEARTBEAT_INTERVAL_MS);
    } catch (error) {
      this.running.set(summary.id, {
        summary,
        manifest,
        worker: undefined as unknown as Worker,
        objectUrl: "",
        state: {
          id: summary.id,
          name: summary.name,
          capabilities: manifest.capabilities,
          status: "failed",
          error: error instanceof Error ? error.message : String(error),
        },
        callsThisMinute: 0,
        windowStartedAt: Date.now(),
        readyTimer: 0,
        heartbeatTimer: 0,
        lastHeartbeatAt: Date.now(),
        instanceToken: "",
        inFlight: 0,
      });
    }
  }

  private stop(id: string): void {
    const plugin = this.running.get(id);
    if (!plugin) return;
    window.clearTimeout(plugin.readyTimer);
    window.clearInterval(plugin.heartbeatTimer);
    plugin.worker?.terminate();
    if (plugin.objectUrl.startsWith("blob:")) URL.revokeObjectURL(plugin.objectUrl);
    this.running.delete(id);
    this.dropContributions(id);
  }

  private fail(id: string, message: string): void {
    const plugin = this.running.get(id);
    if (!plugin) return;
    window.clearTimeout(plugin.readyTimer);
    window.clearInterval(plugin.heartbeatTimer);
    plugin.worker?.terminate();
    if (plugin.objectUrl.startsWith("blob:")) URL.revokeObjectURL(plugin.objectUrl);
    plugin.state = { ...plugin.state, status: "failed", error: message };
    this.dropContributions(id);
    this.publishState();
  }

  private dropContributions(id: string): void {
    const commands = this.commands.filter((command) => command.pluginId !== id);
    const panels = this.panels.filter((panel) => panel.pluginId !== id);
    if (commands.length !== this.commands.length) {
      this.commands = commands;
      this.bindings.onCommandsChanged(commands);
    }
    if (panels.length !== this.panels.length) {
      this.panels = panels;
      this.bindings.onPanelsChanged(panels);
    }
  }

  private publishState(): void {
    this.bindings.onStateChanged(this.states());
  }

  private post(plugin: RunningPlugin, message: HostToPlugin): void {
    plugin.worker?.postMessage(message);
  }

  /** A plugin that will not stop calling is stopped, not throttled silently. */
  private withinBudget(plugin: RunningPlugin): boolean {
    const now = Date.now();
    if (now - plugin.windowStartedAt > 60_000) {
      plugin.windowStartedAt = now;
      plugin.callsThisMinute = 0;
    }
    plugin.callsThisMinute += 1;
    return plugin.callsThisMinute <= CALL_BUDGET_PER_MINUTE;
  }

  private async handle(plugin: RunningPlugin, message: PluginToHost): Promise<void> {
    if (!message || typeof message !== "object") return;

    if (message.kind === "emit") {
      if (message.event === "heartbeat") {
        plugin.lastHeartbeatAt = Date.now();
        return;
      }
      if (message.event === "ready") {
        window.clearTimeout(plugin.readyTimer);
        plugin.lastHeartbeatAt = Date.now();
        const payload = message.payload as { sandboxIncomplete?: boolean } | null;
        if (payload?.sandboxIncomplete) {
          this.fail(plugin.summary.id, "This device could not fully isolate the plugin sandbox.");
          return;
        }
        plugin.state = { ...plugin.state, status: "ready" };
        this.publishState();
      }
      if (message.event === "log") {
        plugin.state = { ...plugin.state, error: String(message.payload) };
        this.publishState();
      }
      return;
    }

    if (message.kind !== "request") return;

    let requestBytes: number;
    try {
      requestBytes = new TextEncoder().encode(JSON.stringify(message)).length;
    } catch {
      this.fail(plugin.summary.id, "The plugin sent an unserializable request.");
      return;
    }
    if (requestBytes > 64 * 1024) {
      this.fail(plugin.summary.id, "The plugin exceeded the 64 KiB request limit.");
      return;
    }
    if (plugin.inFlight >= 4) {
      this.fail(plugin.summary.id, "The plugin exceeded the 4-call concurrency limit.");
      return;
    }

    if (!this.withinBudget(plugin)) {
      this.fail(plugin.summary.id, "The plugin was stopped for making too many calls.");
      return;
    }

    const params = (message.params ?? {}) as Record<string, unknown>;
    plugin.inFlight += 1;
    try {
      // One gate, consulted before anything else looks at the method: an
      // unknown method has no capability and is therefore refused.
      if (!capabilityFor(message.method)) {
        throw new Error(`Unknown plugin method: ${message.method}`);
      }
      if (!permits(plugin.manifest, message.method)) {
        throw new Error(
          `"${plugin.summary.name}" did not ask for the ${capabilityFor(message.method)} capability.`
        );
      }
      const value = await this.dispatch(plugin, message.method, params);
      if (new TextEncoder().encode(JSON.stringify(value ?? null)).length > 4 * 1024 * 1024) {
        throw new Error("The plugin response exceeded the 4 MiB limit.");
      }
      this.post(plugin, { kind: "reply", id: message.id, ok: true, value });
    } catch (error) {
      this.post(plugin, {
        kind: "reply",
        id: message.id,
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      });
    } finally {
      plugin.inFlight -= 1;
    }
  }

  private async dispatch(
    plugin: RunningPlugin,
    method: string,
    params: Record<string, unknown>
  ): Promise<unknown> {
    if (method === "ui.notice") {
      this.bindings.onNotice(plugin.summary.name, String(params.message ?? "").slice(0, 400));
      return null;
    }
    if (method === "ui.panel") {
      const body = String(params.body ?? "");
      if (body.length > MAX_PANEL_BYTES) throw new Error("A plugin panel cannot exceed 16 KiB.");
      // Stored and rendered as text, never as markup: a plugin contributes
      // words to the interface, not nodes.
      this.panels = [
        ...this.panels.filter((panel) => panel.pluginId !== plugin.summary.id),
        {
          pluginId: plugin.summary.id,
          pluginName: plugin.summary.name,
          title: String(params.title ?? plugin.summary.name).slice(0, 80),
          body,
        },
      ];
      this.bindings.onPanelsChanged(this.panels);
      return null;
    }
    if (method === "commands.register") {
      const mine = this.commands.filter((command) => command.pluginId === plugin.summary.id);
      if (mine.length >= MAX_COMMANDS) throw new Error("A plugin may register at most 25 commands.");
      const id = String(params.id ?? "").slice(0, 80);
      if (!id) throw new Error("A command needs an id.");
      this.commands = [
        ...this.commands.filter(
          (command) => !(command.pluginId === plugin.summary.id && command.id === id)
        ),
        {
          pluginId: plugin.summary.id,
          pluginName: plugin.summary.name,
          id,
          label: String(params.label ?? id).slice(0, 120),
        },
      ];
      this.bindings.onCommandsChanged(this.commands);
      return null;
    }
    if (method === "storage.get" || method === "storage.set") {
      return this.callPrivileged(plugin, method, params);
    }
    return this.callPrivileged(plugin, method, params);
  }

  private async callPrivileged(
    plugin: RunningPlugin,
    method: string,
    params: Record<string, unknown>
  ): Promise<unknown> {
    const call = this.bindings.call(
      {
        pluginId: plugin.summary.id,
        instanceToken: plugin.instanceToken,
        revision: plugin.summary.revision,
      },
      method,
      params
    );
    let timeout = 0;
    try {
      return await Promise.race([
        call,
        new Promise<never>((_resolve, reject) => {
          timeout = window.setTimeout(
            () => reject(new Error("The plugin call exceeded its 10 second deadline.")),
            10_000
          );
        }),
      ]);
    } finally {
      window.clearTimeout(timeout);
    }
  }
}
