import type { PluginCapability, PluginManifest } from "./manifest";

/**
 * The only vocabulary that crosses the sandbox boundary.
 *
 * Everything here is structured-cloneable data. No function, no proxy and no
 * object with behaviour is ever handed across, so a plugin cannot reach the
 * host's scope by holding on to something it was given.
 */

export interface PluginRequest {
  kind: "request";
  /** Correlates a reply with its call; the host echoes it back untouched. */
  id: number;
  method: string;
  params: unknown;
}

export interface PluginEmit {
  kind: "emit";
  event: "ready" | "command" | "log" | "heartbeat";
  payload: unknown;
}

export type PluginToHost = PluginRequest | PluginEmit;

export interface HostReply {
  kind: "reply";
  id: number;
  ok: boolean;
  value?: unknown;
  error?: string;
}

export interface HostInvoke {
  kind: "invoke";
  /** A command the plugin registered, fired from the palette. */
  command: string;
}

export interface HostBoot {
  kind: "boot";
  manifest: PluginManifest;
  source: string;
}

export interface HostPing {
  kind: "ping";
  nonce: number;
}

export type HostToPlugin = HostReply | HostInvoke | HostBoot | HostPing;

export interface RegisteredCommand {
  pluginId: string;
  pluginName: string;
  id: string;
  label: string;
}

export interface PluginPanel {
  pluginId: string;
  pluginName: string;
  title: string;
  body: string;
}

export interface PluginRuntimeState {
  id: string;
  name: string;
  capabilities: PluginCapability[];
  status: "starting" | "ready" | "failed" | "stopped";
  error?: string;
}
