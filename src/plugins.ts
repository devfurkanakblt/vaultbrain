/**
 * Plugin manifests and the capability model they are checked against.
 *
 * The point of this file is that a plugin's reach is *declared* and *finite*.
 * Obsidian's model — arbitrary Node inside the app process — is exactly what
 * this vault cannot offer: a plugin there can read the whole filesystem, and no
 * amount of encryption at rest survives that. Here a plugin gets a fixed list
 * of host methods, each behind a named capability the manifest had to ask for,
 * and the person installing it sees that list before it ever runs.
 *
 * Three layers, in order of how much they are trusted:
 *
 *  1. The manifest, checked here. It says what a plugin may ask for.
 *  2. The worker sandbox in the desktop app. It removes the ambient authority a
 *     script would otherwise have — DOM, network, module loading.
 *  3. The Rust command layer, which is the actual boundary and does not trust
 *     either of the first two. A plugin that escaped the worker entirely would
 *     still hold only the capabilities the webview itself has.
 *
 * Only layer 3 is a security boundary. Layers 1 and 2 are what make a plugin's
 * behaviour legible and bounded; they are not what keeps a hostile plugin away
 * from the key, because the key never enters the webview at all.
 */

export const PLUGIN_MANIFEST_VERSION = 1;

/**
 * This module is imported by both the Node core and the browser-side sandbox
 * host, so it stays free of Node-only APIs on purpose: a second copy of the
 * capability table is the one way this model could quietly drift out of
 * agreement with itself.
 */
function byteLength(text: string): number {
  return new TextEncoder().encode(text).length;
}

export const MAX_PLUGIN_SOURCE_BYTES = 2 * 1024 * 1024;
export const MAX_PLUGIN_STORAGE_BYTES = 256 * 1024;
export const MAX_PLUGINS = 100;

/**
 * The complete set. A capability is added here only alongside the host methods
 * it unlocks, so a new method cannot become reachable without one.
 */
export const PLUGIN_CAPABILITIES = [
  "notes:metadata",
  "notes:read",
  "notes:write",
  "search",
  "canvas:read",
  "canvas:write",
  "attachments:read",
  "commands",
  "ui:notice",
  "ui:panel",
  "storage",
] as const;

export type PluginCapability = (typeof PLUGIN_CAPABILITIES)[number];

/** What each capability lets a plugin do, in the words the installer sees. */
export const CAPABILITY_DESCRIPTIONS: Record<PluginCapability, string> = {
  "notes:metadata": "See note titles, paths, tags and properties — but not their text",
  "notes:read": "Read the full text of your notes",
  "notes:write": "Create and change notes",
  search: "Search your vault",
  "canvas:read": "Read your canvases",
  "canvas:write": "Create and change canvases",
  "attachments:read": "List attachments and read their decrypted bytes",
  commands: "Add entries to the command palette",
  "ui:notice": "Show you a short message",
  "ui:panel": "Add a panel of its own text beside a note",
  storage: "Keep its own settings, encrypted in your vault",
};

/**
 * The host methods a sandboxed plugin can call, and the capability each one
 * needs. This table is the enforcement point: the host looks a method up here
 * and refuses anything absent, so an unlisted method is unreachable rather than
 * merely undocumented.
 */
export const HOST_METHOD_CAPABILITIES = {
  "notes.list": "notes:metadata",
  "notes.metadata": "notes:metadata",
  "notes.read": "notes:read",
  "notes.create": "notes:write",
  "notes.update": "notes:write",
  "search.query": "search",
  "canvas.list": "canvas:read",
  "canvas.read": "canvas:read",
  "canvas.save": "canvas:write",
  "attachments.list": "attachments:read",
  "attachments.read": "attachments:read",
  "commands.register": "commands",
  "ui.notice": "ui:notice",
  "ui.panel": "ui:panel",
  "storage.get": "storage",
  "storage.set": "storage",
} as const satisfies Record<string, PluginCapability>;

export type HostMethod = keyof typeof HOST_METHOD_CAPABILITIES;

export interface PluginManifest {
  manifestVersion: 1;
  /** Stable identity. Lower-case, used as the storage namespace. */
  id: string;
  name: string;
  version: string;
  description: string;
  author: string;
  capabilities: PluginCapability[];
  /** `ed25519:<raw-public-key-base64url>:<signature-base64url>`. */
  signature?: string;
}

export interface PluginSignatureInfo {
  algorithm: "ed25519";
  /** SHA-256 of the raw public key, encoded as lower-case hex. */
  keyId: string;
}

export type PluginSignatureStatus = "unsigned" | "verified" | "revoked";

export interface PluginSecurityPolicy {
  version: 1;
  restrictedMode: boolean;
  revokedSigners: string[];
}

export interface PluginPackage {
  version: 1;
  /** Vault identity, distinct from the author-chosen `manifest.id`. */
  id: string;
  manifest: PluginManifest;
  source: string;
  /** Re-derived and checked whenever the encrypted package is opened. */
  signature?: PluginSignatureInfo;
  enabled: boolean;
  installedAt: string;
  updatedAt: string;
  revision: number;
}

/** The listing shape: identity, labels and reach — never the source. */
export interface PluginSummary {
  id: string;
  manifestId: string;
  name: string;
  version: string;
  description: string;
  author: string;
  capabilities: PluginCapability[];
  enabled: boolean;
  signatureStatus: PluginSignatureStatus;
  signer?: string;
  /** Kept for older API consumers; true means cryptographically verified. */
  signed: boolean;
  sourceBytes: number;
  updatedAt: string;
  revision: number;
}

const PLUGIN_ID = /^[a-z0-9][a-z0-9-]{1,63}$/u;
const SEMVER = /^\d{1,5}\.\d{1,5}\.\d{1,5}(?:-[0-9A-Za-z.-]{1,32})?$/u;
const CAPABILITY_SET = new Set<string>(PLUGIN_CAPABILITIES);

export function isPluginCapability(value: string): value is PluginCapability {
  return CAPABILITY_SET.has(value);
}

export function capabilityFor(method: string): PluginCapability | undefined {
  return Object.prototype.hasOwnProperty.call(HOST_METHOD_CAPABILITIES, method)
    ? HOST_METHOD_CAPABILITIES[method as HostMethod]
    : undefined;
}

/**
 * The single gate every call passes. An unknown method is refused rather than
 * allowed by omission, so adding a host method without listing it above fails
 * closed.
 */
export function permits(manifest: PluginManifest, method: string): boolean {
  const capability = capabilityFor(method);
  return capability !== undefined && manifest.capabilities.includes(capability);
}

function line(value: unknown, field: string, max: number): string {
  if (typeof value !== "string") throw new Error(`Plugin manifest ${field} must be a string.`);
  const text = value.trim();
  if (!text || text.length > max || /[\u0000-\u001f\u007f]/u.test(text)) {
    throw new Error(`Plugin manifest ${field} must be a single line of 1-${max} characters.`);
  }
  return text;
}

/**
 * Parses a manifest and refuses anything it does not fully understand: an
 * unknown capability is an error, not a field to skip, because skipping would
 * silently install a plugin whose reach this build cannot describe to the
 * person approving it.
 */
export function parsePluginManifest(input: unknown): PluginManifest {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("A plugin manifest must be a JSON object.");
  }
  const raw = input as Record<string, unknown>;
  if (raw.manifestVersion !== PLUGIN_MANIFEST_VERSION) {
    throw new Error(
      `Unsupported plugin manifest version: ${String(raw.manifestVersion)}. This build reads version ${PLUGIN_MANIFEST_VERSION}.`
    );
  }
  const id = line(raw.id, "id", 64).toLowerCase();
  if (!PLUGIN_ID.test(id)) {
    throw new Error(
      "Plugin id must be 2-64 lower-case letters, numbers or '-', starting with a letter or number."
    );
  }
  const version = line(raw.version, "version", 40);
  if (!SEMVER.test(version)) {
    throw new Error(`Plugin version must look like 1.2.3, got: ${version}`);
  }
  if (!Array.isArray(raw.capabilities)) {
    throw new Error("Plugin manifest capabilities must be an array.");
  }
  const capabilities: PluginCapability[] = [];
  for (const entry of raw.capabilities) {
    if (typeof entry !== "string" || !isPluginCapability(entry)) {
      throw new Error(
        `Unknown plugin capability: ${String(entry)}. This build grants: ${PLUGIN_CAPABILITIES.join(", ")}.`
      );
    }
    if (!capabilities.includes(entry)) capabilities.push(entry);
  }
  if (capabilities.length > PLUGIN_CAPABILITIES.length) {
    throw new Error("A plugin cannot request more capabilities than exist.");
  }
  const signature = raw.signature === undefined ? undefined : line(raw.signature, "signature", 512);
  return {
    manifestVersion: PLUGIN_MANIFEST_VERSION,
    id,
    name: line(raw.name, "name", 80),
    version,
    description: line(raw.description ?? "", "description", 240),
    author: line(raw.author ?? "unknown", "author", 80),
    capabilities,
    ...(signature ? { signature } : {}),
  };
}

/**
 * Source is stored as text and never evaluated here. The only checks that
 * belong at this layer are the ones the sandbox cannot make later: size, and
 * that it is text at all.
 */
export function validatePluginSource(source: unknown): string {
  if (typeof source !== "string" || !source.trim()) {
    throw new Error("A plugin needs non-empty source.");
  }
  const size = byteLength(source);
  if (size > MAX_PLUGIN_SOURCE_BYTES) {
    throw new Error(
      `Plugin source cannot exceed ${MAX_PLUGIN_SOURCE_BYTES / 1024} KiB (got ${Math.ceil(size / 1024)} KiB).`
    );
  }
  if (source.includes("\u0000")) throw new Error("Plugin source cannot contain a null byte.");
  return source;
}

export function summarizePlugin(
  plugin: PluginPackage,
  policy?: Pick<PluginSecurityPolicy, "revokedSigners">
): PluginSummary {
  const revoked = Boolean(
    plugin.signature && policy?.revokedSigners.includes(plugin.signature.keyId)
  );
  const signatureStatus: PluginSignatureStatus = revoked
    ? "revoked"
    : plugin.signature
      ? "verified"
      : "unsigned";
  return {
    id: plugin.id,
    manifestId: plugin.manifest.id,
    name: plugin.manifest.name,
    version: plugin.manifest.version,
    description: plugin.manifest.description,
    author: plugin.manifest.author,
    capabilities: plugin.manifest.capabilities,
    enabled: plugin.enabled,
    signatureStatus,
    ...(plugin.signature ? { signer: plugin.signature.keyId } : {}),
    signed: signatureStatus === "verified",
    sourceBytes: byteLength(plugin.source),
    updatedAt: plugin.updatedAt,
    revision: plugin.revision,
  };
}

/**
 * What to show someone before they say yes. Ordered most-reaching first, so the
 * line that matters is the line they read.
 */
export function describeCapabilities(capabilities: PluginCapability[]): string[] {
  const weight = (capability: PluginCapability) =>
    capability.endsWith(":write") ? 0 : capability.endsWith(":read") ? 1 : 2;
  return [...capabilities]
    .sort((left, right) => weight(left) - weight(right) || left.localeCompare(right))
    .map((capability) => CAPABILITY_DESCRIPTIONS[capability]);
}
