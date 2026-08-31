/**
 * The desktop side deliberately re-exports the core's capability model instead
 * of restating it. A plugin's reach is decided in exactly one table, and a
 * second copy of that table — drifting by one entry — is precisely the bug this
 * layer cannot afford.
 */
export {
  CAPABILITY_DESCRIPTIONS,
  HOST_METHOD_CAPABILITIES,
  MAX_PLUGIN_SOURCE_BYTES,
  PLUGIN_CAPABILITIES,
  capabilityFor,
  describeCapabilities,
  isPluginCapability,
  parsePluginManifest,
  permits,
  validatePluginSource,
} from "../../../src/plugins";

export type {
  HostMethod,
  PluginCapability,
  PluginManifest,
  PluginPackage,
  PluginSummary,
} from "../../../src/plugins";
