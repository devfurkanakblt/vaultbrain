import { useRef, useState } from "react";
import { AlertTriangle, Ban, CircleDot, KeyRound, LockKeyhole, Puzzle, ShieldCheck, Trash2, Upload } from "lucide-react";
import { describeCapabilities, isPluginCapability, parsePluginManifest, type PluginCapability } from "./plugins/manifest";
import type { PluginRuntimeState } from "./plugins/protocol";
import type { PluginSecurityPolicy, PluginSummary } from "./types";

interface PluginManagerProps {
  plugins: PluginSummary[];
  policy: PluginSecurityPolicy;
  states: PluginRuntimeState[];
  onInstall: (manifest: unknown, source: string) => Promise<void>;
  onToggle: (id: string, enabled: boolean) => Promise<void>;
  onRemove: (plugin: PluginSummary) => Promise<void>;
  onRestricted: (enabled: boolean) => Promise<void>;
  onRevoke: (plugin: PluginSummary) => Promise<void>;
  onRestore: (keyId: string) => Promise<void>;
  onNotice: (message: string) => void;
}

function readableBytes(bytes: number) {
  return bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KiB`;
}

export function PluginManager({ plugins, policy, states, onInstall, onToggle, onRemove, onRestricted, onRevoke, onRestore, onNotice }: PluginManagerProps) {
  const manifestInput = useRef<HTMLInputElement>(null);
  const [pending, setPending] = useState<{ manifest: unknown; source: string; capabilities: PluginCapability[]; name: string }>();
  const [busy, setBusy] = useState(false);

  const stateOf = (id: string) => states.find((state) => state.id === id);

  /**
   * A plugin is chosen as its manifest plus its code in one step. Approving a
   * manifest that could later be paired with different code would make the
   * capability list meaningless.
   */
  async function choose(files: FileList | null) {
    if (!files?.length) return;
    try {
      const manifestFile = [...files].find((file) => file.name.endsWith(".json"));
      const sourceFile = [...files].find((file) => file.name.endsWith(".js"));
      if (!manifestFile || !sourceFile) {
        throw new Error("Choose both the plugin's manifest (.json) and its source (.js).");
      }
      const manifest = parsePluginManifest(JSON.parse(await manifestFile.text()));
      setPending({
        manifest,
        source: await sourceFile.text(),
        capabilities: manifest.capabilities,
        name: manifest.name,
      });
    } catch (error) {
      onNotice(error instanceof Error ? error.message : String(error));
    } finally {
      if (manifestInput.current) manifestInput.current.value = "";
    }
  }

  async function confirmInstall() {
    if (!pending) return;
    setBusy(true);
    try {
      await onInstall(pending.manifest, pending.source);
      setPending(undefined);
    } catch (error) {
      onNotice(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  }

  return <section className="plugin-view" aria-label="Plugins">
    <header className="plugin-header">
      <div>
        <p className="eyebrow">SANDBOXED EXTENSIONS</p>
        <h2>Plugins</h2>
        <span>Each plugin runs in an isolated worker with no network and no filesystem, and reaches only what its manifest declared.</span>
      </div>
      <button className="plugin-install" onClick={() => manifestInput.current?.click()} disabled={busy}>
        <Upload size={16} /> Install from files
      </button>
      <input ref={manifestInput} type="file" multiple accept=".json,.js" hidden onChange={(event) => void choose(event.target.files)} />
    </header>

    <section className="plugin-policy" aria-label="Plugin security policy">
      <div><LockKeyhole size={16} /><span><b>Restricted mode</b><small>Only verified Ed25519 packages can be installed or run.</small></span></div>
      <label className="plugin-toggle">
        <input aria-label="Restricted mode" type="checkbox" checked={policy.restrictedMode} onChange={(event) => void onRestricted(event.target.checked)} />
        <span>{policy.restrictedMode ? "On" : "Off"}</span>
      </label>
    </section>

    {plugins.length ? <div className="plugin-list">{plugins.map((plugin) => {
      const state = stateOf(plugin.id);
      return <article className="plugin-card" key={plugin.id}>
        <div className="plugin-title">
          <Puzzle size={17} />
          <div>
            <b>{plugin.name}</b>
            <small>v{plugin.version} · {plugin.author} · {readableBytes(plugin.sourceBytes)}</small>
            <span className={`plugin-signature ${plugin.signatureStatus}`}>
              {plugin.signatureStatus === "verified" ? <><KeyRound size={11} /> verified signer</>
                : plugin.signatureStatus === "revoked" ? <><Ban size={11} /> signer revoked</>
                : <><AlertTriangle size={11} /> unsigned</>}
            </span>
          </div>
          <label className="plugin-toggle">
            <input
              type="checkbox"
              checked={plugin.enabled}
              onChange={(event) => void onToggle(plugin.id, event.target.checked)}
              aria-label={`Enable ${plugin.name}`}
            />
            <span>{plugin.enabled ? "On" : "Off"}</span>
          </label>
        </div>
        {plugin.description && <p className="plugin-description">{plugin.description}</p>}
        <ul className="plugin-capabilities">
          {describeCapabilities(plugin.capabilities.filter(isPluginCapability)).map((line) => (
            <li key={line}><ShieldCheck size={12} />{line}</li>
          ))}
          {!plugin.capabilities.length && <li><ShieldCheck size={12} />Asks for nothing at all</li>}
        </ul>
        <footer>
          <span className={`plugin-status ${state?.status ?? "stopped"}`}>
            {state?.status === "ready" ? <><CircleDot size={11} /> running</>
              : state?.status === "starting" ? <><CircleDot size={11} className="spin" /> starting</>
              : state?.status === "failed" ? <><AlertTriangle size={11} /> {state.error ?? "failed"}</>
              : "not running"}
          </span>
          <div>
            {plugin.signatureStatus === "verified" && <button onClick={() => void onRevoke(plugin)} title={`Revoke ${plugin.name}'s signer`}><Ban size={13} /> Revoke signer</button>}
            {plugin.signatureStatus === "revoked" && plugin.signer && <button onClick={() => void onRestore(plugin.signer!)}><KeyRound size={13} /> Restore signer</button>}
            <button onClick={() => void onRemove(plugin)} title={`Remove ${plugin.name}`}><Trash2 size={13} /> Remove</button>
          </div>
        </footer>
      </article>;
    })}</div> : <div className="plugin-empty">
      <Puzzle size={30} />
      <h3>No plugins installed</h3>
      <p>A plugin is a manifest and one JavaScript file. It gets only the capabilities its manifest asks for, and you see that list before it runs.</p>
    </div>}

    {pending && <div className="overlay" onMouseDown={(event) => event.target === event.currentTarget && setPending(undefined)}>
      <section className="lifecycle-dialog" role="dialog" aria-modal="true" aria-label="Confirm plugin install">
        <header className="lifecycle-head">
          <ShieldCheck size={18} />
          <div><p className="eyebrow">BEFORE IT RUNS</p><h2>{pending.name} is asking for:</h2></div>
        </header>
        <ul className="plugin-capabilities plugin-consent">
          {describeCapabilities(pending.capabilities).map((line) => <li key={line}><ShieldCheck size={12} />{line}</li>)}
          {!pending.capabilities.length && <li><ShieldCheck size={12} />Nothing at all</li>}
        </ul>
        <p className="lifecycle-hint">It cannot reach the network or your filesystem either way. Everything above happens inside this vault, and you can turn it off or remove it at any time.</p>
        <div className="lifecycle-actions">
          <button type="button" onClick={() => setPending(undefined)}>Cancel</button>
          <button onClick={() => void confirmInstall()} disabled={busy}>{busy ? "Installing…" : "Install (disabled)"}</button>
        </div>
      </section>
    </div>}
  </section>;
}
