import { AlertTriangle, Ban, CheckCircle2, Fingerprint, RefreshCw, ShieldAlert, ShieldCheck } from "lucide-react";
import { useState } from "react";
import type { DesktopSyncOperation } from "../../src/desktop-sync-protocol.js";
import type { SyncStatusData } from "./types";

interface SyncStatusProps {
  status: SyncStatusData | null;
  /** Owner-signature check from `sync_verify_registry`; `null` until it answers. */
  registryVerified?: boolean | null;
  onRun?: (operation: DesktopSyncOperation, input: Record<string, unknown>) => Promise<unknown>;
  onCancel?: () => Promise<void>;
}

interface DesktopConflict {
  objectType: string;
  objectId: string;
  heads: string[];
}

/**
 * Visibility into the native sync store plus explicit, one-shot operations
 * delegated to the packaged TypeScript helper. The panel never opens files or
 * shells from the webview; the native bridge owns the request boundary.
 */
export function SyncStatus({ status, registryVerified = null, onRun, onCancel }: SyncStatusProps) {
  const [passphrase, setPassphrase] = useState("");
  const [deviceName, setDeviceName] = useState("");
  const [deviceId, setDeviceId] = useState("");
  const [relayUrl, setRelayUrl] = useState("");
  const [relayToken, setRelayToken] = useState("");
  const [requestText, setRequestText] = useState("");
  const [generatedRequest, setGeneratedRequest] = useState("");
  const [authority, setAuthority] = useState("");
  const [objectType, setObjectType] = useState("");
  const [objectId, setObjectId] = useState("");
  const [selectedHeadId, setSelectedHeadId] = useState("");
  const [conflicts, setConflicts] = useState<DesktopConflict[]>([]);
  const [lastOperation, setLastOperation] = useState<DesktopSyncOperation | null>(null);
  const [busy, setBusy] = useState<DesktopSyncOperation | null>(null);
  const [error, setError] = useState("");
  const readConflicts = (value: unknown): DesktopConflict[] => {
    if (!value || typeof value !== "object" || Array.isArray(value)) return [];
    const result = (value as { result?: unknown }).result ?? value;
    if (!result || typeof result !== "object" || Array.isArray(result)) return [];
    const entries = (result as { conflicts?: unknown }).conflicts;
    if (!Array.isArray(entries)) return [];
    return entries.flatMap((entry) => {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) return [];
      const candidate = entry as { objectType?: unknown; objectId?: unknown; heads?: unknown };
      if (
        typeof candidate.objectType !== "string" ||
        typeof candidate.objectId !== "string" ||
        !Array.isArray(candidate.heads) ||
        candidate.heads.some((head) => typeof head !== "string")
      )
        return [];
      return [{ objectType: candidate.objectType, objectId: candidate.objectId, heads: candidate.heads as string[] }];
    });
  };
  const run = async (operation: DesktopSyncOperation) => {
    if (!onRun || !passphrase) {
      setError("Enter this vault's passphrase for the one-time sync operation.");
      return;
    }
    setBusy(operation);
    setLastOperation(operation);
    setError("");
    try {
      const input = Object.fromEntries(
        Object.entries({
          passphrase,
          deviceName,
          deviceId,
          relayUrl,
          relayToken,
          enrollmentRequest: operation === "approve" && requestText ? JSON.parse(requestText) : undefined,
          authorityFingerprint: status?.authorityFingerprint || authority,
          objectType,
          objectId,
          selectedHeadId,
        }).filter(([, value]) => value !== "" && value !== undefined),
      );
      const value = await onRun(operation, input);
      const result = value && typeof value === "object" ? ((value as { result?: unknown }).result ?? value) : null;
      if (operation === "request" && result && typeof result === "object" && "enrollmentRequest" in result) {
        setGeneratedRequest(JSON.stringify(result.enrollmentRequest, null, 2));
        const request = result.enrollmentRequest as { deviceId?: string };
        if (request.deviceId) setDeviceId(request.deviceId);
      }
      if (operation === "conflicts") setConflicts(readConflicts(value));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Sync operation failed.");
    } finally {
      setBusy(null);
      setPassphrase("");
      setRelayToken("");
    }
  };
  const cancel = async () => {
    if (!busy || !onCancel) return;
    try {
      await onCancel();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not cancel sync operation.");
    }
  };

  // Keep the original read-only embedding contract for callers that do not
  // provide the native sidecar. The desktop app opts into the controls below
  // by passing onRun; this also lets older hosts render status during upgrade.
  if (!onRun && (!status || !status.enrolled)) return null;

  return (
    <section className="sync-view" aria-label="Sync status">
      <header className="sync-header">
        <div>
          <p className="eyebrow">{onRun ? "DESKTOP SYNC" : "CLI-OWNED SYNC"}</p>
          <h2>
            <RefreshCw size={20} /> Sync status
          </h2>
        </div>
      </header>

      {!status || !status.enrolled ? (
        <section className="sync-controls" aria-label="Sync enrollment">
          <p>
            Initialize this device as the sync owner, or create an enrollment request for approval on an owner device.
          </p>
          <label>
            Device name
            <input value={deviceName} onChange={(event) => setDeviceName(event.target.value)} />
          </label>
          <label>
            Vault passphrase
            <input type="password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} />
          </label>
          {onRun && (
            <div>
              <button disabled={!!busy} onClick={() => void run("init")}>
                Initialize owner
              </button>
              <button disabled={!!busy} onClick={() => void run("request")}>
                Create enrollment request
              </button>
            </div>
          )}
          {generatedRequest && (
            <label>
              Generated enrollment request
              <textarea readOnly value={generatedRequest} />
            </label>
          )}
          <label>
            Verified owner fingerprint
            <input value={authority} onChange={(event) => setAuthority(event.target.value)} />
          </label>
          <label>
            Relay URL
            <input value={relayUrl} onChange={(event) => setRelayUrl(event.target.value)} />
          </label>
          <label>
            Relay token
            <input type="password" value={relayToken} onChange={(event) => setRelayToken(event.target.value)} />
          </label>
          <button disabled={!!busy} onClick={() => void run("pull")}>
            Pull approved enrollment
          </button>
          {error && <p className="sync-error">{error}</p>}
        </section>
      ) : (
        <>
          {!status.readable ? (
            <p className="sync-unreadable">
              <AlertTriangle size={14} /> This vault uses a newer format this build cannot display.
            </p>
          ) : (
            <>
              <section className="sync-summary" aria-label="Registry summary">
                <div>
                  <Fingerprint size={14} />
                  <span>
                    <b>Authority</b>
                    <code>{status.authorityFingerprint.slice(0, 12)}</code>
                  </span>
                </div>
                <div>
                  <span>
                    <b>Epoch</b>
                    <code>epoch {status.epoch}</code>
                  </span>
                </div>
                <div>
                  <span>
                    <b>Registry revision</b>
                    <code>{status.registryRevision}</code>
                  </span>
                </div>
                {registryVerified === null ? null : registryVerified ? (
                  <div>
                    <ShieldCheck size={14} />
                    <span>
                      <b>Owner signature</b>
                      <code>verified</code>
                    </span>
                  </div>
                ) : (
                  <div className="sync-unverified">
                    <ShieldAlert size={14} />
                    <span>
                      <b>Owner signature</b>
                      <code>does not verify</code>
                    </span>
                  </div>
                )}
              </section>

              <section className="sync-devices" aria-label="Enrolled devices">
                <h3>Devices</h3>
                <ul>
                  {status.devices.map((device) => (
                    <li key={device.deviceId} className="sync-device">
                      <div>
                        <b>{device.name}</b>
                        <small>
                          serial {device.serial} · epoch {device.epoch}
                        </small>
                      </div>
                      <span
                        className={
                          device.revokedAfterSequence === undefined ? "sync-device-active" : "sync-device-revoked"
                        }
                      >
                        {device.revokedAfterSequence === undefined ? (
                          <>
                            <CheckCircle2 size={12} /> active
                          </>
                        ) : (
                          <>
                            <Ban size={12} /> revoked after sequence {device.revokedAfterSequence}
                          </>
                        )}
                      </span>
                    </li>
                  ))}
                </ul>
              </section>

              <section className="sync-checkpoint" aria-label="Checkpoint">
                <h3>Checkpoint</h3>
                {status.checkpoint ? (
                  <p>
                    sequence {status.checkpoint.sequence} · pinned{" "}
                    {new Date(status.checkpoint.createdAt).toLocaleString()}
                  </p>
                ) : (
                  <p>no checkpoint pinned</p>
                )}
              </section>

              <section className="sync-counts" aria-label="Change counts">
                <p>
                  {status.changeCount} changes recorded, {status.appliedObjectCount} objects synced
                </p>
              </section>
            </>
          )}

          {onRun && (
            <section className="sync-controls" aria-label="Sync controls">
              <h3>Manual sync</h3>
              <p>Credentials are sent once through the native helper's private input and are not stored.</p>
              <label>
                Vault passphrase
                <input type="password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} />
              </label>
              <label>
                Relay URL
                <input
                  value={relayUrl}
                  onChange={(event) => setRelayUrl(event.target.value)}
                  placeholder="https://relay.example"
                />
              </label>
              <label>
                Relay token
                <input type="password" value={relayToken} onChange={(event) => setRelayToken(event.target.value)} />
              </label>
              <div>
                <button disabled={!!busy} onClick={() => void run("push")}>
                  Push
                </button>
                <button disabled={!!busy} onClick={() => void run("pull")}>
                  Pull
                </button>
                <button disabled={!!busy || !lastOperation} onClick={() => lastOperation && void run(lastOperation)}>
                  Retry
                </button>
                {busy && onCancel && <button onClick={() => void cancel()}>Cancel</button>}
              </div>
              {busy && (
                <p className="sync-progress" role="status">
                  {busy} in progress…
                </p>
              )}
              <label>
                Device ID (for approval or revocation)
                <input value={deviceId} onChange={(event) => setDeviceId(event.target.value)} />
              </label>
              <label>
                Enrollment request JSON
                <textarea value={requestText} onChange={(event) => setRequestText(event.target.value)} />
              </label>
              <div>
                <button disabled={!!busy} onClick={() => void run("approve")}>
                  Approve request
                </button>
                <button disabled={!!busy} onClick={() => void run("revoke")}>
                  Revoke device
                </button>
              </div>
              <section className="sync-conflicts" aria-label="Conflict resolution">
                <h3>Conflicts</h3>
                <button disabled={!!busy} onClick={() => void run("conflicts")}>
                  Refresh conflicts
                </button>
                {conflicts.length === 0 ? (
                  <p>No unresolved conflicts reported.</p>
                ) : (
                  <ul>
                    {conflicts.map((conflict) => (
                      <li key={`${conflict.objectType}:${conflict.objectId}`}>
                        <button
                          type="button"
                          onClick={() => {
                            setObjectType(conflict.objectType);
                            setObjectId(conflict.objectId);
                            setSelectedHeadId(conflict.heads[0] ?? "");
                          }}
                        >
                          {conflict.objectType}:{conflict.objectId} ({conflict.heads.length} heads)
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
                <label>
                  Object type
                  <input value={objectType} onChange={(event) => setObjectType(event.target.value)} />
                </label>
                <label>
                  Object ID
                  <input value={objectId} onChange={(event) => setObjectId(event.target.value)} />
                </label>
                <label>
                  Selected head ID
                  <input value={selectedHeadId} onChange={(event) => setSelectedHeadId(event.target.value)} />
                </label>
                <div>
                  <button disabled={!!busy} onClick={() => void run("apply")}>
                    Apply resolved
                  </button>
                  <button disabled={!!busy} onClick={() => void run("resolve")}>
                    Resolve conflict
                  </button>
                </div>
              </section>
              {error && <p className="sync-error">{error}</p>}
            </section>
          )}
        </>
      )}

      {/* Guidance, not interpreted vault data: it stays true, and stays useful,
        even when the registry itself is from a format this build cannot read. */}
      <footer className="sync-footer">
        <p>
          {onRun
            ? "Sync uses the native helper on explicit user request; it never starts in the background."
            : "Sync is read-only in this host. Run mutations from the CLI:"}
        </p>
        {!onRun && <code>vbrain --experimental-trusted-sync sync devices list</code>}
      </footer>
    </section>
  );
}
