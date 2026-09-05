import { AlertTriangle, Ban, CheckCircle2, Fingerprint, RefreshCw, ShieldAlert, ShieldCheck } from "lucide-react";
import type { SyncStatusData } from "./types";

interface SyncStatusProps {
  status: SyncStatusData | null;
  /** Owner-signature check from `sync_verify_registry`; `null` until it answers. */
  registryVerified?: boolean | null;
}

/**
 * Read-only visibility into the CLI-owned sync store: enrollment, the
 * device registry, the active checkpoint and honest change/object counts.
 * There is deliberately no button here that enrolls, revokes, imports,
 * applies or relays -- every mutating sync operation stays in the CLI so the
 * sync protocol keeps exactly one authoritative implementation. This panel
 * only ever reads what `sync_status` and `sync_verify_registry` report.
 */
export function SyncStatus({ status, registryVerified = null }: SyncStatusProps) {
  if (!status || !status.enrolled) return null;

  return <section className="sync-view" aria-label="Sync status">
    <header className="sync-header">
      <div>
        <p className="eyebrow">CLI-OWNED SYNC</p>
        <h2><RefreshCw size={20} /> Sync status</h2>
      </div>
    </header>

    {!status.readable ? <p className="sync-unreadable">
      <AlertTriangle size={14} /> This vault uses a newer format this build cannot display.
    </p> : <>
      <section className="sync-summary" aria-label="Registry summary">
        <div>
          <Fingerprint size={14} />
          <span><b>Authority</b><code>{status.authorityFingerprint.slice(0, 12)}</code></span>
        </div>
        <div><span><b>Epoch</b><code>epoch {status.epoch}</code></span></div>
        <div><span><b>Registry revision</b><code>{status.registryRevision}</code></span></div>
        {registryVerified === null ? null : registryVerified
          ? <div>
              <ShieldCheck size={14} />
              <span><b>Owner signature</b><code>verified</code></span>
            </div>
          : <div className="sync-unverified">
              <ShieldAlert size={14} />
              <span><b>Owner signature</b><code>does not verify</code></span>
            </div>}
      </section>

      <section className="sync-devices" aria-label="Enrolled devices">
        <h3>Devices</h3>
        <ul>
          {status.devices.map((device) => <li key={device.deviceId} className="sync-device">
            <div>
              <b>{device.name}</b>
              <small>serial {device.serial} · epoch {device.epoch}</small>
            </div>
            <span className={device.revokedAfterSequence === undefined ? "sync-device-active" : "sync-device-revoked"}>
              {device.revokedAfterSequence === undefined
                ? <><CheckCircle2 size={12} /> active</>
                : <><Ban size={12} /> revoked after sequence {device.revokedAfterSequence}</>}
            </span>
          </li>)}
        </ul>
      </section>

      <section className="sync-checkpoint" aria-label="Checkpoint">
        <h3>Checkpoint</h3>
        {status.checkpoint
          ? <p>sequence {status.checkpoint.sequence} · pinned {new Date(status.checkpoint.createdAt).toLocaleString()}</p>
          : <p>no checkpoint pinned</p>}
      </section>

      <section className="sync-counts" aria-label="Change counts">
        <p>{status.changeCount} changes recorded, {status.appliedObjectCount} objects synced</p>
      </section>
    </>}

    {/* Guidance, not interpreted vault data: it stays true, and stays useful,
        even when the registry itself is from a format this build cannot read. */}
    <footer className="sync-footer">
      <p>Sync is read-only in the desktop app. Run mutations from the CLI:</p>
      <code>vbrain --experimental-trusted-sync sync devices list</code>
    </footer>
  </section>;
}
