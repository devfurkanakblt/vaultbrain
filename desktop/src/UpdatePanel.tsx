import { useEffect, useMemo, useState } from "react";
import { CheckCircle2, Download, LoaderCircle, RefreshCw, RotateCw, ShieldCheck, TriangleAlert, X } from "lucide-react";
import { updaterClient, type UpdateSnapshot, type UpdaterClient } from "./updater";

interface UpdatePanelProps {
  onPrepareInstall: () => Promise<void>;
  updater?: UpdaterClient;
}

const INITIAL: UpdateSnapshot = { phase: "idle", currentVersion: "0.2.0" };

function messageOf(error: unknown) {
  return error instanceof Error ? error.message : String(error) || "The update operation failed.";
}

function progressOf(snapshot: UpdateSnapshot) {
  if (!snapshot.totalBytes || snapshot.downloadedBytes === undefined) return undefined;
  return Math.min(100, Math.max(0, Math.round((snapshot.downloadedBytes / snapshot.totalBytes) * 100)));
}

export function UpdatePanel({ onPrepareInstall, updater = updaterClient }: UpdatePanelProps) {
  const [snapshot, setSnapshot] = useState(INITIAL);
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const progress = useMemo(() => progressOf(snapshot), [snapshot]);

  useEffect(() => {
    let active = true;
    let unlisten: (() => void) | undefined;
    void updater
      .subscribe((next) => active && setSnapshot(next))
      .then((stop) => {
        if (active) unlisten = stop;
        else stop();
      })
      .catch(() => undefined);
    // Hydration reads native memory only; it does not contact the release
    // channel. A network check still happens exclusively after a user click.
    void updater
      .status()
      .then((next) => active && setSnapshot(next))
      .catch(() => undefined);
    return () => {
      active = false;
      unlisten?.();
    };
  }, [updater]);

  async function run(action: () => Promise<UpdateSnapshot>) {
    setBusy(true);
    try {
      setSnapshot(await action());
    } catch (error) {
      setSnapshot((current) => ({ ...current, phase: "error", error: messageOf(error) }));
    } finally {
      setBusy(false);
    }
  }

  async function install() {
    setBusy(true);
    try {
      await onPrepareInstall();
      setSnapshot((current) => ({ ...current, phase: "installing", error: undefined }));
      await updater.install();
      setSnapshot((current) => ({ ...current, phase: "restart-required" }));
      setBusy(false);
    } catch (error) {
      setSnapshot((current) => ({ ...current, phase: "error", error: messageOf(error) }));
      setConfirming(false);
      setBusy(false);
    }
  }

  const version = snapshot.availableVersion;
  const canCheck = !busy && !["checking", "downloading", "installing"].includes(snapshot.phase);

  return (
    <section className="update-view" aria-labelledby="update-title">
      <header className="update-header">
        <div>
          <p className="eyebrow">SIGNED RELEASE CHANNEL</p>
          <h2 id="update-title">
            <RefreshCw size={25} /> Application updates
          </h2>
        </div>
        <span className="update-current">
          CURRENT <b>v{snapshot.currentVersion}</b>
        </span>
      </header>

      <div className="update-card">
        <div className={`update-mark ${snapshot.phase}`} aria-hidden="true">
          {snapshot.phase === "error" ? (
            <TriangleAlert size={28} />
          ) : snapshot.phase === "downloading" || snapshot.phase === "checking" || snapshot.phase === "installing" ? (
            <LoaderCircle className="spin" size={28} />
          ) : snapshot.phase === "restart-required" ? (
            <RotateCw size={28} />
          ) : snapshot.phase === "up-to-date" ? (
            <CheckCircle2 size={28} />
          ) : (
            <ShieldCheck size={28} />
          )}
        </div>

        <div className="update-copy" aria-live="polite" aria-atomic="true">
          {snapshot.phase === "idle" && (
            <>
              <h3>Updates wait for you.</h3>
              <p>Vault Brain never checks or downloads in the background. Start a check when you are ready.</p>
            </>
          )}
          {snapshot.phase === "checking" && (
            <>
              <h3>Checking the signed channel…</h3>
              <p>Your vault remains available while release metadata is verified.</p>
            </>
          )}
          {snapshot.phase === "up-to-date" && (
            <>
              <h3>You have the latest version.</h3>
              <p>Vault Brain v{snapshot.currentVersion} is current.</p>
            </>
          )}
          {snapshot.phase === "available" && (
            <>
              <h3>Vault Brain v{version} is available.</h3>
              <p>The package is downloaded only after you approve it.</p>
            </>
          )}
          {snapshot.phase === "downloading" && (
            <>
              <h3>Downloading v{version}…</h3>
              <p>The signature is verified before this update can be installed.</p>
            </>
          )}
          {snapshot.phase === "ready" && (
            <>
              <h3>v{version} is verified and ready.</h3>
              <p>Installation saves every edit, locks and clears the vault, then restarts the application.</p>
            </>
          )}
          {snapshot.phase === "installing" && (
            <>
              <h3>Installing the verified update…</h3>
              <p>Keep Vault Brain open. The application will restart when installation finishes.</p>
            </>
          )}
          {snapshot.phase === "restart-required" && (
            <>
              <h3>Restart required.</h3>
              <p>Close and reopen Vault Brain to finish applying v{version}.</p>
            </>
          )}
          {snapshot.phase === "cancelled" && (
            <>
              <h3>Download cancelled.</h3>
              <p>Nothing was installed. You can check again whenever you choose.</p>
            </>
          )}
          {snapshot.phase === "error" && (
            <div role="alert">
              <h3>The update could not continue.</h3>
              <p>{snapshot.error ?? "The native updater rejected the operation."}</p>
              <small>Your vault and ordinary offline work are unaffected.</small>
            </div>
          )}
        </div>

        {snapshot.notes && (
          <div className="update-notes">
            <b>Release notes</b>
            <p>{snapshot.notes}</p>
          </div>
        )}

        {snapshot.phase === "downloading" && (
          <div className="update-progress">
            <div className="update-progress-label">
              <span>Verified download</span>
              <b>{progress === undefined ? "IN PROGRESS" : `${progress}%`}</b>
            </div>
            <progress aria-label="Update download progress" value={progress} max={100}>
              {progress}%
            </progress>
          </div>
        )}

        <div className="update-actions">
          {snapshot.phase === "available" && (
            <button className="update-primary" disabled={busy} onClick={() => void run(updater.download)}>
              <Download size={15} /> Download update
            </button>
          )}
          {snapshot.phase === "downloading" && (
            <button disabled={busy} onClick={() => void run(updater.cancel)}>
              <X size={15} /> Cancel download
            </button>
          )}
          {snapshot.phase === "ready" && !confirming && (
            <button className="update-primary" onClick={() => setConfirming(true)}>
              <RotateCw size={15} /> Install and restart
            </button>
          )}
          {snapshot.phase === "ready" && confirming && (
            <div className="update-confirm" role="group" aria-label="Confirm update installation">
              <p>
                <b>Save, lock, and restart now?</b>
                <span>Unsaved edits are saved first. A failed save stops installation.</span>
              </p>
              <button onClick={() => setConfirming(false)}>Not now</button>
              <button className="update-primary" disabled={busy} onClick={() => void install()}>
                Confirm install
              </button>
            </div>
          )}
          {!["available", "downloading", "ready", "installing"].includes(snapshot.phase) && (
            <button className="update-primary" disabled={!canCheck} onClick={() => void run(updater.check)}>
              {snapshot.phase === "checking" ? <LoaderCircle className="spin" size={15} /> : <RefreshCw size={15} />}{" "}
              Check for updates
            </button>
          )}
        </div>
      </div>

      <footer className="update-assurance">
        <ShieldCheck size={16} />
        <p>
          <b>Native verification is mandatory.</b> The release source and public key are pinned inside the application;
          this screen cannot change them.
        </p>
      </footer>
    </section>
  );
}
