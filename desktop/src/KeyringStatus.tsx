import { useState } from "react";
import { AlertTriangle, KeyRound, LifeBuoy, ShieldAlert, ShieldCheck } from "lucide-react";
import type {
  KeyringStatusData,
  KeyringStatusSlot,
  Notify,
  PassphraseChangeReport,
  RecoveryKitReport,
} from "./types";

/** The same floor `MIN_PASSPHRASE_LENGTH` enforces in both cores. */
const MIN_PASSPHRASE_LENGTH = 12;

interface KeyringStatusProps {
  status: KeyringStatusData | null;
  onChangePassphrase?: (current: string, next: string) => Promise<PassphraseChangeReport>;
  onCreateRecoveryKit?: (passphrase: string) => Promise<RecoveryKitReport | null>;
  onChanged?: () => void | Promise<void>;
  onNotice?: Notify;
}

function formatCost(n: number): string {
  const exponent = Math.log2(n);
  return Number.isInteger(exponent) ? `2^${exponent}` : String(n);
}

function formatDate(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf()) ? value : parsed.toLocaleDateString();
}

/**
 * What the vault's keyring holds. Slot headers only — nothing here is
 * unwrapped, and the panel never asks for the passphrase.
 *
 * Two things are invisible without it, and both matter. A passphrase change
 * deliberately preserves the slots it cannot open, so a slot someone else
 * added stays there unseen. And a vault created before the default work
 * factor rose keeps its old cost until its passphrase is changed once, which
 * makes the upgrade path undiscoverable unless the cost is shown.
 */
export function KeyringStatus({
  status,
  onChangePassphrase,
  onCreateRecoveryKit,
  onChanged,
  onNotice,
}: KeyringStatusProps) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [kitPassphrase, setKitPassphrase] = useState("");
  const [kitBusy, setKitBusy] = useState(false);
  // Held in memory for exactly as long as the person is looking at it. The
  // code is never written anywhere by the application.
  const [issued, setIssued] = useState<RecoveryKitReport | null>(null);

  if (!status) return null;

  if (status.format !== "keyring") {
    return <section className="sync-view" aria-label="Keyring status">
      <header className="sync-header">
        <div>
          <p className="eyebrow">VAULT KEYS</p>
          <h2><KeyRound size={20} /> Keyring</h2>
        </div>
      </header>
      <p className="sync-unreadable">
        <AlertTriangle size={14} /> This vault predates the keyring format. Run{" "}
        <code>vbrain migrate</code> to upgrade it; nothing is re-encrypted.
      </p>
    </section>;
  }

  const behind = status.slots.filter((slot) => slot.kdf.cost === "below-default");

  return <section className="sync-view" aria-label="Keyring status">
    <header className="sync-header">
      <div>
        <p className="eyebrow">VAULT KEYS</p>
        <h2><KeyRound size={20} /> Keyring</h2>
      </div>
    </header>

    <section className="sync-summary" aria-label="Keyring summary">
      <div><span><b>Slots</b><code>{status.slots.length}</code></span></div>
      <div><span><b>Format version</b><code>{status.version ?? "unknown"}</code></span></div>
      {status.recoveryConfigured
        ? <div>
            <ShieldCheck size={14} />
            <span><b>Recovery kit</b><code>configured</code></span>
          </div>
        : <div className="sync-unverified">
            <ShieldAlert size={14} />
            <span><b>Recovery kit</b><code>none</code></span>
          </div>}
    </section>

    {status.recoveryConfigured || issued ? null : <div className="keyring-recovery">
      <p className="sync-unreadable">
        <LifeBuoy size={14} /> This vault has no recovery slot. The keyring holds
        the only wrapped copies of its keys, so a forgotten passphrase or a damaged
        keyring loses every note permanently.
      </p>
      {!onCreateRecoveryKit ? <p className="keyring-hint">
        Create one with <code>vbrain keyring recovery create</code>, and keep the
        code somewhere separate from the kit.
      </p> : <form
        aria-label="Create a recovery kit"
        onSubmit={async (event) => {
          event.preventDefault();
          if (kitBusy) return;
          setKitBusy(true);
          try {
            const report = await onCreateRecoveryKit(kitPassphrase);
            setKitPassphrase("");
            // A dismissed save dialog is a cancellation, not a failure.
            if (report) {
              setIssued(report);
              await onChanged?.();
            }
          } catch (error) {
            onNotice?.(error instanceof Error ? error.message : String(error), "error");
          } finally {
            setKitBusy(false);
          }
        }}
      >
        <label>Confirm your passphrase
          <input
            type="password"
            value={kitPassphrase}
            autoComplete="current-password"
            onChange={(event) => setKitPassphrase(event.target.value)}
          />
        </label>
        <p className="keyring-hint">
          You choose where the kit is written, and it cannot be written inside this
          vault — whatever destroys the keyring would destroy a kit beside it.
        </p>
        <button type="submit" disabled={kitBusy || kitPassphrase.length === 0}>
          {kitBusy ? "Creating…" : "Create a recovery kit"}
        </button>
      </form>}
    </div>}

    {!issued ? null : <div className="keyring-issued" role="alert">
      <h3><LifeBuoy size={16} /> Write this code down now</h3>
      <p>
        It is shown once and stored nowhere. Without it the kit at{" "}
        <code>{issued.kitPath}</code> opens nothing. With both, someone has your
        vault — so keep them apart.
      </p>
      <code className="keyring-code">{issued.recoveryCode}</code>
      <button type="button" onClick={() => setIssued(null)}>I have saved the code</button>
    </div>}

    {behind.length === 0 ? null : <p className="sync-unreadable">
      <AlertTriangle size={14} /> {behind.length === 1 ? "One slot is" : `${behind.length} slots are`}{" "}
      still at an older key-derivation cost. Running{" "}
      <code>vbrain passphrase change</code> once rewrites every slot at{" "}
      {formatCost(status.recommendedScryptN)} without touching a single note.
    </p>}

    {!onChangePassphrase ? null : <form
      className="keyring-passphrase"
      aria-label="Change vault passphrase"
      onSubmit={async (event) => {
        event.preventDefault();
        if (busy) return;
        if (next !== confirmation) {
          onNotice?.("The new passphrase and its confirmation do not match.", "error");
          return;
        }
        setBusy(true);
        try {
          const report = await onChangePassphrase(current, next);
          setCurrent(""); setNext(""); setConfirmation("");
          onNotice?.(
            report.slotsPreserved > 0
              ? `Passphrase changed. ${report.slotsPreserved} slot the old passphrase could not open was preserved.`
              : "Passphrase changed. No note was re-encrypted.",
          );
          await onChanged?.();
        } catch (error) {
          onNotice?.(error instanceof Error ? error.message : String(error), "error");
        } finally {
          setBusy(false);
        }
      }}
    >
      <h3>Change the passphrase</h3>
      <p>
        This moves the wrapping around the vault's keys and nothing else. No note
        is re-encrypted, so anyone who already knew the old passphrase and holds a
        copy of this vault still reads what that copy contains. Only a re-key
        answers a leaked passphrase, and it is a CLI operation.
      </p>
      <label>Current passphrase
        <input
          type="password"
          value={current}
          autoComplete="current-password"
          onChange={(event) => setCurrent(event.target.value)}
        />
      </label>
      <label>New passphrase
        <input
          type="password"
          value={next}
          autoComplete="new-password"
          minLength={MIN_PASSPHRASE_LENGTH}
          onChange={(event) => setNext(event.target.value)}
        />
      </label>
      <label>Confirm new passphrase
        <input
          type="password"
          value={confirmation}
          autoComplete="new-password"
          onChange={(event) => setConfirmation(event.target.value)}
        />
      </label>
      <p className="keyring-hint">
        At least {MIN_PASSPHRASE_LENGTH} characters. If this machine has a
        remembered credential from the command line, it will be stale afterwards —
        re-run <code>vbrain unlock</code> to store the new one.
      </p>
      <button
        type="submit"
        disabled={busy || current.length === 0 || next.length < MIN_PASSPHRASE_LENGTH}
      >
        {busy ? "Changing…" : "Change passphrase"}
      </button>
    </form>}

    <section className="keyring-cli" aria-label="Command-line recovery operations">
      <h3>Done from the command line</h3>
      <p>
        Restoring a damaged keyring verifies vault ciphertext before it replaces
        anything, and re-keying rewrites every object. Neither is offered here:
        a restore is needed exactly when this application cannot open the vault
        at all, so a button for it would be unreachable when it mattered.
      </p>
      <ul>
        <li><code>vbrain keyring recovery restore</code> — replace a lost or damaged keyring using the kit and its code</li>
        <li><code>vbrain keyring recovery remove</code> — drop the recovery slot, after which existing kit copies still open older backups</li>
        <li><code>vbrain rekey</code> — fresh data keys and a re-encrypted vault, the only answer to a leaked passphrase</li>
      </ul>
    </section>

    <table className="sync-devices">
      <caption className="sr-only">Keyring slots</caption>
      <thead>
        <tr>
          <th scope="col">Label</th>
          <th scope="col">Created</th>
          <th scope="col">Cost</th>
          <th scope="col">Slot</th>
        </tr>
      </thead>
      <tbody>
        {status.slots.map((slot: KeyringStatusSlot) => <tr key={slot.id}>
          <td>{slot.recovery ? "recovery" : slot.label}</td>
          <td>{formatDate(slot.createdAt)}</td>
          <td className={slot.kdf.cost === "below-default" ? "sync-unverified" : undefined}>
            <code>{formatCost(slot.kdf.N)}</code>
            {slot.kdf.cost === "below-default" ? " below current" : null}
          </td>
          <td><code>{slot.id.slice(0, 8)}</code></td>
        </tr>)}
      </tbody>
    </table>
  </section>;
}
