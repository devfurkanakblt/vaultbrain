import { AlertTriangle, KeyRound, LifeBuoy, ShieldAlert, ShieldCheck } from "lucide-react";
import type { KeyringStatusData, KeyringStatusSlot } from "./types";

interface KeyringStatusProps {
  status: KeyringStatusData | null;
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
export function KeyringStatus({ status }: KeyringStatusProps) {
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

    {status.recoveryConfigured ? null : <p className="sync-unreadable">
      <LifeBuoy size={14} /> This vault has no recovery slot. If the passphrase is
      lost, every note is lost with it. Create one with{" "}
      <code>vbrain keyring recovery create</code> and keep the code somewhere
      separate from the kit.
    </p>}

    {behind.length === 0 ? null : <p className="sync-unreadable">
      <AlertTriangle size={14} /> {behind.length === 1 ? "One slot is" : `${behind.length} slots are`}{" "}
      still at an older key-derivation cost. Running{" "}
      <code>vbrain passphrase change</code> once rewrites every slot at{" "}
      {formatCost(status.recommendedScryptN)} without touching a single note.
    </p>}

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
