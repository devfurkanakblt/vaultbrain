import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { KeyringStatus } from "./KeyringStatus";
import type { KeyringStatusData } from "./types";

function status(overrides: Partial<KeyringStatusData> = {}): KeyringStatusData {
  return {
    format: "keyring",
    version: 2,
    recommendedScryptN: 131072,
    recoveryConfigured: false,
    slots: [
      {
        id: "00000000-0000-4000-8000-000000000001",
        type: "passphrase",
        label: "primary",
        createdAt: "2026-09-01T09:00:00.000Z",
        recovery: false,
        kdf: { name: "scrypt", N: 131072, r: 8, p: 1, cost: "default" },
      },
    ],
    ...overrides,
  };
}

describe("KeyringStatus", () => {
  afterEach(cleanup);

  it("says plainly that a vault without a recovery slot can be lost outright", () => {
    render(<KeyringStatus status={status()} />);
    expect(screen.getByText(/no recovery slot/i)).toBeTruthy();
    expect(screen.getByText("vbrain keyring recovery create")).toBeTruthy();
  });

  it("stops warning once a recovery slot exists", () => {
    render(
      <KeyringStatus
        status={status({
          recoveryConfigured: true,
          slots: [
            ...status().slots,
            {
              id: "00000000-0000-4000-8000-000000000002",
              type: "passphrase",
              label: "recovery",
              createdAt: "2026-09-02T09:00:00.000Z",
              recovery: true,
              kdf: { name: "scrypt", N: 131072, r: 8, p: 1, cost: "default" },
            },
          ],
        })}
      />,
    );
    expect(screen.queryByText(/no recovery slot/i)).toBeNull();
    expect(screen.getByText("configured")).toBeTruthy();
  });

  /**
   * The whole reason the cost is shown: a vault created before the default
   * rose keeps its old work factor until its passphrase is changed once, and
   * without this nobody would ever find that out.
   */
  it("surfaces a slot still at an older key-derivation cost, and how to fix it", () => {
    render(
      <KeyringStatus
        status={status({
          slots: [
            {
              ...status().slots[0],
              kdf: { name: "scrypt", N: 32768, r: 8, p: 1, cost: "below-default" },
            },
          ],
        })}
      />,
    );
    expect(screen.getByText(/older key-derivation cost/i)).toBeTruthy();
    expect(screen.getByText("vbrain passphrase change")).toBeTruthy();
    expect(screen.getByText("2^15")).toBeTruthy();
  });

  it("sends a pre-keyring vault to migrate rather than showing an empty table", () => {
    render(<KeyringStatus status={status({ format: "legacy", version: null, slots: [] })} />);
    expect(screen.getByText(/predates the keyring format/i)).toBeTruthy();
    expect(screen.getByText("vbrain migrate")).toBeTruthy();
  });
});

describe("KeyringStatus passphrase form", () => {
  afterEach(cleanup);

  const filled = {
    format: "keyring",
    version: 2,
    recommendedScryptN: 131072,
    recoveryConfigured: true,
    slots: [
      {
        id: "00000000-0000-4000-8000-000000000001",
        type: "passphrase",
        label: "primary",
        createdAt: "2026-09-01T09:00:00.000Z",
        recovery: false,
        kdf: { name: "scrypt", N: 131072, r: 8, p: 1, cost: "default" as const },
      },
    ],
  };

  function type(label: RegExp, value: string) {
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
  }

  it("says plainly that changing the passphrase re-encrypts nothing", () => {
    render(<KeyringStatus status={filled} onChangePassphrase={async () => report} />);
    expect(screen.getByText(/No note\s+is re-encrypted/i)).toBeTruthy();
  });

  const report = { slotsRewritten: 1, slotsPreserved: 1, previousN: 32768, newN: 131072 };

  it("refuses to submit a confirmation that does not match, without calling the vault", async () => {
    const change = vi.fn(async () => report);
    const notice = vi.fn();
    render(<KeyringStatus status={filled} onChangePassphrase={change} onNotice={notice} />);
    type(/current passphrase/i, "the original passphrase");
    type(/^new passphrase$/i, "a replacement passphrase");
    type(/confirm new passphrase/i, "a different passphrase");
    fireEvent.click(screen.getByRole("button", { name: /change passphrase/i }));
    await waitFor(() => expect(notice).toHaveBeenCalledWith(expect.stringMatching(/do not match/i), "error"));
    expect(change).not.toHaveBeenCalled();
  });

  it("keeps the submit button out of reach until the new passphrase clears the floor", () => {
    render(<KeyringStatus status={filled} onChangePassphrase={async () => report} />);
    type(/current passphrase/i, "the original passphrase");
    type(/^new passphrase$/i, "short");
    expect(screen.getByRole("button", { name: /change passphrase/i }).hasAttribute("disabled")).toBe(true);
    type(/^new passphrase$/i, "a replacement passphrase");
    expect(screen.getByRole("button", { name: /change passphrase/i }).hasAttribute("disabled")).toBe(false);
  });

  it("reports a preserved slot, because a recovery kit surviving is the point", async () => {
    const notice = vi.fn();
    const refresh = vi.fn();
    render(
      <KeyringStatus
        status={filled}
        onChangePassphrase={async () => report}
        onChanged={refresh}
        onNotice={notice}
      />,
    );
    type(/current passphrase/i, "the original passphrase");
    type(/^new passphrase$/i, "a replacement passphrase");
    type(/confirm new passphrase/i, "a replacement passphrase");
    fireEvent.click(screen.getByRole("button", { name: /change passphrase/i }));
    await waitFor(() => expect(notice).toHaveBeenCalledWith(expect.stringMatching(/1 slot .* preserved/i)));
    expect(refresh).toHaveBeenCalled();
  });

  it("surfaces the core's refusal instead of claiming success", async () => {
    const notice = vi.fn();
    render(
      <KeyringStatus
        status={filled}
        onChangePassphrase={async () => {
          throw new Error("wrong passphrase, or the keyring is damaged");
        }}
        onNotice={notice}
      />,
    );
    type(/current passphrase/i, "not the passphrase");
    type(/^new passphrase$/i, "a replacement passphrase");
    type(/confirm new passphrase/i, "a replacement passphrase");
    fireEvent.click(screen.getByRole("button", { name: /change passphrase/i }));
    await waitFor(() =>
      expect(notice).toHaveBeenCalledWith(expect.stringMatching(/wrong passphrase/i), "error"),
    );
  });
});
