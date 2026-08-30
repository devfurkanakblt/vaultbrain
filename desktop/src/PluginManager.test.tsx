import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PluginManager } from "./PluginManager";
import type { PluginSummary } from "./types";

const base: PluginSummary = {
  id: "plugin-1",
  manifestId: "word-count",
  name: "Word count",
  version: "1.0.0",
  description: "Counts words",
  author: "someone",
  capabilities: ["notes:read"],
  enabled: false,
  signatureStatus: "verified",
  signer: "a".repeat(64),
  signed: true,
  sourceBytes: 120,
  updatedAt: "2026-08-31T08:00:00.000Z",
  revision: 1,
};

function show(overrides: Partial<Parameters<typeof PluginManager>[0]> = {}) {
  const props = {
    plugins: [base],
    policy: { version: 1 as const, restrictedMode: false, revokedSigners: [] },
    states: [],
    onInstall: vi.fn(async () => {}),
    onToggle: vi.fn(async () => {}),
    onRemove: vi.fn(async () => {}),
    onRestricted: vi.fn(async () => {}),
    onRevoke: vi.fn(async () => {}),
    onRestore: vi.fn(async () => {}),
    onNotice: vi.fn(),
    ...overrides,
  };
  render(<PluginManager {...props} />);
  return props;
}

afterEach(cleanup);

describe("plugin package trust controls", () => {
  it("shows verified, unsigned and revoked package states", () => {
    show({
      plugins: [
        base,
        { ...base, id: "plugin-2", name: "Plain", signatureStatus: "unsigned", signer: undefined, signed: false },
        { ...base, id: "plugin-3", name: "Blocked", signatureStatus: "revoked", signed: false },
      ],
    });

    expect(screen.getByText("verified signer")).toBeInTheDocument();
    expect(screen.getByText("unsigned")).toBeInTheDocument();
    expect(screen.getByText("signer revoked")).toBeInTheDocument();
  });

  it("routes restricted mode and signer revocation through explicit actions", async () => {
    const props = show();
    fireEvent.click(screen.getByRole("checkbox", { name: /restricted mode/iu }));
    fireEvent.click(screen.getByRole("button", { name: /revoke signer/iu }));

    await waitFor(() => expect(props.onRestricted).toHaveBeenCalledWith(true));
    expect(props.onRevoke).toHaveBeenCalledWith(base);
  });

  it("can restore a locally revoked signer", () => {
    const revoked = { ...base, signatureStatus: "revoked" as const, signed: false };
    const props = show({ plugins: [revoked] });
    fireEvent.click(screen.getByRole("button", { name: /restore signer/iu }));
    expect(props.onRestore).toHaveBeenCalledWith(base.signer);
  });
});
