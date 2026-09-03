import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { SyncStatus } from "./SyncStatus";
import type { SyncStatusData } from "./types";

afterEach(cleanup);

const base: SyncStatusData = {
  enrolled: true,
  authorityFingerprint: "a".repeat(64),
  epoch: 2,
  registryRevision: 3,
  registryVersion: 2,
  readable: true,
  changeCount: 12,
  appliedObjectCount: 4,
  checkpoint: { id: "b".repeat(64), sequence: 1, changeCount: 12, createdAt: "2026-09-03T00:00:00.000Z" },
  devices: [
    { deviceId: "11111111-1111-4111-8111-111111111111", name: "Owner laptop", serial: 1, epoch: 2 },
    { deviceId: "22222222-2222-4222-8222-222222222222", name: "Travel laptop", serial: 2, epoch: 1, revokedAfterSequence: 0 },
  ],
};

describe("SyncStatus", () => {
  it("renders nothing before enrollment", () => {
    const { container } = render(<SyncStatus status={{ ...base, enrolled: false }} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing when there is no status yet", () => {
    const { container } = render(<SyncStatus status={null} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("shows the active epoch and marks revoked devices, active devices as active", () => {
    render(<SyncStatus status={base} />);
    expect(within(screen.getByLabelText("Registry summary")).getByText(/epoch 2/i)).toBeInTheDocument();
    expect(screen.getByText("Owner laptop")).toBeInTheDocument();
    expect(screen.getByText(/revoked after sequence 0/i)).toBeInTheDocument();
    expect(screen.getByText(/^active$/i)).toBeInTheDocument();
  });

  it("states that mutation is CLI-only and shows the command", () => {
    render(<SyncStatus status={base} />);
    expect(screen.getByText(/read-only/i)).toBeInTheDocument();
    expect(screen.getByText(/sbrain --experimental-trusted-sync sync devices list/)).toBeInTheDocument();
  });

  it("reports the recorded change count and the applied object count honestly", () => {
    render(<SyncStatus status={base} />);
    expect(screen.getByText(/12 changes recorded/i)).toBeInTheDocument();
    expect(screen.getByText(/4 objects synced/i)).toBeInTheDocument();
  });

  it("shows the checkpoint sequence and creation time", () => {
    render(<SyncStatus status={base} />);
    expect(screen.getByText(/checkpoint/i)).toBeInTheDocument();
    expect(screen.getByText(/sequence 1/i)).toBeInTheDocument();
  });

  it("says no checkpoint is pinned when there is none", () => {
    render(<SyncStatus status={{ ...base, checkpoint: null }} />);
    expect(screen.getByText(/no checkpoint pinned/i)).toBeInTheDocument();
  });

  it("explains an unreadable newer format instead of failing, and hides the interpreted detail", () => {
    render(<SyncStatus status={{ ...base, readable: false, registryVersion: 99 }} />);
    expect(screen.getByText(/newer format this build cannot display/i)).toBeInTheDocument();
    expect(screen.queryByText("Owner laptop")).not.toBeInTheDocument();
    expect(screen.queryByText(/sbrain --experimental-trusted-sync/i)).not.toBeInTheDocument();
  });
});
