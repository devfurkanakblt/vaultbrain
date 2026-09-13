import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryPanel } from "./MemoryPanel";
import type { MemoryStatusData } from "./types";

const status: MemoryStatusData = { state: "disabled", paired: false, paused: false, queued: 0, review: 0, failed: 0, expired: 0, compatibilityReasons: ["Enable memory from an unlocked vault."], generation: 1 };
const handlers = { onRefresh: vi.fn(async () => {}), onPairBegin: vi.fn(async () => ({ pairingId: "pair-1", state: "awaitingConfirmation" as const })), onPairComplete: vi.fn(async () => {}), onPairCancel: vi.fn(async () => {}), onDisconnect: vi.fn(async () => {}), onPause: vi.fn(async () => {}), onExclude: vi.fn(async () => {}), onApprove: vi.fn(async () => {}), onReject: vi.fn(async () => {}), onPin: vi.fn(async () => {}), onForget: vi.fn(async () => {}), onRelearn: vi.fn(async () => {}), onOpenNote: vi.fn(async () => {}), onNotice: vi.fn() };
afterEach(cleanup);
describe("MemoryPanel", () => {
  it("shows disabled memory honestly without a successful setup affordance", () => { render(<MemoryPanel status={status} review={[]} {...handlers} />); expect(screen.getByText(/not ready/i)).toBeTruthy(); expect(screen.getByRole("button", { name: /begin owner pairing/i })).toBeDisabled(); });
  it("reveals references only on owner request and sends review actions through callbacks", async () => { const active = { ...status, state: "ready" as const, paired: true, review: 1 }; render(<MemoryPanel status={active} review={[{ id: "c-1", kind: "fact", title: "Tea", body: "Prefers tea", evidence: [{ messageId: "m-1", quote: "I prefer tea." }], sourceKind: "user-stated", sensitive: false, links: [], createdAt: "2026-09-12T00:00:00Z" }]} {...handlers} />); expect(screen.queryByText("I prefer tea.")).toBeNull(); fireEvent.click(screen.getByText(/source references/i)); expect(screen.getByText("I prefer tea.")).toBeTruthy(); fireEvent.click(screen.getByRole("button", { name: /approve/i })); expect(await handlers.onApprove).toHaveBeenCalledWith("c-1"); });
});
