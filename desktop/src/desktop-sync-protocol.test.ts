import { describe, expect, it } from "vitest";

import { parseDesktopSyncRequest, syncProgress } from "../../src/desktop-sync-protocol.js";

describe("desktop sync helper protocol", () => {
  const base = { version: 1, operation: "request", vaultPath: "C:/vault", passphrase: "secret", deviceName: "Laptop" };

  it("accepts a bounded request and never serializes credentials into progress", () => {
    const request = parseDesktopSyncRequest(base);
    expect(request.operation).toBe("request");
    expect(syncProgress("request", "running", request)).toEqual({ version: 1, operation: "request", state: "running" });
  });

  it("rejects unknown fields and oversized credential fields", () => {
    expect(() => parseDesktopSyncRequest({ ...base, surprise: true })).toThrow(/unknown/i);
    expect(() => parseDesktopSyncRequest({ ...base, passphrase: "x".repeat(4097) })).toThrow(/passphrase/i);
  });

  it("requires a pinned authority fingerprint for the first relay pull", () => {
    expect(() => parseDesktopSyncRequest({ ...base, operation: "pull", relayUrl: "https://relay.example" })).toThrow(/fingerprint/i);
  });

  it("admits conflict inspection without exposing change bodies", () => {
    expect(parseDesktopSyncRequest({ ...base, operation: "conflicts" }).operation).toBe("conflicts");
  });
});
