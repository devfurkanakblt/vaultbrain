import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type UpdatePhase =
  | "idle"
  | "checking"
  | "up-to-date"
  | "available"
  | "downloading"
  | "ready"
  | "installing"
  | "restart-required"
  | "cancelled"
  | "error";

/**
 * The only updater data the webview may observe. URLs, signing keys and
 * installer paths deliberately do not cross this boundary.
 */
export interface UpdateSnapshot {
  phase: UpdatePhase;
  currentVersion: string;
  availableVersion?: string;
  notes?: string;
  downloadedBytes?: number;
  totalBytes?: number;
  publishedAt?: string;
  canCancel?: boolean;
  error?: string;
}

/** Exact camelCase payload emitted by the native Phase 12 controller. */
export interface NativeUpdateSnapshot {
  status: "idle" | "checking" | "upToDate" | "available" | "downloading" | "downloaded" | "installing" | "error";
  currentVersion: string;
  version?: string;
  notes?: string;
  publishedAt?: string;
  totalBytes?: number;
  downloadedBytes: number;
  canCancel: boolean;
  error?: string;
}

export interface UpdaterClient {
  status(): Promise<UpdateSnapshot>;
  check(): Promise<UpdateSnapshot>;
  download(): Promise<UpdateSnapshot>;
  cancel(): Promise<UpdateSnapshot>;
  install(): Promise<void>;
  subscribe(listener: (snapshot: UpdateSnapshot) => void): Promise<() => void>;
}

type Invoke = <T>(command: string) => Promise<T>;
type Listen = <T>(event: string, handler: (event: { payload: T }) => void) => Promise<UnlistenFn>;

export function normalizeUpdateSnapshot(snapshot: NativeUpdateSnapshot): UpdateSnapshot {
  const phase: UpdatePhase =
    snapshot.status === "upToDate" ? "up-to-date" : snapshot.status === "downloaded" ? "ready" : snapshot.status;
  return {
    phase,
    currentVersion: snapshot.currentVersion,
    availableVersion: snapshot.version,
    notes: snapshot.notes,
    publishedAt: snapshot.publishedAt,
    totalBytes: snapshot.totalBytes,
    downloadedBytes: snapshot.downloadedBytes,
    canCancel: snapshot.canCancel,
    error: snapshot.error,
  };
}

/** Injectable adapter keeps component tests independent of the Tauri runtime. */
export function createUpdaterClient(call: Invoke, observe: Listen): UpdaterClient {
  return {
    status: () => call<NativeUpdateSnapshot>("update_status").then(normalizeUpdateSnapshot),
    check: () => call<NativeUpdateSnapshot>("check_for_update").then(normalizeUpdateSnapshot),
    download: () => call<NativeUpdateSnapshot>("download_update").then(normalizeUpdateSnapshot),
    cancel: () =>
      call<NativeUpdateSnapshot>("cancel_update").then((snapshot) => ({
        ...normalizeUpdateSnapshot(snapshot),
        phase: "cancelled",
      })),
    install: () => call<void>("install_update"),
    async subscribe(listener) {
      return observe<NativeUpdateSnapshot>("vaultbrain://update-state", ({ payload }) =>
        listener(normalizeUpdateSnapshot(payload)),
      );
    },
  };
}

export const updaterClient = createUpdaterClient(invoke, listen);
