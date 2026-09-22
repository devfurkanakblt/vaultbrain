import crypto from "node:crypto";
import fs from "node:fs";
import {
  decrypt,
  decryptWithKey,
  encrypt,
  encryptWithKey,
  envelopeVersion,
  KEYED_ENVELOPE_VERSION,
  type AnyEncryptedPayload,
  type KeyedEncryptedPayload,
} from "./crypto.js";
import { assertNotSymlink, readTextFileLimited, writeFileAtomic } from "./fs-safe.js";
import { openOrCreateVaultKey, openVaultReadKeys } from "./keyring.js";
import { isRedactionLevel, type RedactionLevel } from "./redaction.js";
import { normalizeVaultName, resolveInside } from "./safety.js";
import { withVaultLock } from "./vault-lock.js";

/**
 * Per-agent scoped grants.
 *
 * MCP access is fail-closed: no `grants.enc` means no agent access. Direct CLI
 * operations remain available to the owner, but an MCP process cannot turn a
 * missing policy into whole-vault access.
 */

export type GrantAction = "discover" | "resolve" | "store";

export const GRANT_ACTIONS: GrantAction[] = ["discover", "resolve", "store"];

export type ConfirmPolicy = "never" | "always";

export interface GrantScope {
  /** A vault category, or `*` for every category. */
  file: string;
  /** Exact key names, a `PREFIX*` glob, or `*`. */
  keys: string[];
  actions: GrantAction[];
  /** Applied to resolved values under this scope. */
  redact: RedactionLevel;
}

/**
 * Whether a scope masks values that `partial` was never designed for.
 *
 * `partial` recognises identifiers — an IBAN, a card number, a phone number,
 * an email, a long opaque id — and keeps a short tail so an agent can confirm
 * a match. Anything it does not recognise falls through to the same treatment:
 * every character but the last four is replaced. That is the right default for
 * an unknown secret and the wrong one for a name, a date or a sentence, which
 * come back as `•••••••••••raca` and answer nothing.
 *
 * Applied to one identifier that is exactly the intent. Applied across a whole
 * file with `*`, it silently destroys every ordinary value in that file, and
 * the agent reports back that it could not find the answer. Measured on a
 * synthetic vault, `health:*:discover,resolve:partial` left three of six
 * permitted questions unanswerable.
 *
 * This does not make the scope unsafe, so it is a warning at the point the
 * owner writes it, never a refusal.
 */
export function overBroadRedaction(scope: GrantScope): boolean {
  if (scope.redact === "none") return false;
  if (!scope.actions.includes("resolve")) return false;
  return scope.keys.some((key) => key === "*" || key.endsWith("*"));
}

export interface AgentGrant {
  id: string;
  agent: string;
  scopes: GrantScope[];
  createdAt: string;
  expiresAt: string | null;
  confirm: ConfirmPolicy;
  revokedAt: string | null;
  note?: string;
}

/** A resolve held back by a `confirm: "always"` grant until the owner decides. */
export interface ConfirmationRequest {
  id: string;
  agent: string;
  file: string;
  key: string;
  requestedAt: string;
  expiresAt: string;
  approvedAt: string | null;
}

export interface GrantFile {
  version: 1;
  grants: AgentGrant[];
  requests: ConfirmationRequest[];
}

export interface AccessRequest {
  agent: string;
  action: GrantAction;
  /** Omitted for a vault-wide discovery call. */
  file?: string;
  /**
   * The exact key the operation will touch. Omitting it asks the broader
   * question "is anything here reachable", which narrows a listing; it never
   * authorizes a write. A caller about to store something must decide the key
   * first and name it here.
   */
  key?: string;
  now?: Date;
}

export interface GrantDecision {
  allowed: boolean;
  /** A sentence the agent can show its user, never a secret. */
  reason: string;
  grantId?: string;
  redact: RedactionLevel;
  /** True when the caller must first obtain an approval for this exact key. */
  requiresConfirmation: boolean;
  /** True when the vault has no grant file (and access was denied). */
  ungoverned: boolean;
}

const GRANTS_FILENAME = "grants.enc";
/**
 * Runs a read-modify-write of the grant file under the vault lock.
 *
 * Every mutation here is a decision taken on what the file said a moment ago:
 * which grants exist, whether an approval is still unspent. Without a lock
 * spanning both halves two processes read the same file, each act on it, and
 * the second silently overwrites the first - which for `consumeApproval` means
 * one owner "yes" can be spent once per racing process, and the single-use
 * guarantee this module exists to provide does not hold.
 *
 * The keyring is resolved first so the scrypt unwrap does not run inside the
 * lock; `withVaultLock` is reentrant, so nesting these is safe. It is resolved
 * only when a policy already exists, because `openOrCreateVaultKey` creates a
 * keyring on a vault that has none — and `consumeApproval` answers false on an
 * ungoverned vault without writing anything, so warming it there would bring a
 * keyring into existence as a side effect of a question.
 */
function withGrantsLock<T>(vaultDir: string, passphrase: string, operation: () => T): T {
  if (grantsExist(vaultDir)) openOrCreateVaultKey(vaultDir, passphrase, "kv")?.fill(0);
  return withVaultLock(vaultDir, operation);
}
const MAX_GRANTS = 100;
const MAX_SCOPES = 50;
const MAX_REQUESTS = 200;
const APPROVAL_TTL_MS = 5 * 60 * 1000;
const SAFE_AGENT = /^[\p{L}\p{N}][\p{L}\p{N} _.:-]*$/u;
const SAFE_KEY_PATTERN = /^(?:\*|[\p{L}\p{N}_][\p{L}\p{N}_.:-]*\*?)$/u;

function grantsPath(vaultDir: string): string {
  return resolveInside(vaultDir, GRANTS_FILENAME);
}

export function grantsExist(vaultDir: string): boolean {
  return fs.existsSync(grantsPath(vaultDir));
}

export function normalizeAgent(input: string): string {
  const agent = input.trim();
  if (!agent || agent.length > 120 || !SAFE_AGENT.test(agent)) {
    throw new Error("Invalid agent name. Use up to 120 letters, numbers, spaces, '_', '.', ':' or '-'.");
  }
  return agent;
}

function normalizeKeyPattern(input: string): string {
  const pattern = input.trim();
  if (!pattern || pattern.length > 160 || !SAFE_KEY_PATTERN.test(pattern)) {
    throw new Error(`Invalid key pattern: ${input}. Use an exact key, 'PREFIX*' or '*'.`);
  }
  return pattern;
}

export function normalizeScope(scope: GrantScope): GrantScope {
  const file = scope.file === "*" ? "*" : normalizeVaultName(scope.file);
  const keys = [...new Set((scope.keys.length ? scope.keys : ["*"]).map(normalizeKeyPattern))];
  const actions = [...new Set(scope.actions)];
  if (!actions.length) throw new Error("A scope must allow at least one action.");
  for (const action of actions) {
    if (!GRANT_ACTIONS.includes(action)) throw new Error(`Unknown action: ${action}`);
  }
  if (!isRedactionLevel(scope.redact)) throw new Error(`Unknown redaction level: ${scope.redact}`);
  return { file, keys, actions, redact: scope.redact };
}

export function emptyGrantFile(): GrantFile {
  return { version: 1, grants: [], requests: [] };
}

const GRANTS_FILE_IDENTITY = "grants";

export function loadGrants(vaultDir: string, passphrase: string): GrantFile | null {
  const path = grantsPath(vaultDir);
  if (!fs.existsSync(path)) return null;
  assertNotSymlink(path);
  const payload: AnyEncryptedPayload = JSON.parse(readTextFileLimited(path, 8 * 1024 * 1024, "Grant policy"));
  const parsed: GrantFile = JSON.parse(
    envelopeVersion(payload) === KEYED_ENVELOPE_VERSION
      ? decryptWithKey(
          payload as KeyedEncryptedPayload,
          requireGrantsReadKeys(vaultDir, passphrase),
          GRANTS_FILE_IDENTITY,
        )
      : decrypt(payload, passphrase),
  );
  if (parsed.version !== 1 || !Array.isArray(parsed.grants)) {
    throw new Error("Unrecognized grant file. Refusing to enforce a policy this build cannot read.");
  }
  return { version: 1, grants: parsed.grants, requests: parsed.requests ?? [] };
}

/** The `kv` key in force, then the retiring one of an unfinished re-key. */
function requireGrantsReadKeys(vaultDir: string, passphrase: string): Buffer[] {
  const keys = openVaultReadKeys(vaultDir, passphrase, "kv");
  if (!keys) throw new Error("The grant file is keyring-encrypted but the vault has no readable keyring.");
  return keys;
}

export function saveGrants(vaultDir: string, file: GrantFile, passphrase: string): GrantFile {
  if (file.grants.length > MAX_GRANTS) {
    throw new Error(`A vault may hold at most ${MAX_GRANTS} grants.`);
  }
  const path = grantsPath(vaultDir);
  if (fs.existsSync(path)) assertNotSymlink(path);
  const stored: GrantFile = {
    version: 1,
    grants: file.grants,
    requests: file.requests.slice(-MAX_REQUESTS),
  };
  const key = openOrCreateVaultKey(vaultDir, passphrase, "kv");
  const payload = key
    ? encryptWithKey(JSON.stringify(stored), key, GRANTS_FILE_IDENTITY)
    : encrypt(JSON.stringify(stored), passphrase);
  writeFileAtomic(path, JSON.stringify(payload, null, 2), { mode: 0o600 });
  return stored;
}

export interface NewGrant {
  agent: string;
  scopes: GrantScope[];
  expiresAt?: string | null;
  confirm?: ConfirmPolicy;
  note?: string;
}

export function addGrant(vaultDir: string, input: NewGrant, passphrase: string): AgentGrant {
  return withGrantsLock(vaultDir, passphrase, () => {
    const file = loadGrants(vaultDir, passphrase) ?? emptyGrantFile();
    if (!input.scopes.length || input.scopes.length > MAX_SCOPES) {
      throw new Error(`A grant needs between 1 and ${MAX_SCOPES} scopes.`);
    }
    if (input.expiresAt && Number.isNaN(new Date(input.expiresAt).getTime())) {
      throw new Error(`Invalid expiry: ${input.expiresAt}`);
    }
    const grant: AgentGrant = {
      id: crypto.randomUUID(),
      agent: normalizeAgent(input.agent),
      scopes: input.scopes.map(normalizeScope),
      createdAt: new Date().toISOString(),
      expiresAt: input.expiresAt ? new Date(input.expiresAt).toISOString() : null,
      confirm: input.confirm ?? "never",
      revokedAt: null,
      ...(input.note ? { note: input.note.trim().slice(0, 240) } : {}),
    };
    saveGrants(vaultDir, { ...file, grants: [...file.grants, grant] }, passphrase);
    return grant;
  });
}

export function revokeGrant(vaultDir: string, id: string, passphrase: string): AgentGrant {
  return withGrantsLock(vaultDir, passphrase, () => {
    const file = loadGrants(vaultDir, passphrase);
    if (!file) throw new Error("This vault has no grants to revoke.");
    const grant = file.grants.find((entry) => entry.id === id || entry.id.startsWith(id));
    if (!grant) throw new Error(`No grant matches: ${id}`);
    if (grant.revokedAt) return grant;
    const revoked: AgentGrant = { ...grant, revokedAt: new Date().toISOString() };
    saveGrants(
      vaultDir,
      {
        ...file,
        grants: file.grants.map((entry) => (entry.id === grant.id ? revoked : entry)),
        // A revoked grant must not leave a usable approval behind.
        requests: file.requests.filter((request) => request.agent !== grant.agent),
      },
      passphrase,
    );
    return revoked;
  });
}

export function listGrants(vaultDir: string, passphrase: string): AgentGrant[] {
  return loadGrants(vaultDir, passphrase)?.grants ?? [];
}

export function isActive(grant: AgentGrant, now: Date): boolean {
  if (grant.revokedAt) return false;
  return !grant.expiresAt || new Date(grant.expiresAt).getTime() > now.getTime();
}

export function matchesKey(pattern: string, key: string): boolean {
  if (pattern === "*") return true;
  if (pattern.endsWith("*")) return key.startsWith(pattern.slice(0, -1));
  return pattern === key;
}

function scopeCovers(scope: GrantScope, request: AccessRequest): boolean {
  if (!scope.actions.includes(request.action)) return false;
  if (scope.file !== "*" && request.file !== undefined && scope.file !== request.file) return false;
  if (request.key === undefined) {
    // A write is never authorized against an unnamed key. Treating an absent
    // key as "every pattern matches" let a caller ask permission before it had
    // decided what to write, and then write a key no scope covered; the key
    // patterns an owner typed are the whole point of a store scope, so the
    // only safe answer to "may I write something, I will tell you what later"
    // is no. Discovery and resolve keep answering the broader question — is
    // there any key here this agent may touch — which is what narrows a
    // listing rather than authorizing an operation.
    return request.action !== "store";
  }
  return scope.keys.some((pattern) => matchesKey(pattern, request.key!));
}

/**
 * The narrowest matching scope wins, so adding a broad convenience grant can
 * never quietly widen a value the owner already chose to mask: among the scopes
 * that cover the request, the strictest redaction is the one applied.
 */
export function decide(file: GrantFile | null, request: AccessRequest): GrantDecision {
  if (!file) {
    return {
      allowed: false,
      reason: "This vault has no grant policy. Ask the vault owner to run: vbrain grant add.",
      redact: "full",
      requiresConfirmation: false,
      ungoverned: true,
    };
  }
  const now = request.now ?? new Date();
  const agent = request.agent.trim();
  const matching = file.grants.filter(
    (grant) =>
      grant.agent === agent && isActive(grant, now) && grant.scopes.some((scope) => scopeCovers(scope, request)),
  );
  if (!matching.length) {
    const known = file.grants.some((grant) => grant.agent === agent);
    return {
      allowed: false,
      reason: known
        ? `No active grant lets "${agent}" ${request.action} that key. Ask the vault owner to widen or renew it.`
        : `"${agent}" has no grant in this vault. Ask the vault owner to run: vbrain grant add.`,
      redact: "full",
      requiresConfirmation: false,
      ungoverned: false,
    };
  }
  const covering = matching.flatMap((grant) =>
    grant.scopes.filter((scope) => scopeCovers(scope, request)).map((scope) => ({ grant, scope })),
  );
  const strictest = covering.reduce((left, right) =>
    strictness(right.scope.redact) > strictness(left.scope.redact) ? right : left,
  );
  const requiresConfirmation =
    request.action === "resolve" && covering.every(({ grant }) => grant.confirm === "always");
  return {
    allowed: true,
    reason: requiresConfirmation
      ? "This grant requires the vault owner to approve each resolution."
      : "Allowed by an active grant.",
    grantId: strictest.grant.id,
    redact: strictest.scope.redact,
    requiresConfirmation,
    ungoverned: false,
  };
}

function strictness(level: RedactionLevel): number {
  return level === "full" ? 2 : level === "partial" ? 1 : 0;
}

/**
 * Confirmation is deliberately out of band: a stdio MCP server has nobody to
 * ask, so the request is parked in the vault and the owner approves it from
 * their own terminal.
 */
export function requestConfirmation(
  vaultDir: string,
  input: { agent: string; file: string; key: string },
  passphrase: string,
): ConfirmationRequest {
  return withGrantsLock(vaultDir, passphrase, () => {
    const file = loadGrants(vaultDir, passphrase);
    if (!file) throw new Error("This vault has no grant policy.");
    const now = new Date();
    const agent = normalizeAgent(input.agent);
    const open = file.requests.find(
      (request) =>
        request.agent === agent &&
        request.file === input.file &&
        request.key === input.key &&
        new Date(request.expiresAt).getTime() > now.getTime(),
    );
    if (open) return open;
    const request: ConfirmationRequest = {
      id: crypto.randomUUID(),
      agent,
      file: input.file,
      key: input.key,
      requestedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + APPROVAL_TTL_MS).toISOString(),
      approvedAt: null,
    };
    saveGrants(vaultDir, { ...file, requests: [...pruneRequests(file.requests, now), request] }, passphrase);
    return request;
  });
}

function pruneRequests(requests: ConfirmationRequest[], now: Date): ConfirmationRequest[] {
  return requests.filter((request) => new Date(request.expiresAt).getTime() > now.getTime());
}

export function pendingRequests(vaultDir: string, passphrase: string): ConfirmationRequest[] {
  const file = loadGrants(vaultDir, passphrase);
  if (!file) return [];
  return pruneRequests(file.requests, new Date()).filter((request) => !request.approvedAt);
}

export function approveRequest(vaultDir: string, id: string, passphrase: string): ConfirmationRequest {
  return withGrantsLock(vaultDir, passphrase, () => {
    const file = loadGrants(vaultDir, passphrase);
    if (!file) throw new Error("This vault has no grant policy.");
    const now = new Date();
    const request = pruneRequests(file.requests, now).find((entry) => entry.id === id || entry.id.startsWith(id));
    if (!request) throw new Error(`No pending request matches: ${id}`);
    const approved: ConfirmationRequest = {
      ...request,
      approvedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + APPROVAL_TTL_MS).toISOString(),
    };
    saveGrants(
      vaultDir,
      {
        ...file,
        requests: pruneRequests(file.requests, now).map((entry) => (entry.id === request.id ? approved : entry)),
      },
      passphrase,
    );
    return approved;
  });
}

export function denyRequest(vaultDir: string, id: string, passphrase: string): void {
  withGrantsLock(vaultDir, passphrase, () => {
    const file = loadGrants(vaultDir, passphrase);
    if (!file) throw new Error("This vault has no grant policy.");
    const now = new Date();
    const remaining = pruneRequests(file.requests, now).filter((entry) => entry.id !== id && !entry.id.startsWith(id));
    saveGrants(vaultDir, { ...file, requests: remaining }, passphrase);
  });
}

/**
 * Single-use by construction: an approval is removed as it is spent, so one
 * "yes" cannot become a standing permission the owner never granted.
 */
export function consumeApproval(
  vaultDir: string,
  input: { agent: string; file: string; key: string },
  passphrase: string,
): boolean {
  return withGrantsLock(vaultDir, passphrase, () => {
    const file = loadGrants(vaultDir, passphrase);
    if (!file) return false;
    const now = new Date();
    const live = pruneRequests(file.requests, now);
    const approval = live.find(
      (request) =>
        request.approvedAt !== null &&
        request.agent === input.agent &&
        request.file === input.file &&
        request.key === input.key,
    );
    if (!approval) {
      if (live.length !== file.requests.length) {
        saveGrants(vaultDir, { ...file, requests: live }, passphrase);
      }
      return false;
    }
    saveGrants(vaultDir, { ...file, requests: live.filter((request) => request.id !== approval.id) }, passphrase);
    return true;
  });
}

/** Keys an agent may even learn the names of, used to narrow discovery. */
export function filterDiscoverable<T extends { key: string }>(
  file: GrantFile | null,
  agent: string,
  vaultFile: string,
  entries: T[],
  now = new Date(),
): T[] {
  if (!file) return [];
  return entries.filter(
    (entry) => decide(file, { agent, action: "discover", file: vaultFile, key: entry.key, now }).allowed,
  );
}
