import crypto from "node:crypto";
import fs from "node:fs";
import { decrypt, encrypt, type AnyEncryptedPayload } from "./crypto.js";
import { assertNotSymlink, writeFileAtomic } from "./fs-safe.js";
import { isRedactionLevel, type RedactionLevel } from "./redaction.js";
import { normalizeVaultName, resolveInside } from "./safety.js";

/**
 * Per-agent scoped grants.
 *
 * The file's existence is the switch: a vault with no `grants.enc` behaves the
 * way it always has — one passphrase, no per-agent narrowing — and a vault with
 * one enforces every rule below. That keeps an existing vault working until its
 * owner decides to govern it, and makes "is this vault governed?" a question
 * with a yes/no answer rather than a policy to read.
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
  /** True when the vault has no grant file and is therefore ungoverned. */
  ungoverned: boolean;
}

const GRANTS_FILENAME = "grants.enc";
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
    throw new Error(
      "Invalid agent name. Use up to 120 letters, numbers, spaces, '_', '.', ':' or '-'."
    );
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

export function loadGrants(vaultDir: string, passphrase: string): GrantFile | null {
  const path = grantsPath(vaultDir);
  if (!fs.existsSync(path)) return null;
  assertNotSymlink(path);
  const payload: AnyEncryptedPayload = JSON.parse(fs.readFileSync(path, "utf8"));
  const parsed: GrantFile = JSON.parse(decrypt(payload, passphrase));
  if (parsed.version !== 1 || !Array.isArray(parsed.grants)) {
    throw new Error("Unrecognized grant file. Refusing to enforce a policy this build cannot read.");
  }
  return { version: 1, grants: parsed.grants, requests: parsed.requests ?? [] };
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
  writeFileAtomic(path, JSON.stringify(encrypt(JSON.stringify(stored), passphrase), null, 2), {
    mode: 0o600,
  });
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
}

export function revokeGrant(vaultDir: string, id: string, passphrase: string): AgentGrant {
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
    passphrase
  );
  return revoked;
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
  if (request.key === undefined) return true;
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
      allowed: true,
      reason: "This vault has no grant policy, so every unlocked key is reachable.",
      redact: "none",
      requiresConfirmation: false,
      ungoverned: true,
    };
  }
  const now = request.now ?? new Date();
  const agent = request.agent.trim();
  const matching = file.grants.filter(
    (grant) => grant.agent === agent && isActive(grant, now) && grant.scopes.some((scope) => scopeCovers(scope, request))
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
    grant.scopes.filter((scope) => scopeCovers(scope, request)).map((scope) => ({ grant, scope }))
  );
  const strictest = covering.reduce((left, right) =>
    strictness(right.scope.redact) > strictness(left.scope.redact) ? right : left
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
  passphrase: string
): ConfirmationRequest {
  const file = loadGrants(vaultDir, passphrase);
  if (!file) throw new Error("This vault has no grant policy.");
  const now = new Date();
  const agent = normalizeAgent(input.agent);
  const open = file.requests.find(
    (request) =>
      request.agent === agent &&
      request.file === input.file &&
      request.key === input.key &&
      new Date(request.expiresAt).getTime() > now.getTime()
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
  saveGrants(
    vaultDir,
    { ...file, requests: [...pruneRequests(file.requests, now), request] },
    passphrase
  );
  return request;
}

function pruneRequests(requests: ConfirmationRequest[], now: Date): ConfirmationRequest[] {
  return requests.filter((request) => new Date(request.expiresAt).getTime() > now.getTime());
}

export function pendingRequests(vaultDir: string, passphrase: string): ConfirmationRequest[] {
  const file = loadGrants(vaultDir, passphrase);
  if (!file) return [];
  return pruneRequests(file.requests, new Date()).filter((request) => !request.approvedAt);
}

export function approveRequest(
  vaultDir: string,
  id: string,
  passphrase: string
): ConfirmationRequest {
  const file = loadGrants(vaultDir, passphrase);
  if (!file) throw new Error("This vault has no grant policy.");
  const now = new Date();
  const request = pruneRequests(file.requests, now).find(
    (entry) => entry.id === id || entry.id.startsWith(id)
  );
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
      requests: pruneRequests(file.requests, now).map((entry) =>
        entry.id === request.id ? approved : entry
      ),
    },
    passphrase
  );
  return approved;
}

export function denyRequest(vaultDir: string, id: string, passphrase: string): void {
  const file = loadGrants(vaultDir, passphrase);
  if (!file) throw new Error("This vault has no grant policy.");
  const now = new Date();
  const remaining = pruneRequests(file.requests, now).filter(
    (entry) => entry.id !== id && !entry.id.startsWith(id)
  );
  saveGrants(vaultDir, { ...file, requests: remaining }, passphrase);
}

/**
 * Single-use by construction: an approval is removed as it is spent, so one
 * "yes" cannot become a standing permission the owner never granted.
 */
export function consumeApproval(
  vaultDir: string,
  input: { agent: string; file: string; key: string },
  passphrase: string
): boolean {
  const file = loadGrants(vaultDir, passphrase);
  if (!file) return false;
  const now = new Date();
  const live = pruneRequests(file.requests, now);
  const approval = live.find(
    (request) =>
      request.approvedAt !== null &&
      request.agent === input.agent &&
      request.file === input.file &&
      request.key === input.key
  );
  if (!approval) {
    if (live.length !== file.requests.length) {
      saveGrants(vaultDir, { ...file, requests: live }, passphrase);
    }
    return false;
  }
  saveGrants(
    vaultDir,
    { ...file, requests: live.filter((request) => request.id !== approval.id) },
    passphrase
  );
  return true;
}

/** Keys an agent may even learn the names of, used to narrow discovery. */
export function filterDiscoverable<T extends { key: string }>(
  file: GrantFile | null,
  agent: string,
  vaultFile: string,
  entries: T[],
  now = new Date()
): T[] {
  if (!file) return entries;
  return entries.filter(
    (entry) =>
      decide(file, { agent, action: "discover", file: vaultFile, key: entry.key, now }).allowed
  );
}
