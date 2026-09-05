import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  decryptDocumentBytes,
  encryptDocumentBytes,
  type DocumentReadKey,
} from "./document-crypto.js";
import { ATTACHMENT_CHUNK_SIZE } from "./documents.js";
import { AAD, attachmentChunkAad } from "./format-version.js";
import { assertNotSymlink, writeFileAtomic } from "./fs-safe.js";
import { resolveInside } from "./safety.js";

export const MAX_BLOB_BYTES = 2 * 1024 * 1024;

/**
 * The key that seals transport blobs, derived from the permanent `syncChange`
 * key rather than taken from the rotatable `documents` one.
 *
 * A blob's id is the SHA-256 of its sealed bytes, and those ids travel inside
 * a version 3 change body, so they are part of the change's canonical JSON and
 * therefore of its id. Sealing a blob under a key `vbrain rekey` rotates would
 * rename every blob a re-key touched, leave every already-sealed manifest
 * pointing at nothing, and make the manifest unfixable — correcting it would
 * change the change id the causal DAG references. Deriving from a key that is
 * never rotated is what keeps blob addressing stable for the life of the
 * vault, exactly as `syncChange` keeps change ids stable.
 */
export function deriveBlobKey(syncChangeKey: Buffer): Buffer {
  return crypto.createHmac("sha256", syncChangeKey).update(AAD.syncBlobKey).digest();
}
const BLOB_ID_PATTERN = /^[0-9a-f]{64}$/u;

function assertBlobId(id: string): void {
  if (!BLOB_ID_PATTERN.test(id)) {
    throw new Error("A blob id must be 64 lowercase hexadecimal characters.");
  }
}

/**
 * Seal `data` into 1 MiB AEAD chunks bound to their attachment id and index.
 * A blob id is the SHA-256 of the sealed bytes themselves, so the relay can
 * verify an upload without holding any key.
 */
export function sealAttachmentBlobs(
  data: Buffer,
  attachmentId: string,
  key: Buffer
): { blobs: string[]; payloads: Buffer[] } {
  const chunks = Math.ceil(data.length / ATTACHMENT_CHUNK_SIZE);
  const blobs: string[] = [];
  const payloads: Buffer[] = [];
  for (let index = 0; index < chunks; index += 1) {
    const chunk = data.subarray(index * ATTACHMENT_CHUNK_SIZE, (index + 1) * ATTACHMENT_CHUNK_SIZE);
    const payload = Buffer.from(
      JSON.stringify(encryptDocumentBytes(chunk, key, attachmentChunkAad(attachmentId, index))),
      "utf8"
    );
    if (payload.length > MAX_BLOB_BYTES) throw new Error("A sealed attachment chunk exceeds 2 MiB.");
    payloads.push(payload);
    blobs.push(crypto.createHash("sha256").update(payload).digest("hex"));
  }
  return { blobs, payloads };
}

/** Open one sealed blob back into its plaintext chunk. */
export function openAttachmentBlob(
  payload: Buffer,
  attachmentId: string,
  index: number,
  key: DocumentReadKey
): Buffer {
  return decryptDocumentBytes(
    JSON.parse(payload.toString("utf8")) as never,
    key,
    attachmentChunkAad(attachmentId, index)
  );
}

/** Sealed attachment chunks staged under `documents/sync/blobs/<blobId>`. */
export class SyncBlobStore {
  private readonly dir: string;

  constructor(vaultDir: string) {
    this.dir = path.join(vaultDir, "documents", "sync", "blobs");
  }

  private pathFor(id: string): string {
    assertBlobId(id);
    return resolveInside(this.dir, id);
  }

  has(id: string): boolean {
    return fs.existsSync(this.pathFor(id));
  }

  put(id: string, body: Buffer): void {
    const target = this.pathFor(id);
    if (body.length > MAX_BLOB_BYTES) throw new Error("A blob may not exceed 2 MiB.");
    if (crypto.createHash("sha256").update(body).digest("hex") !== id) {
      throw new Error("Blob content does not match its id.");
    }
    if (fs.existsSync(target)) return;
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    writeFileAtomic(target, body, { mode: 0o600 });
  }

  read(id: string): Buffer {
    const target = this.pathFor(id);
    assertNotSymlink(target);
    const stat = fs.lstatSync(target);
    if (stat.isSymbolicLink()) throw new Error("A blob path may not be a symlink.");
    if (stat.size > MAX_BLOB_BYTES) throw new Error("A blob may not exceed 2 MiB.");
    return fs.readFileSync(target);
  }

  missing(ids: string[]): string[] {
    return ids.filter((id) => !this.has(id));
  }

  /**
   * Staged ids whose bytes no longer hash to their own id. Presence is not
   * integrity: a blob can rot on disk or be swapped by anything that writes
   * past `put`, and a caller that is about to commit to a change must learn
   * that before it commits, not while it is decrypting.
   */
  corrupt(ids: string[]): string[] {
    return ids.filter(
      (id) => this.has(id) && crypto.createHash("sha256").update(this.read(id)).digest("hex") !== id,
    );
  }

  remove(id: string): void {
    fs.rmSync(this.pathFor(id), { force: true });
  }
}
