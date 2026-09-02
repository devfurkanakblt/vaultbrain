import { useEffect, useRef, useState } from "react";
import { Download, FileArchive, FileImage, FileText, LoaderCircle, Paperclip, Trash2, Upload, X } from "lucide-react";
import { vaultBridge } from "./bridge";
import type { AttachmentInfo } from "./types";

interface AttachmentLibraryProps {
  attachments: AttachmentInfo[];
  onRefresh: () => Promise<void>;
  onNotice: (message: string) => void;
}

function readableBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unit = units[0];
  for (let index = 1; value >= 1024 && index < units.length; index += 1) {
    value /= 1024;
    unit = units[index];
  }
  return `${value.toFixed(value >= 10 ? 1 : 2)} ${unit}`;
}

function bytesToBase64(bytes: Uint8Array) {
  let binary = "";
  const chunk = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunk) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunk));
  }
  return btoa(binary);
}

function base64ToBytes(data: string) {
  const binary = atob(data);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

type SafePreview =
  | { kind: "image"; url: string }
  | { kind: "text"; text: string }
  | { kind: "blocked"; reason: string };

const SAFE_TEXT_MIMES = new Set(["text/plain", "text/markdown", "text/csv"]);
const MAX_TEXT_PREVIEW_BYTES = 2 * 1024 * 1024;

function hasPrefix(bytes: Uint8Array, prefix: number[]) {
  return prefix.every((value, index) => bytes[index] === value);
}

function verifiedImageMime(declared: string, bytes: Uint8Array): string | undefined {
  if (declared === "image/png" && hasPrefix(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return declared;
  if (declared === "image/jpeg" && hasPrefix(bytes, [0xff, 0xd8, 0xff])) return declared;
  if (declared === "image/gif" && (hasPrefix(bytes, [0x47, 0x49, 0x46, 0x38, 0x37, 0x61]) || hasPrefix(bytes, [0x47, 0x49, 0x46, 0x38, 0x39, 0x61]))) return declared;
  if (declared === "image/webp" && hasPrefix(bytes, [0x52, 0x49, 0x46, 0x46]) && String.fromCharCode(...bytes.slice(8, 12)) === "WEBP") return declared;
  return undefined;
}

function safePreview(info: AttachmentInfo, bytes: Uint8Array): SafePreview {
  const imageMime = verifiedImageMime(info.mime, bytes);
  if (imageMime) {
    return { kind: "image", url: URL.createObjectURL(new Blob([Uint8Array.from(bytes).buffer], { type: imageMime })) };
  }
  if (SAFE_TEXT_MIMES.has(info.mime)) {
    if (bytes.length > MAX_TEXT_PREVIEW_BYTES) {
      return { kind: "blocked", reason: "Text previews are limited to 2 MiB." };
    }
    return { kind: "text", text: new TextDecoder("utf-8", { fatal: false }).decode(bytes) };
  }
  return {
    kind: "blocked",
    reason: "This file type is not rendered inline. Download it to open it in an isolated application.",
  };
}

function AttachmentIcon({ mime }: { mime: string }) {
  if (mime.startsWith("image/")) return <FileImage size={18} />;
  if (mime.startsWith("text/") || mime === "application/pdf") return <FileText size={18} />;
  return <FileArchive size={18} />;
}

export function AttachmentLibrary({ attachments, onRefresh, onNotice }: AttachmentLibraryProps) {
  const input = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState<AttachmentInfo>();
  const [preview, setPreview] = useState<SafePreview>();

  useEffect(() => () => {
    if (preview?.kind === "image") URL.revokeObjectURL(preview.url);
  }, [preview]);

  async function upload(files: FileList | null) {
    if (!files?.length) return;
    setBusy(true);
    try {
      for (const file of files) {
        const data = bytesToBase64(new Uint8Array(await file.arrayBuffer()));
        await vaultBridge.addAttachment(file.name, file.type || "application/octet-stream", data);
      }
      await onRefresh();
      onNotice(`${files.length} attachment${files.length === 1 ? "" : "s"} encrypted and stored.`);
    } catch (error) {
      onNotice(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
      if (input.current) input.current.value = "";
    }
  }

  async function decrypt(info: AttachmentInfo, download: boolean) {
    setBusy(true);
    try {
      const content = await vaultBridge.readAttachment(info.id);
      const bytes = base64ToBytes(content.data);
      if (download) {
        const url = URL.createObjectURL(new Blob([Uint8Array.from(bytes).buffer], { type: "application/octet-stream" }));
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = info.filename;
        anchor.click();
        window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      } else {
        if (preview?.kind === "image") URL.revokeObjectURL(preview.url);
        setSelected(info);
        setPreview(safePreview(info, bytes));
      }
    } catch (error) {
      onNotice(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  }

  async function remove(info: AttachmentInfo) {
    if (!window.confirm(`Delete ${info.filename} from the encrypted vault? Canvas references will remain as missing references.`)) return;
    setBusy(true);
    try {
      await vaultBridge.deleteAttachment(info.id);
      if (selected?.id === info.id) {
        if (preview?.kind === "image") URL.revokeObjectURL(preview.url);
        setSelected(undefined);
        setPreview(undefined);
      }
      await onRefresh();
      onNotice(`${info.filename} deleted.`);
    } catch (error) {
      onNotice(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  }

  return <section className="asset-library" aria-label="Encrypted attachments">
    <header className="asset-header">
      <div><p className="eyebrow">ENCRYPTED OBJECT STORE</p><h2>Attachments</h2><span>Files are content-addressed, chunked, and decrypted only when opened.</span></div>
      <button className="asset-upload" onClick={() => input.current?.click()} disabled={busy}>
        {busy ? <LoaderCircle className="spin" size={16} /> : <Upload size={16} />} Add files
      </button>
      <input ref={input} type="file" multiple hidden onChange={(event) => void upload(event.target.files)} />
    </header>
    <div className="asset-summary"><Paperclip size={15} /><b>{attachments.length}</b> encrypted objects <i /> <span>{readableBytes(attachments.reduce((sum, item) => sum + item.size, 0))}</span></div>
    {attachments.length ? <div className="asset-grid">{attachments.map((item) => <article className="asset-card" key={item.id}>
      <button className="asset-open" onClick={() => void decrypt(item, false)}>
        <span className="asset-type"><AttachmentIcon mime={item.mime} /></span>
        <b title={item.filename}>{item.filename}</b>
        <small>{item.mime}</small>
        <div><span>{readableBytes(item.size)}</span><span>{item.chunks} chunk{item.chunks === 1 ? "" : "s"}</span></div>
      </button>
      <footer><code>{item.id.slice(0, 10)}</code><button onClick={() => void decrypt(item, true)} title="Decrypt and download"><Download size={14} /></button><button onClick={() => void remove(item)} title="Delete attachment"><Trash2 size={14} /></button></footer>
    </article>)}</div> : <div className="asset-empty"><Paperclip size={30} /><h3>No attachments yet</h3><p>Drop in reference images, PDFs, audio, or any file you want to keep beside your notes.</p><button onClick={() => input.current?.click()}>Choose files</button></div>}
    {selected && preview && <div className="asset-preview" role="dialog" aria-modal="true" aria-label={`Preview ${selected.filename}`}>
      <header><div><AttachmentIcon mime={selected.mime} /><b>{selected.filename}</b><span>{readableBytes(selected.size)}</span></div><button onClick={() => { if (preview.kind === "image") URL.revokeObjectURL(preview.url); setPreview(undefined); setSelected(undefined); }}><X size={17} /></button></header>
      <div>{preview.kind === "image" ? <img src={preview.url} alt={selected.filename} />
        : preview.kind === "text" ? <pre className="asset-text-preview">{preview.text}</pre>
        : <div className="asset-no-preview"><FileArchive size={32} /><p>{preview.reason}</p><button onClick={() => void decrypt(selected, true)}><Download size={15} /> Decrypt and download</button></div>}</div>
    </div>}
  </section>;
}
