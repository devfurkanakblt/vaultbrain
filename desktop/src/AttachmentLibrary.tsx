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

function base64ToBlob(data: string, mime: string) {
  const binary = atob(data);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return new Blob([bytes], { type: mime });
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
  const [previewUrl, setPreviewUrl] = useState("");

  useEffect(() => () => {
    if (previewUrl) URL.revokeObjectURL(previewUrl);
  }, [previewUrl]);

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
      const url = URL.createObjectURL(base64ToBlob(content.data, info.mime));
      if (download) {
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = info.filename;
        anchor.click();
        window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      } else {
        if (previewUrl) URL.revokeObjectURL(previewUrl);
        setSelected(info);
        setPreviewUrl(url);
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
        if (previewUrl) URL.revokeObjectURL(previewUrl);
        setSelected(undefined);
        setPreviewUrl("");
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
    {selected && previewUrl && <div className="asset-preview" role="dialog" aria-modal="true" aria-label={`Preview ${selected.filename}`}>
      <header><div><AttachmentIcon mime={selected.mime} /><b>{selected.filename}</b><span>{readableBytes(selected.size)}</span></div><button onClick={() => { URL.revokeObjectURL(previewUrl); setPreviewUrl(""); setSelected(undefined); }}><X size={17} /></button></header>
      <div>{selected.mime.startsWith("image/") ? <img src={previewUrl} alt={selected.filename} />
        : selected.mime.startsWith("audio/") ? <audio src={previewUrl} controls autoPlay />
        : selected.mime.startsWith("video/") ? <video src={previewUrl} controls autoPlay />
        : selected.mime === "application/pdf" || selected.mime.startsWith("text/") ? <iframe src={previewUrl} title={selected.filename} />
        : <div className="asset-no-preview"><FileArchive size={32} /><p>This file type has no inline preview.</p><button onClick={() => void decrypt(selected, true)}><Download size={15} /> Decrypt and download</button></div>}</div>
    </div>}
  </section>;
}
