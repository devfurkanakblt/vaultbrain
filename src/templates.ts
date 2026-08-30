import path from "node:path";
import {
  DocumentVault,
  type NoteDocument,
  type PropertyValue,
} from "./documents.js";
import { normalizeNotePath } from "./markdown.js";

export type TemplateVariables = Record<string, string | number | boolean>;

export interface TemplateCreateOptions {
  title?: string;
  variables?: TemplateVariables;
  tags?: string[];
  properties?: Record<string, PropertyValue>;
  date?: Date;
}

export interface DailyNoteOptions {
  folder?: string;
  filenameFormat?: string;
  template?: string;
  tags?: string[];
}

function pad(value: number): string {
  return String(value).padStart(2, "0");
}

export function parseLocalDate(input?: string): Date {
  if (!input) return new Date();
  const match = /^(\d{4})-(\d{2})-(\d{2})$/u.exec(input);
  if (!match) throw new Error("Daily note date must use YYYY-MM-DD.");
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const date = new Date(year, month - 1, day, 12, 0, 0, 0);
  if (date.getFullYear() !== year || date.getMonth() !== month - 1 || date.getDate() !== day) {
    throw new Error(`Invalid calendar date: ${input}`);
  }
  return date;
}

export function formatLocalDate(date: Date, format: string): string {
  const values: Record<string, string> = {
    YYYY: String(date.getFullYear()),
    MM: pad(date.getMonth() + 1),
    DD: pad(date.getDate()),
    HH: pad(date.getHours()),
    mm: pad(date.getMinutes()),
    ss: pad(date.getSeconds()),
  };
  return format.replace(/YYYY|MM|DD|HH|mm|ss/gu, (token) => values[token]);
}

export function renderTemplateText(
  text: string,
  context: { title: string; path: string; date: Date; variables?: TemplateVariables }
): string {
  return text.replace(/\{\{\s*([\w.-]+)(?::([^}]+))?\s*\}\}/gu, (whole, rawName, rawFormat) => {
    const name = String(rawName);
    const format = rawFormat ? String(rawFormat).trim() : undefined;
    if (name === "date") return formatLocalDate(context.date, format ?? "YYYY-MM-DD");
    if (name === "time") return formatLocalDate(context.date, format ?? "HH:mm");
    if (name === "title") return context.title;
    if (name === "path") return context.path;
    if (name === "year") return formatLocalDate(context.date, "YYYY");
    if (name === "month") return formatLocalDate(context.date, "MM");
    if (name === "day") return formatLocalDate(context.date, "DD");
    const value = context.variables?.[name];
    return value === undefined ? whole : String(value);
  });
}

function renderProperty(value: PropertyValue, context: Parameters<typeof renderTemplateText>[1]): PropertyValue {
  if (typeof value === "string") return renderTemplateText(value, context);
  if (Array.isArray(value)) return value.map((item) => renderProperty(item, context));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, renderProperty(item, context)])
    );
  }
  return value;
}

export function createFromTemplate(
  vault: DocumentVault,
  templateReference: string,
  targetPath: string,
  options: TemplateCreateOptions = {}
): NoteDocument {
  const template = vault.get(templateReference);
  const normalizedPath = normalizeNotePath(targetPath);
  const title = options.title?.trim() || path.posix.basename(normalizedPath, ".md");
  const context = {
    title,
    path: normalizedPath,
    date: options.date ?? new Date(),
    variables: options.variables,
  };
  const templateProperties = Object.fromEntries(
    Object.entries(template.properties).map(([key, value]) => [key, renderProperty(value, context)])
  );
  return vault.put({
    path: normalizedPath,
    title: renderTemplateText(title, context),
    body: renderTemplateText(template.body, context),
    tags: [...template.tags.filter((tag) => tag !== "template"), ...(options.tags ?? [])],
    properties: { ...templateProperties, ...(options.properties ?? {}) },
  });
}

export function openDailyNote(
  vault: DocumentVault,
  date: Date,
  options: DailyNoteOptions = {}
): { note: NoteDocument; created: boolean } {
  const folder = (options.folder ?? "Daily").trim().replace(/\\/gu, "/").replace(/^\/+|\/+$/gu, "");
  const filename = formatLocalDate(date, options.filenameFormat ?? "YYYY-MM-DD");
  const notePath = normalizeNotePath(`${folder ? `${folder}/` : ""}${filename}`);
  try {
    return { note: vault.get(notePath), created: false };
  } catch (error) {
    if (!(error instanceof Error) || !error.message.startsWith("Note not found:")) throw error;
  }

  if (options.template) {
    return {
      note: createFromTemplate(vault, options.template, notePath, {
        title: filename,
        date,
        tags: ["daily", ...(options.tags ?? [])],
        properties: { date: formatLocalDate(date, "YYYY-MM-DD") },
      }),
      created: true,
    };
  }
  return {
    note: vault.put({
      path: notePath,
      title: filename,
      body: `# ${filename}\n\n`,
      tags: ["daily", ...(options.tags ?? [])],
      properties: { date: formatLocalDate(date, "YYYY-MM-DD") },
    }),
    created: true,
  };
}
