/**
 * The .kv format — deliberately close to .env, because that's the mental
 * model this project borrows from developers:
 *
 *   # @desc: Bir sonraki doktor kontrol tarihi
 *   DOCTOR_NEXT_APPOINTMENT="2026-09-15"
 *
 * The `@desc` line is the ONLY thing that ever leaves the vault unencrypted
 * (via `sbrain index`). It must never itself contain the sensitive value —
 * that's a convention this tool can't fully enforce, so the README calls
 * it out explicitly.
 */

export interface KVEntry {
  key: string;
  value: string;
  desc: string;
}

export function parseKV(content: string): KVEntry[] {
  const lines = content.split("\n");
  const entries: KVEntry[] = [];
  let pendingDesc = "";

  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;

    if (line.startsWith("# @desc:")) {
      pendingDesc = line.slice("# @desc:".length).trim();
      continue;
    }
    if (line.startsWith("#")) continue; // plain comment, ignored

    const eq = line.indexOf("=");
    if (eq === -1) continue;

    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if (value.startsWith('"') && value.endsWith('"')) {
      // New files use JSON string escaping, which safely round-trips quotes,
      // backslashes and newlines. Fall back to the original MVP behaviour so
      // existing vaults remain readable.
      try {
        const parsed: unknown = JSON.parse(value);
        if (typeof parsed === "string") value = parsed;
        else value = value.slice(1, -1);
      } catch {
        value = value.slice(1, -1);
      }
    }

    entries.push({ key, value, desc: pendingDesc });
    pendingDesc = "";
  }

  return entries;
}

export function serializeKV(entries: KVEntry[]): string {
  return (
    entries
      .map((e) => `# @desc: ${e.desc}\n${e.key}=${JSON.stringify(e.value)}`)
      .join("\n\n") + "\n"
  );
}
