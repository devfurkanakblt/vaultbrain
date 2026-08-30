let ownedText: string | undefined;
let expiryTimer: number | undefined;

async function clearIfOwned() {
  const expected = ownedText;
  if (!expected || !navigator.clipboard?.readText || !navigator.clipboard?.writeText) return false;
  try {
    if (await navigator.clipboard.readText() !== expected) return false;
    await navigator.clipboard.writeText("");
    ownedText = undefined;
    return true;
  } catch {
    return false;
  }
}

export async function copyWithExpiry(text: string, ttlMs = 30_000) {
  if (!navigator.clipboard?.writeText || !navigator.clipboard?.readText) {
    throw new Error("Secure clipboard access is unavailable on this system.");
  }
  window.clearTimeout(expiryTimer);
  await navigator.clipboard.writeText(text);
  ownedText = text;
  expiryTimer = window.setTimeout(() => void clearIfOwned(), ttlMs);
}

export async function clearOwnedClipboard() {
  window.clearTimeout(expiryTimer);
  await clearIfOwned();
  ownedText = undefined;
}
