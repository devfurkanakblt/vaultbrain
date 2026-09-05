import readline from "node:readline";
import { recallPassphrase } from "./keychain.js";

export interface PassphraseOptions {
  /** When given, an OS-stored credential for this vault is tried first. */
  vaultDir?: string;
  useKeychain?: boolean;
  prompt?: string;
}

/**
 * A `rl.question` callback is one-shot, so a caller piping several lines to
 * several sequential prompts has every line after the first discarded by the
 * interface that read it, not carried forward to the next prompt. Naming
 * only "end of file" would misattribute that: the fix is not more input, it
 * is one passphrase per prompt, or the non-interactive environment
 * variables.
 */
function endOfFileMessage(): string {
  return (
    "No passphrase could be read because standard input reached end of file. " +
    "A passphrase must be supplied for each prompt in turn (piping several lines to several prompts does not work), " +
    "or set VBRAIN_PASSPHRASE / VBRAIN_NEW_PASSPHRASE to supply them non-interactively."
  );
}

/**
 * Reads a passphrase without echoing it. On a real terminal each character is
 * acknowledged with a `*`; when input is piped (a script, a test) there is no
 * terminal to mask, so the line is read as-is.
 */
export function readSecret(prompt = "Vault passphrase: "): Promise<string> {
  const input = process.stdin;
  if (!input.isTTY || typeof input.setRawMode !== "function") {
    // `rl.question`'s callback is one-shot: once one prompt has consumed an
    // answer, a *second* sequential `readSecret` call constructs a brand new
    // `readline.Interface` over the same `process.stdin`. If stdin had
    // already ended before that interface existed (piped input with only
    // one line, or a second call made after any macrotask boundary), the
    // new interface never observes an `end` event of its own — nothing
    // further arrives on the stream — so it never emits `close` either, and
    // the promise below would settle neither way, leaving the process to
    // exit 0 having read nothing. Check the already-ended state up front and
    // reject immediately rather than waiting for an event that will not
    // come.
    if (input.readableEnded || input.closed || input.destroyed) {
      return Promise.reject(new Error(endOfFileMessage()));
    }
    const rl = readline.createInterface({ input, output: process.stderr });
    return new Promise((resolve, reject) => {
      let answered = false;
      rl.question(prompt, (answer) => {
        answered = true;
        rl.close();
        resolve(answer);
      });
      rl.on("close", () => {
        if (answered) return;
        reject(new Error(endOfFileMessage()));
      });
    });
  }

  process.stderr.write(prompt);
  const wasRaw = input.isRaw ?? false;
  input.setRawMode(true);
  input.resume();
  input.setEncoding("utf8");

  return new Promise((resolve, reject) => {
    let value = "";
    const restore = () => {
      input.setRawMode(wasRaw);
      input.pause();
      input.removeListener("data", onData);
    };
    const onData = (chunk: string) => {
      for (const character of chunk) {
        if (character === "\r" || character === "\n") {
          restore();
          process.stderr.write("\n");
          resolve(value);
          return;
        }
        if (character === "\u0003" || character === "\u0004") {
          restore();
          process.stderr.write("\n");
          reject(new Error("Passphrase entry cancelled."));
          return;
        }
        if (character === "\u007f" || character === "\b") {
          if (value.length > 0) {
            value = value.slice(0, -1);
            process.stderr.write("\b \b");
          }
          continue;
        }
        if (character < " ") continue;
        value += character;
        process.stderr.write("*");
      }
    };
    input.on("data", onData);
  });
}

/**
 * Resolution order: the environment (scripts, MCP), then the OS credential
 * store for this vault, then a masked prompt. The passphrase is never written
 * to disk by this module — only the OS store holds it, and only if the user
 * asked for that with `vbrain keychain store`.
 */
export async function getPassphrase(options: PassphraseOptions = {}): Promise<string> {
  // SBRAIN_PASSPHRASE was the public name before the vbrain rename. Keep it
  // as a read-only compatibility alias so existing scripts and older sync
  // tooling do not unexpectedly fall back to an interactive prompt.
  const environmentPassphrase = process.env.VBRAIN_PASSPHRASE ?? process.env.SBRAIN_PASSPHRASE;
  if (environmentPassphrase) return environmentPassphrase;
  if (options.vaultDir && options.useKeychain !== false) {
    const remembered = recallPassphrase(options.vaultDir);
    if (remembered) return remembered;
  }
  return readSecret(options.prompt ?? "Vault passphrase (or set VBRAIN_PASSPHRASE): ");
}
