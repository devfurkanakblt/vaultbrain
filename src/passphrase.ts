import readline from "node:readline";
import { recallPassphrase } from "./keychain.js";

export interface PassphraseOptions {
  /** When given, an OS-stored credential for this vault is tried first. */
  vaultDir?: string;
  useKeychain?: boolean;
  prompt?: string;
}

/**
 * Reads a passphrase without echoing it. On a real terminal each character is
 * acknowledged with a `*`; when input is piped (a script, a test) there is no
 * terminal to mask, so the line is read as-is.
 */
export function readSecret(prompt = "Vault passphrase: "): Promise<string> {
  const input = process.stdin;
  if (!input.isTTY || typeof input.setRawMode !== "function") {
    const rl = readline.createInterface({ input, output: process.stderr });
    return new Promise((resolve) =>
      rl.question(prompt, (answer) => {
        rl.close();
        resolve(answer);
      }),
    );
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
  if (process.env.VBRAIN_PASSPHRASE) return process.env.VBRAIN_PASSPHRASE;
  if (options.vaultDir && options.useKeychain !== false) {
    const remembered = recallPassphrase(options.vaultDir);
    if (remembered) return remembered;
  }
  return readSecret(options.prompt ?? "Vault passphrase (or set VBRAIN_PASSPHRASE): ");
}
