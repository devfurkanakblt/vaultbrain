/**
 * Redaction sits between a granted value and the agent that asked for it.
 *
 * It is a reduction in exposure, not a guarantee: under the current MCP spec a
 * tool result flows into the calling model's context, so the honest claim is
 * "the model saw a masked value", never "the model cannot know the value".
 * Anything that must never reach a model belongs behind `sbrain get` (Mode 1),
 * which invokes no model at all.
 */

export type RedactionLevel = "none" | "partial" | "full";

export const REDACTION_LEVELS: RedactionLevel[] = ["none", "partial", "full"];

export function isRedactionLevel(value: string): value is RedactionLevel {
  return (REDACTION_LEVELS as string[]).includes(value);
}

interface Detector {
  /** What this looks like, used verbatim in the `full` description. */
  label: string;
  pattern: RegExp;
  /** Characters left visible at the end under `partial`. */
  keep: number;
}

/**
 * Deliberately conservative: each pattern has to be specific enough that a
 * false positive costs only an over-masked value, never an under-masked one.
 * Order matters — the first match wins for the `full` description.
 */
const DETECTORS: Detector[] = [
  { label: "an IBAN", pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/gu, keep: 4 },
  { label: "a payment card number", pattern: /\b(?:\d[ -]?){13,19}\b/gu, keep: 4 },
  { label: "an email address", pattern: /\b[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}\b/gu, keep: 0 },
  { label: "a phone number", pattern: /(?<![\w.])\+?\d[\d ().-]{7,17}\d(?![\w.])/gu, keep: 2 },
  { label: "a long identifier", pattern: /\b[A-Za-z0-9]{9,}\b/gu, keep: 4 },
];

function maskRun(surface: string, keep: number): string {
  const visible = keep > 0 ? surface.slice(-keep) : "";
  const hiddenLength = Math.max(1, surface.length - visible.length);
  return `${"•".repeat(Math.min(hiddenLength, 12))}${visible}`;
}

/** Which detector, if any, describes the value as a whole. */
function classify(value: string): Detector | undefined {
  const trimmed = value.trim();
  return DETECTORS.find((detector) => {
    const anchored = new RegExp(`^(?:${detector.pattern.source})$`, "u");
    return anchored.test(trimmed);
  });
}

/**
 * A shape, never a value: enough for an agent to decide whether this is the
 * field it wanted, and to ask the person for it directly.
 */
export function describeValue(value: string): string {
  const detector = classify(value);
  const shape = detector ? detector.label : "a stored value";
  const lines = value.split(/\r?\n/u).length;
  const size = `${value.length} character${value.length === 1 ? "" : "s"}`;
  return lines > 1
    ? `[redacted: ${shape}, ${size} across ${lines} lines]`
    : `[redacted: ${shape}, ${size}]`;
}

/**
 * `partial` keeps the value's shape and enough of its tail to confirm a match
 * without handing over the identifier itself. `full` returns no characters of
 * the value at all.
 */
export function redactValue(value: string, level: RedactionLevel): string {
  if (level === "none") return value;
  if (level === "full") return describeValue(value);
  let masked = value;
  for (const detector of DETECTORS) {
    masked = masked.replace(
      new RegExp(detector.pattern.source, detector.pattern.flags),
      (surface) => maskRun(surface, detector.keep)
    );
  }
  return masked === value ? maskRun(value, Math.min(4, Math.max(0, value.length - 1))) : masked;
}

/** True when the level changes what the caller sees. */
export function isRedacting(level: RedactionLevel): boolean {
  return level !== "none";
}
