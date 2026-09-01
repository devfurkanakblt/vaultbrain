export type EditorFont = "serif" | "sans" | "mono";

export interface ThemeSettings {
  preset: string;
  shell: string;
  surface: string;
  ink: string;
  accent: string;
  readingSize: number;
  editorFont: EditorFont;
}

export interface ThemePreset extends ThemeSettings {
  label: string;
  danger: string;
}

const STORAGE_KEY = "vbrain:theme";

export const EDITOR_FONTS: Record<EditorFont, string> = {
  serif: '"Newsreader Variable", Georgia, serif',
  sans: '"IBM Plex Sans Variable", system-ui, sans-serif',
  mono: '"IBM Plex Mono", ui-monospace, monospace',
};

export const PRESETS: ThemePreset[] = [
  {
    preset: "archive",
    label: "Archive",
    shell: "#151713",
    surface: "#f1eee4",
    ink: "#25271f",
    accent: "#c7ef55",
    danger: "#a84e38",
    readingSize: 17,
    editorFont: "serif",
  },
  {
    preset: "slate",
    label: "Slate",
    shell: "#14171c",
    surface: "#eef1f5",
    ink: "#1e242b",
    accent: "#8bb8ff",
    danger: "#c05a45",
    readingSize: 17,
    editorFont: "sans",
  },
  {
    preset: "ember",
    label: "Ember",
    shell: "#191411",
    surface: "#f5efe6",
    ink: "#2a221d",
    accent: "#eb9a4f",
    danger: "#b04a34",
    readingSize: 18,
    editorFont: "serif",
  },
  {
    preset: "contrast",
    label: "High contrast",
    shell: "#000000",
    surface: "#ffffff",
    ink: "#000000",
    accent: "#ffd400",
    danger: "#c81e1e",
    readingSize: 18,
    editorFont: "sans",
  },
];

export const DEFAULT_THEME: ThemeSettings = settingsOf(PRESETS[0]);

function settingsOf(preset: ThemePreset): ThemeSettings {
  const { label: _label, danger: _danger, ...settings } = preset;
  return settings;
}

export function presetSettings(name: string): ThemeSettings {
  return settingsOf(PRESETS.find((preset) => preset.preset === name) ?? PRESETS[0]);
}

function channels(hex: string) {
  const value = hex.replace("#", "");
  const full = value.length === 3 ? [...value].map((part) => part + part).join("") : value;
  return [0, 2, 4].map((index) => Number.parseInt(full.slice(index, index + 2), 16));
}

function toHex(parts: number[]) {
  return `#${parts
    .map((part) =>
      Math.max(0, Math.min(255, Math.round(part)))
        .toString(16)
        .padStart(2, "0"),
    )
    .join("")}`;
}

export function isHexColor(value: string) {
  return /^#(?:[0-9a-f]{3}|[0-9a-f]{6})$/iu.test(value);
}

/** Blend toward white for a positive amount, toward black for a negative one. */
export function shade(hex: string, amount: number) {
  const target = amount >= 0 ? 255 : 0;
  const weight = Math.min(1, Math.abs(amount));
  return toHex(channels(hex).map((part) => part + (target - part) * weight));
}

function luminance(hex: string) {
  const [red, green, blue] = channels(hex).map((part) => {
    const ratio = part / 255;
    return ratio <= 0.03928 ? ratio / 12.92 : ((ratio + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * red + 0.7152 * green + 0.0722 * blue;
}

/** WCAG 2.1 contrast ratio, rounded to one decimal. */
export function contrastRatio(foreground: string, background: string) {
  const [light, dark] = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
  return Math.round(((light + 0.05) / (dark + 0.05)) * 10) / 10;
}

export function themeVariables(settings: ThemeSettings): Record<string, string> {
  const danger = PRESETS.find((preset) => preset.preset === settings.preset)?.danger ?? PRESETS[0].danger;
  return {
    "--night": settings.shell,
    "--night-2": shade(settings.shell, 0.045),
    "--night-3": shade(settings.shell, 0.1),
    "--paper": settings.surface,
    "--paper-deep": shade(settings.surface, -0.045),
    "--paper-line": shade(settings.surface, -0.115),
    "--ink": settings.ink,
    "--ink-soft": shade(settings.ink, 0.22),
    "--muted": shade(settings.ink, 0.48),
    "--muted-2": shade(settings.ink, 0.45),
    "--acid": settings.accent,
    "--acid-deep": shade(settings.accent, -0.34),
    "--rust": danger,
    "--font-editor": EDITOR_FONTS[settings.editorFont],
    "--reading-size": `${settings.readingSize}px`,
  };
}

export function applyTheme(settings: ThemeSettings, root: HTMLElement = document.documentElement) {
  for (const [token, value] of Object.entries(themeVariables(settings))) root.style.setProperty(token, value);
}

export function loadTheme(): ThemeSettings {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT_THEME;
    const stored = JSON.parse(raw) as Partial<ThemeSettings>;
    const preset = typeof stored.preset === "string" ? stored.preset : DEFAULT_THEME.preset;
    const base = presetSettings(preset);
    const colors = (["shell", "surface", "ink", "accent"] as const).reduce<Partial<ThemeSettings>>((carry, key) => {
      const value = stored[key];
      if (typeof value === "string" && isHexColor(value)) carry[key] = value;
      return carry;
    }, {});
    const readingSize = Number(stored.readingSize);
    return {
      ...base,
      ...colors,
      preset,
      readingSize: readingSize >= 14 && readingSize <= 22 ? readingSize : base.readingSize,
      editorFont: stored.editorFont && stored.editorFont in EDITOR_FONTS ? stored.editorFont : base.editorFont,
    };
  } catch {
    return DEFAULT_THEME;
  }
}

export function saveTheme(settings: ThemeSettings) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
  } catch {
    /* a device that refuses storage still gets the theme for this session */
  }
}

export function clearTheme() {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    /* nothing to clean up */
  }
}
