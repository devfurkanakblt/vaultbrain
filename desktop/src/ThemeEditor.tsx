import { Palette, RotateCcw, X } from "lucide-react";
import { contrastRatio, DEFAULT_THEME, EDITOR_FONTS, isHexColor, PRESETS, presetSettings, type EditorFont, type ThemeSettings } from "./theme";

const COLORS = [
  { key: "shell", label: "Chrome", hint: "Sidebar, title bar and lock screen" },
  { key: "surface", label: "Surface", hint: "The page a note is written on" },
  { key: "ink", label: "Ink", hint: "Body text" },
  { key: "accent", label: "Accent", hint: "Active states and links" },
] as const;

const FONT_LABELS: Record<EditorFont, string> = { serif: "Newsreader", sans: "Plex Sans", mono: "Plex Mono" };

export function ThemeEditor({ settings, onChange, onClose }: {
  settings: ThemeSettings;
  onChange: (next: ThemeSettings) => void;
  onClose: () => void;
}) {
  const readable = contrastRatio(settings.ink, settings.surface);
  const chrome = contrastRatio(settings.accent, settings.shell);

  function update(change: Partial<ThemeSettings>) {
    onChange({ ...settings, ...change });
  }

  return <div className="overlay theme-overlay" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
    <section className="theme-editor" role="dialog" aria-modal="true" aria-label="Theme editor">
      <header>
        <div className="theme-icon"><Palette size={18} /></div>
        <div><p className="eyebrow">APPEARANCE</p><h2>Theme</h2></div>
        <button onClick={onClose} aria-label="Close theme editor"><X size={17} /></button>
      </header>

      <div className="theme-body">
        <fieldset className="theme-presets">
          <legend>Preset</legend>
          {PRESETS.map((preset) => <button key={preset.preset} type="button"
            className={settings.preset === preset.preset ? "active" : ""}
            aria-pressed={settings.preset === preset.preset}
            onClick={() => onChange(presetSettings(preset.preset))}>
            <span className="preset-swatch" style={{ background: preset.shell }}>
              <i style={{ background: preset.surface }} /><em style={{ background: preset.accent }} />
            </span>
            {preset.label}
          </button>)}
        </fieldset>

        <fieldset className="theme-colors">
          <legend>Colours</legend>
          {COLORS.map(({ key, label, hint }) => <label key={key}>
            <span>{label}<small>{hint}</small></span>
            <input type="color" aria-label={label} value={settings[key]}
              onChange={(event) => update({ [key]: event.target.value, preset: "custom" } as Partial<ThemeSettings>)} />
            <input type="text" aria-label={`${label} hex`} value={settings[key]} spellCheck={false}
              onChange={(event) => {
                const value = event.target.value.trim();
                if (isHexColor(value)) update({ [key]: value, preset: "custom" } as Partial<ThemeSettings>);
              }} />
          </label>)}
        </fieldset>

        <fieldset className="theme-type">
          <legend>Reading</legend>
          <label>
            <span>Text size<small>Editor and reading view</small></span>
            <input type="range" min={14} max={22} step={1} aria-label="Reading text size" value={settings.readingSize}
              onChange={(event) => update({ readingSize: Number(event.target.value) })} />
            <b>{settings.readingSize}px</b>
          </label>
          <div className="type-choices" role="group" aria-label="Editor typeface">
            {(Object.keys(EDITOR_FONTS) as EditorFont[]).map((font) => <button key={font} type="button"
              className={settings.editorFont === font ? "active" : ""}
              aria-pressed={settings.editorFont === font}
              style={{ fontFamily: EDITOR_FONTS[font] }}
              onClick={() => update({ editorFont: font })}>{FONT_LABELS[font]}</button>)}
          </div>
        </fieldset>

        <dl className="theme-contrast">
          <div className={readable < 4.5 ? "weak" : ""}>
            <dt>Ink on surface</dt><dd>{readable.toFixed(1)}:1 {readable < 4.5 ? "· below AA" : "· AA"}</dd>
          </div>
          <div className={chrome < 3 ? "weak" : ""}>
            <dt>Accent on chrome</dt><dd>{chrome.toFixed(1)}:1 {chrome < 3 ? "· below AA large" : "· AA large"}</dd>
          </div>
        </dl>
      </div>

      <footer>
        <button type="button" className="theme-reset" onClick={() => onChange(DEFAULT_THEME)}><RotateCcw size={13} />Reset to Archive</button>
        <button type="button" className="theme-done" onClick={onClose}>Done</button>
      </footer>
    </section>
  </div>;
}
