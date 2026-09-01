import { beforeEach, describe, expect, it } from "vitest";
import {
  contrastRatio,
  DEFAULT_THEME,
  isHexColor,
  loadTheme,
  presetSettings,
  saveTheme,
  shade,
  themeVariables,
} from "./theme";

describe("theme tokens", () => {
  beforeEach(() => localStorage.clear());

  it("blends toward white and black without leaving the byte range", () => {
    expect(shade("#000000", 1)).toBe("#ffffff");
    expect(shade("#ffffff", -1)).toBe("#000000");
    expect(shade("#808080", 0)).toBe("#808080");
    expect(shade("#c7ef55", -0.5)).toBe("#64782b");
    expect(shade("#abc", 0)).toBe("#aabbcc");
  });

  it("derives every workspace token from four editable colours", () => {
    const tokens = themeVariables(DEFAULT_THEME);
    expect(tokens["--night"]).toBe(DEFAULT_THEME.shell);
    expect(tokens["--paper"]).toBe(DEFAULT_THEME.surface);
    expect(tokens["--acid-deep"]).toBe(shade(DEFAULT_THEME.accent, -0.34));
    expect(tokens["--reading-size"]).toBe("17px");
    expect(tokens["--font-editor"]).toContain("Newsreader");
    // chrome shades stay lighter than the shell they came from
    expect(tokens["--night-2"] > tokens["--night"]).toBe(true);
  });

  it("reports WCAG contrast so an unreadable theme is visible as one", () => {
    expect(contrastRatio("#000000", "#ffffff")).toBe(21);
    expect(contrastRatio("#ffffff", "#ffffff")).toBe(1);
    expect(contrastRatio(DEFAULT_THEME.ink, DEFAULT_THEME.surface)).toBeGreaterThan(4.5);
    expect(contrastRatio("#cccccc", "#ffffff")).toBeLessThan(4.5);
  });

  it("validates hex input before it reaches a token", () => {
    expect(isHexColor("#abc")).toBe(true);
    expect(isHexColor("#AABBCC")).toBe(true);
    expect(isHexColor("#abcd")).toBe(false);
    expect(isHexColor("red")).toBe(false);
    expect(isHexColor("")).toBe(false);
  });

  it("round-trips a saved theme and repairs a corrupted one", () => {
    const custom = { ...presetSettings("slate"), accent: "#ff8800", preset: "custom", readingSize: 20 };
    saveTheme(custom);
    expect(loadTheme()).toEqual(custom);

    localStorage.setItem("vbrain:theme", "{not json");
    expect(loadTheme()).toEqual(DEFAULT_THEME);

    localStorage.setItem("vbrain:theme", JSON.stringify({ preset: "archive", accent: "chartreuse", readingSize: 900, editorFont: "comic" }));
    expect(loadTheme()).toEqual(DEFAULT_THEME);
  });

  it("falls back to the default preset when an unknown one is stored", () => {
    expect(presetSettings("nope")).toEqual(DEFAULT_THEME);
    expect(presetSettings("slate").surface).not.toBe(DEFAULT_THEME.surface);
  });
});
