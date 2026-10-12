/*
 * DCTA settings: how the app looks, for this viewer. Theme (system / light /
 * dark), the accent colour, text size, hiding balances, the assistant's
 * voice, and animations.
 *
 * Loaded in <head>, so the saved look applies before the first paint. Nothing
 * here touches money or the signed payload: these are display preferences,
 * kept in this browser's localStorage (and it may be unavailable — a private
 * window — in which case the defaults apply). The voice on/off is voice.js's
 * own setting; this file only shows a switch for it.
 *
 * ?theme=light|dark on the URL overrides the saved theme for that visit.
 */
"use strict";

const Settings = (() => {
  const KEY = "dcta.settings";
  const DEFAULTS = { theme: "system", accent: "lime", text: "default", privacy: false, motion: true };

  // Each accent, for a light and a dark background: the fill, the text on the
  // fill, a soft tint, a readable ink for text and focus rings, the listening
  // rings, a disabled Confirm, and the panels inside the balance card. Lime is
  // the stylesheet's own default; the others override it.
  const ACCENTS = {
    lime: {
      label: "Lime",
      light: ["#d4f56a", "#0b0b0b", "#eef8cc", "#4a6400", "rgba(160, 200, 40, .28)", "rgba(160, 200, 40, .12)", "#e6ebd3", "#6f7858", "rgba(0, 0, 0, .06)"],
      dark: ["#d4f56a", "#0b0b0b", "rgba(212, 245, 106, .14)", "#d4f56a", "rgba(212, 245, 106, .16)", "rgba(212, 245, 106, .07)", "#2a3312", "#8a9a55", "rgba(0, 0, 0, .08)"],
    },
    blue: {
      label: "Blue",
      light: ["#0071e3", "#ffffff", "#e8f0fd", "#0066cc", "rgba(0, 113, 227, .16)", "rgba(0, 113, 227, .06)", "#d2d2d7", "#6e6e73", "rgba(255, 255, 255, .16)"],
      dark: ["#0071e3", "#ffffff", "rgba(10, 132, 255, .16)", "#4da3ff", "rgba(10, 132, 255, .22)", "rgba(10, 132, 255, .09)", "#1a2a40", "#6f87a8", "rgba(255, 255, 255, .14)"],
    },
    orange: {
      label: "Orange",
      light: ["#ff9f0a", "#1d1d1f", "#fff1dc", "#a35200", "rgba(255, 159, 10, .24)", "rgba(255, 159, 10, .1)", "#ece4d6", "#7d6f58", "rgba(0, 0, 0, .06)"],
      dark: ["#ff9f0a", "#0b0b0b", "rgba(255, 159, 10, .16)", "#ffb340", "rgba(255, 159, 10, .18)", "rgba(255, 159, 10, .08)", "#3a2a10", "#a08250", "rgba(0, 0, 0, .08)"],
    },
    pink: {
      label: "Pink",
      light: ["#ff8fb8", "#1d1d1f", "#fde7f0", "#b0004a", "rgba(255, 111, 168, .24)", "rgba(255, 111, 168, .1)", "#eedde4", "#7e6470", "rgba(0, 0, 0, .06)"],
      dark: ["#ff8fb8", "#0b0b0b", "rgba(255, 143, 184, .16)", "#ff8fb8", "rgba(255, 143, 184, .18)", "rgba(255, 143, 184, .08)", "#3a1f2a", "#a06a80", "rgba(0, 0, 0, .08)"],
    },
    purple: {
      label: "Purple",
      light: ["#7d5cff", "#ffffff", "#efebff", "#5b3fd6", "rgba(125, 92, 255, .18)", "rgba(125, 92, 255, .08)", "#dedbe8", "#6e6a80", "rgba(255, 255, 255, .16)"],
      dark: ["#a28bff", "#0b0b0b", "rgba(162, 139, 255, .16)", "#b9a8ff", "rgba(162, 139, 255, .2)", "rgba(162, 139, 255, .08)", "#241f3a", "#7e74a8", "rgba(0, 0, 0, .08)"],
    },
    mint: {
      label: "Mint",
      light: ["#5ee0c2", "#0b0b0b", "#dcf7f0", "#0b6e5c", "rgba(60, 200, 170, .26)", "rgba(60, 200, 170, .1)", "#d8ebe6", "#5f7a73", "rgba(0, 0, 0, .06)"],
      dark: ["#5ee0c2", "#0b0b0b", "rgba(94, 224, 194, .14)", "#5ee0c2", "rgba(94, 224, 194, .16)", "rgba(94, 224, 194, .07)", "#12302a", "#5f9a8c", "rgba(0, 0, 0, .08)"],
    },
    mono: {
      label: "Mono",
      light: ["#1d1d1f", "#ffffff", "#e8e8ed", "#1d1d1f", "rgba(0, 0, 0, .08)", "rgba(0, 0, 0, .04)", "#d2d2d7", "#6e6e73", "rgba(255, 255, 255, .14)"],
      dark: ["#ffffff", "#000000", "rgba(255, 255, 255, .12)", "#ffffff", "rgba(255, 255, 255, .12)", "rgba(255, 255, 255, .05)", "#2c2c2e", "#8e8e93", "rgba(0, 0, 0, .06)"],
    },
  };
  const VARS = ["--accent", "--accent-fg", "--accent-soft", "--accent-ink", "--ring-1", "--ring-2",
                "--disabled-bg", "--disabled-fg", "--inner"];

  const root = document.documentElement;
  const darkQuery = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
  let urlTheme = null;
  try {
    const t = new URLSearchParams(location.search).get("theme");
    if (t === "light" || t === "dark") urlTheme = t;
  } catch (_) { /* no override */ }

  function load() {
    try {
      const saved = JSON.parse(window.localStorage.getItem(KEY) || "{}");
      return { ...DEFAULTS, ...(saved && typeof saved === "object" ? saved : {}) };
    } catch (_) {
      return { ...DEFAULTS };
    }
  }
  let current = load();
  if (!ACCENTS[current.accent]) current.accent = DEFAULTS.accent;

  function save() {
    try { window.localStorage.setItem(KEY, JSON.stringify(current)); } catch (_) { /* this visit only */ }
  }

  function resolvedTheme() {
    const t = urlTheme || current.theme;
    if (t === "light" || t === "dark") return t;
    return darkQuery && darkQuery.matches ? "dark" : "light";
  }

  function apply() {
    const t = urlTheme || current.theme;
    if (t === "light" || t === "dark") root.dataset.theme = t;
    else delete root.dataset.theme;               // follow the system
    const values = ACCENTS[current.accent][resolvedTheme()];
    VARS.forEach((v, i) => {
      if (current.accent === "lime") root.style.removeProperty(v);
      else root.style.setProperty(v, values[i]);
    });
    root.dataset.accent = current.accent;
    root.dataset.text = current.text;
    if (current.privacy) root.dataset.privacy = "on"; else delete root.dataset.privacy;
    if (current.motion) delete root.dataset.motion; else root.dataset.motion = "off";
  }

  function set(patch) {
    current = { ...current, ...patch };
    if ("theme" in patch) urlTheme = null;        // an explicit choice beats the URL
    save();
    apply();
    paint();
  }

  apply();
  if (darkQuery && darkQuery.addEventListener) {
    darkQuery.addEventListener("change", () => { apply(); paint(); });
  }

  /* ---------- the Settings sheet ---------- */
  let opener = null;

  // The controls show the current choices.
  function paint() {
    const theme = urlTheme || current.theme;
    document.querySelectorAll("[data-theme-choice]").forEach((b) => {
      b.setAttribute("aria-checked", String(b.dataset.themeChoice === theme));
    });
    const shade = resolvedTheme();
    document.querySelectorAll("[data-accent-choice]").forEach((b) => {
      b.setAttribute("aria-checked", String(b.dataset.accentChoice === current.accent));
      b.style.setProperty("--sw", ACCENTS[b.dataset.accentChoice][shade][0]);   // as it looks here
    });
    const large = document.getElementById("set-large");
    const privacy = document.getElementById("set-privacy");
    const motion = document.getElementById("set-motion");
    if (large) large.checked = current.text === "large";
    if (privacy) privacy.checked = !!current.privacy;
    if (motion) motion.checked = !!current.motion;
  }

  function open() {
    const sheet = document.getElementById("settings");
    if (!sheet) return;
    opener = document.activeElement;
    paint();
    sheet.hidden = false;
    const first = sheet.querySelector("[aria-checked='true']") || sheet.querySelector("button");
    if (first) first.focus({ preventScroll: true });
  }
  function close() {
    const sheet = document.getElementById("settings");
    if (!sheet || sheet.hidden) return;
    sheet.hidden = true;
    if (opener && opener.focus) opener.focus({ preventScroll: true });
  }

  function wire() {
    const btn = document.getElementById("settings-btn");
    const sheet = document.getElementById("settings");
    if (!btn || !sheet) return;
    btn.onclick = open;
    document.getElementById("settings-close").onclick = close;
    const scrim = document.querySelector(".scrim");
    if (scrim) scrim.addEventListener("click", () => { if (!sheet.hidden) close(); });
    document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !sheet.hidden) close(); });

    // The swatches, built from ACCENTS so the list has one source.
    const swatches = document.getElementById("set-accents");
    for (const [id, a] of Object.entries(ACCENTS)) {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "swatch";
      b.setAttribute("role", "radio");
      b.setAttribute("aria-label", a.label);
      b.title = a.label;
      b.dataset.accentChoice = id;
      b.onclick = () => set({ accent: id });
      swatches.append(b);
    }
    document.querySelectorAll("[data-theme-choice]").forEach((b) => {
      b.onclick = () => set({ theme: b.dataset.themeChoice });
    });
    document.getElementById("set-large").onchange = (e) => set({ text: e.target.checked ? "large" : "default" });
    document.getElementById("set-privacy").onchange = (e) => set({ privacy: e.target.checked });
    document.getElementById("set-motion").onchange = (e) => set({ motion: e.target.checked });

    // The assistant's voice: voice.js keeps that setting; this is its switch.
    const voice = document.getElementById("set-voice");
    const voiceRow = document.getElementById("set-voice-row");
    if (typeof Voice !== "undefined" && Voice.ttsAvailable()) {
      Voice.onStateChange(() => { voice.checked = !Voice.isMuted(); });
      voice.onchange = () => Voice.setMuted(!voice.checked);
    } else if (voiceRow) {
      voiceRow.hidden = true;                     // no speech engine here: nothing to switch
    }

    document.getElementById("settings-reset").onclick = () => {
      current = { ...DEFAULTS };
      urlTheme = null;
      save();
      apply();
      paint();
      if (typeof Voice !== "undefined" && Voice.ttsAvailable()) Voice.setMuted(false);
    };
    paint();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", wire);
  else wire();

  return { open, close, get: () => ({ ...current }) };
})();
