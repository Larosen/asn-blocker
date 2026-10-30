// App-wide state that several views share: the theme, the overview (counts, banners, apply bar) and the live
// updates from the server (Server-Sent Events), with polling only as the fallback while the stream is down.
import { Icon } from "./icons.js";
import { api, getState, html, setState, t, useStore } from "./lib.js";

// --- Theme: auto (follows the system), light, dark, or OLED (pure black) ---------------------------------------
const THEMES = ["auto", "light", "dark", "oled"];
export const THEME_NAMES = { auto: "Auto", light: "Light", dark: "Dark", oled: "OLED black" };
const redrawers = new Set();
export const onThemeChange = (fn) => { redrawers.add(fn); return () => redrawers.delete(fn); };
export function theme() {
  try { const v = localStorage.getItem("asnb-theme"); if (THEMES.includes(v)) return v; } catch { /* private mode */ }
  return "auto";
}
export function applyTheme() {
  const v = theme();
  if (v === "auto") document.documentElement.removeAttribute("data-theme"); else document.documentElement.dataset.theme = v;
  const dark = v === "dark" || v === "oled" || (v === "auto" && matchMedia("(prefers-color-scheme: dark)").matches);
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", v === "oled" ? "#000000" : dark ? "#0f1013" : "#f6f6f7");
  redrawers.forEach((fn) => fn());
  setState({ theme: v });
}
export function setTheme(v) {
  try { localStorage.setItem("asnb-theme", v); } catch { /* private mode */ }
  applyTheme();
}
export const nextTheme = () => setTheme(THEMES[(THEMES.indexOf(theme()) + 1) % THEMES.length]);
matchMedia("(prefers-color-scheme: dark)").addEventListener?.("change", applyTheme);
// Four direct choices instead of a button that cycles through them
export function ThemeSwitch() {
  const v = useStore((s) => s.theme || theme());
  return html`<div class="seg theme-seg" role="group" aria-label=${t("Theme")}>${THEMES.map((x) => html`<button type="button" data-theme-pick=${x}
    aria-pressed=${v === x} aria-label=${THEME_NAMES[x]} title=${THEME_NAMES[x]} onClick=${() => setTheme(x)}><${Icon} name=${x} /></button>`)}</div>`;
}

// --- Overview and live updates ---------------------------------------------------------------------------------
let pollTimer = null, live = null;
export const liveOk = () => live?.readyState === EventSource.OPEN && !!getState().live;

export async function refreshOverview() {
  clearTimeout(pollTimer);
  let ov;
  try { ov = await api("/overview"); } catch { return; }
  setState({ ov });
  pollTimer = setTimeout(refreshOverview, liveOk() ? 120000 : ov.running ? 2000 : 30000);
}

export function connectLive() {
  live?.close();
  live = new EventSource("/api/events");
  live.addEventListener("state", (e) => {
    const s = JSON.parse(e.data), before = getState().live;
    setState({ live: { ...s, version: (before?.version || 0) + 1 } });
    if (!before || before.rev !== s.rev || before.applied_rev !== s.applied_rev || before.running !== s.running) refreshOverview();
  });
  live.onerror = () => setState({ live: null });  // the browser reconnects by itself; until then the timers poll
}
export function stopLive() { live?.close(); live = null; clearTimeout(pollTimer); setState({ live: null, ov: null }); }
