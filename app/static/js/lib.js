// Basics shared by every view: rendering (Preact + htm, no build step), text, formatting, the API client and a
// small store whose changes re-render the components that read it.
import { Fragment, h, render } from "../vendor/preact.module.js";
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "../vendor/hooks.module.js";
import htm from "../vendor/htm.module.js";

export { Fragment, h, render, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState };
export const html = htm.bind(h);

// --- Text ------------------------------------------------------------------------------------------------------
// t() fills {name} placeholders with strings; tx() also accepts elements (e.g. <code>) and returns a list for JSX
export function t(text, vars) {
  return vars ? text.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m)) : text;
}
export function tx(text, vars) {
  return text.split(/(\{\w+\})/).map((part) => {
    const m = /^\{(\w+)\}$/.exec(part);
    return m && m[1] in vars ? vars[m[1]] : part;
  });
}

const LOCALE = "en-GB";
export const locale = () => LOCALE;
export const fmtNum = (n) => (n ?? 0).toLocaleString(LOCALE);
export const fmtAddr = (n) => (n >= 1e6 ? t("{n} M", { n: (n / 1e6).toLocaleString(LOCALE, { maximumFractionDigits: 1 }) })
  : n >= 1e3 ? t("{n} K", { n: (n / 1e3).toLocaleString(LOCALE, { maximumFractionDigits: 1 }) }) : fmtNum(n));
export const fmtTime = (ts) => (ts ? new Date(ts * 1000).toLocaleString(LOCALE, { dateStyle: "short", timeStyle: "short" }) : "–");
export function ago(ts) {
  if (!ts) return "–";
  const rtf = new Intl.RelativeTimeFormat(LOCALE, { numeric: "auto" });
  const s = ts - Date.now() / 1000, a = Math.abs(s);
  if (a < 90) return rtf.format(0, "second");
  if (a < 3600) return rtf.format(Math.round(s / 60), "minute");
  if (a < 172800) return rtf.format(Math.round(s / 3600), "hour");
  return rtf.format(Math.round(s / 86400), "day");
}
export const now = () => Math.round(Date.now() / 1000);
export const act = (a) => ({ ban: t("Block"), captcha: t("Captcha") }[a] ?? a);
export const runStatus = (s) => ({ ok: t("succeeded"), failed: t("failed"), blocked: t("stopped"), running: t("running") }[s] ?? s);
export const kindName = (k) => (k === "plan" ? t("Preview") : t("Apply"));
export const CONTINENTS = ["EU", "NA", "SA", "AS", "OC", "AF", "AN", ""];
export const continentName = (c) => ({ EU: t("Europe"), NA: t("North America"), SA: t("South America"), AS: t("Asia"), AF: t("Africa"),
  OC: t("Oceania"), AN: t("Antarctica") }[c] ?? t("Other"));
export const IS_MAC = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
export const IP_RE = /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f:]*:[0-9a-f:.]+)$/i;
export const stopReasons = (r) => r?.summary?.stopped?.length ? r.summary.stopped : [t("The change exceeds the sanity limits.")];

// --- API -------------------------------------------------------------------------------------------------------
let onSignedOut = () => {};
export const whenSignedOut = (fn) => { onSignedOut = fn; };

// What a failed request says, in words a person can act on – no "Failed to fetch", no HTML error pages, no stack traces.
export function cleanMessage(m) {
  const s = String(m ?? "").replace(/<[^>]*>/g, " ").replace(/Traceback[\s\S]*$/, "").replace(/\s+/g, " ").trim();
  return s.length > 300 ? s.slice(0, 297) + " …" : s;
}
const statusText = (status) => ({
  502: t("asn-blocker is not reachable – try again in a moment"), 504: t("asn-blocker is not reachable – try again in a moment"),
  503: t("asn-blocker is busy – try again in a moment"), 413: t("The request is too large"),
}[status]);

// The control that was pressed last: a write that starts within a moment of the click shows its progress there.
let trigger = null;
const TRIGGER_MS = 3000;
export const getTrigger = () => trigger;
export const setTrigger = (t_) => { trigger = t_; };
const currentTrigger = () => (trigger && performance.now() - trigger.at < TRIGGER_MS && trigger.el.isConnected ? trigger.el : null);
const isBusy = (el) => !!el && el.getAttribute("aria-busy") === "true";
const PRESSABLE = "button, a.btn, [role=button], input[type=submit]";
// capture phase: before any handler – a busy button swallows further clicks (no double requests)
document.addEventListener("click", (e) => {
  const el = e.target instanceof Element ? e.target.closest(PRESSABLE) : null;
  if (!el) return;
  if (isBusy(el)) { e.preventDefault(); e.stopImmediatePropagation(); return; }
  trigger = { el, at: performance.now() };
}, true);
// a setting that saves itself on change (a select, a checkbox) is no button: its request shows no spinner
for (const type of ["change", "input"]) document.addEventListener(type, (e) => { if (!(e.target instanceof HTMLButtonElement)) trigger = null; }, true);
document.addEventListener("submit", (e) => {
  const sub = e.submitter || e.target.querySelector?.("[type=submit], button:not([type])");
  if (sub && isBusy(sub)) { e.preventDefault(); e.stopImmediatePropagation(); return; }
  if (sub) trigger = { el: sub, at: performance.now() };
}, true);

// Spinner on the button while its work runs (same size, no second click), then briefly green or red.
const busyCount = new WeakMap();
export function trackButton(btn, work) {
  const n = (busyCount.get(btn) || 0) + 1;
  busyCount.set(btn, n);
  if (n === 1) {
    const w = btn.getBoundingClientRect().width;
    if (w) btn.style.minWidth = w + "px";
    btn.setAttribute("aria-busy", "true"); btn.classList.add("is-busy");
  }
  const end = (ok) => {
    const left = (busyCount.get(btn) || 1) - 1;
    busyCount.set(btn, left);
    if (left) return;
    btn.removeAttribute("aria-busy"); btn.classList.remove("is-busy"); btn.style.minWidth = "";
    if (!btn.isConnected) return;
    const cls = ok ? "did-work" : "did-fail";
    btn.classList.remove("did-work", "did-fail"); void btn.offsetWidth; btn.classList.add(cls);
    setTimeout(() => btn.classList.remove(cls), ok ? 1200 : 1600);
  };
  work.then(() => end(true), () => end(false));
}

const inflight = new Map();
const TIMEOUT = { read: 30000, write: 90000 };

async function request(path, { method, body, timeout }) {
  const ctrl = new AbortController(), write = method !== "GET";
  const timer = setTimeout(() => ctrl.abort(), timeout ?? (write ? TIMEOUT.write : TIMEOUT.read));
  let res;
  try {
    res = await fetch("/api" + path, {
      method, credentials: "same-origin", signal: ctrl.signal,
      headers: { "X-Requested-With": "asn-blocker", ...(body !== undefined ? { "Content-Type": "application/json" } : {}) },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    clearTimeout(timer);
    throw new Error(e.name === "AbortError" ? t("No answer from asn-blocker – the request timed out") : t("No connection to asn-blocker – check your network"));
  }
  try {
    if (res.status === 401 && path !== "/login") { onSignedOut(); throw new Error(t("Not signed in")); }
    let data;
    try { data = res.headers.get("content-type")?.includes("json") ? await res.json() : await res.text(); }
    catch { throw new Error(statusText(res.status) || t("The answer was incomplete – please try again")); }
    if (!res.ok) {
      const d = data?.detail;
      const raw = Array.isArray(d) ? d.map((x) => t(x.msg?.replace(/^Value error, /, "") ?? "")).join("; ")
        : d && typeof d === "object" ? d.message : typeof d === "string" ? t(d) : typeof data === "string" ? data : "";
      const err = new Error(statusText(res.status) || cleanMessage(raw) || t(res.statusText) || t("Request failed ({status})", { status: res.status }));
      err.status = res.status; err.detail = d;
      throw err;
    }
    return data;
  } finally { clearTimeout(timer); }
}

// The only way to the server. Changes are never repeated automatically; the same change twice at once (double click,
// Enter held down) is one request that both callers get the answer of.
export function api(path, { method = "GET", body, timeout, button } = {}) {
  const write = method !== "GET";
  const sig = write ? `${method} ${path} ${body === undefined ? "" : JSON.stringify(body)}` : "";
  const running = sig && inflight.get(sig);
  if (running) return running;
  const p = request(path, { method, body, timeout });
  if (sig) { inflight.set(sig, p); const done = () => inflight.delete(sig); p.then(done, done); }
  const btn = button === false ? null : button || (write ? currentTrigger() : null);
  if (btn) trackButton(btn, p);
  return p;
}

// --- Store -----------------------------------------------------------------------------------------------------
// One object of app-wide state; components read a slice with useStore() and re-render when it changes.
const state = { session: null, ov: null, live: null, route: { view: "overview", arg: undefined }, toasts: [] };
const listeners = new Set();
export const getState = () => state;
export function setState(patch) {
  Object.assign(state, typeof patch === "function" ? patch(state) : patch);
  for (const l of [...listeners]) l();
}
export function useStore(select) {
  const [value, set] = useState(() => select(state));
  const sel = useRef(select);
  sel.current = select;
  useEffect(() => {
    const l = () => set(() => sel.current(state));
    listeners.add(l);
    l();
    return () => listeners.delete(l);
  }, []);
  return value;
}

// Loads data for a view: [data, reload, error]; reload() keeps the old data on screen until the new one is there
export function useLoad(fn, deps = []) {
  const [st, set] = useState({ data: undefined, error: null });
  const seq = useRef(0);
  const load = useCallback(async () => {
    const my = ++seq.current;
    try {
      const data = await fn();
      if (my === seq.current) set({ data, error: null });
    } catch (e) {
      if (my === seq.current) set((s) => ({ data: s.data, error: e }));
    }
  }, deps);  // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { load(); }, [load]);
  return [st.data, load, st.error];
}
