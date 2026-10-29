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

export async function api(path, { method = "GET", body } = {}) {
  const res = await fetch("/api" + path, {
    method, credentials: "same-origin",
    headers: { "X-Requested-With": "asn-blocker", ...(body !== undefined ? { "Content-Type": "application/json" } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401 && path !== "/login") { onSignedOut(); throw new Error(t("Not signed in")); }
  const data = res.headers.get("content-type")?.includes("json") ? await res.json() : await res.text();
  if (!res.ok) {
    const d = data?.detail;
    const err = new Error(Array.isArray(d) ? d.map((x) => t(x.msg?.replace(/^Value error, /, "") ?? "")).join("; ")
      : d && typeof d === "object" ? d.message : t(d || res.statusText));
    err.status = res.status; err.detail = d;
    throw err;
  }
  return data;
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
