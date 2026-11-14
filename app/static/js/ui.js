// Shared UI pieces: toasts, the modal dialog, confirmations and small tags.
import { Icon } from "./icons.js";
import { act, cleanMessage, getState, getTrigger, html, render, setState, setTrigger, t, useStore } from "./lib.js";

// --- Toasts ----------------------------------------------------------------------------------------------------
// toast(text, kind): kind is "success" (default), "info", "warning" or "error"; `true` means error (as before).
// They stack (four at most, the oldest go first), identical ones are not doubled, errors stay longest, every one can be
// closed, and one under the pointer or with focus stays until you are done reading.
const TOAST_MS = { success: 3500, info: 5000, warning: 8000, error: 12000 };
const TOAST_MAX = 4;
let toastId = 0;
const timers = new Map();
const dismiss = (id) => { clearTimeout(timers.get(id)); timers.delete(id); setState((s) => ({ toasts: s.toasts.filter((x) => x.id !== id) })); };
const arm = (x) => { clearTimeout(timers.get(x.id)); timers.set(x.id, setTimeout(() => dismiss(x.id), TOAST_MS[x.kind])); };
const hold = (x) => { clearTimeout(timers.get(x.id)); };
export function toast(msg, kind = "success") {
  const k = kind === true ? "error" : kind === false ? "success" : kind;
  const text = cleanMessage(msg);
  if (!text) return;
  const old = getState().toasts.find((x) => x.msg === text);
  if (old) dismiss(old.id);
  const x = { id: ++toastId, msg: text, kind: k };
  setState((s) => ({ toasts: [...s.toasts, x].slice(-TOAST_MAX) }));
  arm(x);
}
export function Toasts() {
  const toasts = useStore((s) => s.toasts);
  return toasts.map((x) => html`<div key=${x.id} class=${"toast " + x.kind} role=${x.kind === "error" ? "alert" : "status"}
    onMouseEnter=${() => hold(x)} onMouseLeave=${() => arm(x)} onFocusIn=${() => hold(x)} onFocusOut=${() => arm(x)}>
    <span class="toast-text">${x.msg}</span>
    <button type="button" class="toast-x" aria-label=${t("Close message")} title=${t("Close")} onClick=${() => dismiss(x.id)}><${Icon} name="close" /></button></div>`);
}
// Runs an action; an error becomes a toast instead of an unhandled rejection
export const guard = (fn) => async (...a) => { try { return await fn(...a); } catch (e) { toast(e.message, "error"); } };

// --- Lists that load ---------------------------------------------------------------------------------------------
// Grey placeholders in the shape of what is coming – only while nothing is there yet; a failure says so and offers a retry.
export const Skeleton = ({ rows = 4 }) => html`<div class="skeleton-list" aria-hidden="true">${Array.from({ length: rows }, () =>
  html`<div class="skeleton"><span class="sk-line"></span><span class="sk-line short"></span></div>`)}</div>`;
export const Pending = ({ error, retry, rows }) => (error
  ? html`<div class="load-error" role="alert"><span>${t("Could not load: {error}", { error: error.message })}</span>
      <button type="button" class="btn sm" onClick=${() => retry?.()}>${t("Try again")}</button></div>`
  : html`<div role="status" aria-busy="true" aria-label=${t("Loading …")}><${Skeleton} rows=${rows} /></div>`);

// --- Dialog ----------------------------------------------------------------------------------------------------
// One native <dialog>; resolves to the value of the clicked button ("" on cancel/Escape). The content stays rendered
// until the next dialog opens, so callers can read form fields after it closed.
export function dialog({ title, body, actions = [["cancel", t("Cancel")], ["ok", "OK", "primary"]], onOpen }) {
  const dlg = document.getElementById("dlg"), form = document.getElementById("dlg-form");
  render(null, form);
  render(html`<div class="dh"><h2 id="dlg-title">${title}</h2>
    <button type="button" class="icon-btn dlg-x" onClick=${() => closeDialog()} aria-label=${t("Close")} title=${t("Close")}><${Icon} name="close" /></button></div><div class="db">${body}</div>
    <div class="df">${actions.map(([v, l, c]) => html`<button class=${"btn " + (c || "")} value=${v}>${l}</button>`)}</div>`, form);
  dlg.setAttribute("aria-labelledby", "dlg-title");
  const before = getTrigger();   // the button that asked: it shows the progress after the answer, not the dialog's own button
  return new Promise((resolve) => {
    dlg.onclose = () => {
      setTrigger(before?.el.isConnected ? { el: before.el, at: performance.now() } : null);
      resolve(dlg.returnValue === "cancel" ? "" : dlg.returnValue);
    };
    dlg.returnValue = "";
    dlg.showModal();
    // Never start on an action button: a stray Enter must not block a network or change a setting
    dlg.querySelector('.df button[value="cancel"]')?.focus();
    onOpen?.(dlg);
  });
}
export const closeDialog = (value = "cancel") => document.getElementById("dlg").close(value);
export const confirmDlg = (title, text, ok = t("Confirm"), cls = "primary") =>
  dialog({ title, body: html`<p>${text}</p>`, actions: [["cancel", t("Cancel")], ["ok", ok, cls]] }).then((v) => v === "ok");

// --- Tags ------------------------------------------------------------------------------------------------------
export const ClassTag = ({ c }) => (!c || c === "Unknown" ? null : html`<span class="tag" title=${t("Classification by bgp.tools")}>${c}</span>`);
export const StatusTag = ({ s }) => (!s ? html`<span class="muted small">${t("not checked yet")}</span>`
  : s === "ban" || s === "captcha" ? html`<span class=${"tag " + s}>${act(s)}</span>` : html`<span class="tag ok">${t("clear")}</span>`);
export const effectName = (e) => ({ ban: t("Block"), captcha: t("Captcha"), cap: t("At most captcha"), allow: t("Never blocked") }[e] ?? e);
export const EffectTag = ({ e }) => html`<span class=${"tag " + (e === "allow" ? "ok" : e === "cap" ? "captcha" : e)}>${effectName(e)}</span>`;
export const SegAction = ({ value, onPick }) => html`<div class="seg" role="group" aria-label=${t("Action")}>
  ${["ban", "captcha"].map((x) => html`<button type="button" class=${x} data-a=${x} aria-pressed=${value === x} onClick=${() => onPick(x)}>${act(x)}</button>`)}</div>`;
export const Empty = ({ children }) => html`<div class="empty">${children}</div>`;
export const isSignedIn = () => !!getState().session?.user;
