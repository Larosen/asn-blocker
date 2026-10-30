// Shared UI pieces: toasts, the modal dialog, confirmations and small tags.
import { Icon } from "./icons.js";
import { act, getState, html, render, setState, t, useStore } from "./lib.js";

// --- Toasts ----------------------------------------------------------------------------------------------------
let toastId = 0;
export function toast(msg, error = false) {
  const id = ++toastId;
  setState((s) => ({ toasts: [...s.toasts, { id, msg, error }] }));
  setTimeout(() => setState((s) => ({ toasts: s.toasts.filter((x) => x.id !== id) })), error ? 7000 : 3500);
}
export function Toasts() {
  const toasts = useStore((s) => s.toasts);
  return toasts.map((x) => html`<div key=${x.id} class=${"toast" + (x.error ? " error" : "")} role=${x.error ? "alert" : "status"}>${x.msg}</div>`);
}
// Runs an action; an error becomes a toast instead of an unhandled rejection
export const guard = (fn) => async (...a) => { try { return await fn(...a); } catch (e) { toast(e.message, true); } };

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
  return new Promise((resolve) => {
    dlg.onclose = () => resolve(dlg.returnValue === "cancel" ? "" : dlg.returnValue);
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
