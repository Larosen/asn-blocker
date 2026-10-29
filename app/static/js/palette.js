// Command palette (⌘K / Ctrl+K): every main action from the keyboard.
import { checkIp, startRun } from "./actions.js";
import { nextTheme, THEME_NAMES, theme } from "./app-state.js";
import { getState, html, IP_RE, render, t, useEffect, useRef, useState } from "./lib.js";
import { VIEWS, viewName } from "./views/index.js";

// Opens a view and hands it a request (search for a term, open the suggestions or the paste dialog)
export const goto = (view, request) => { getState().request = request; location.hash = "#/" + view; window.dispatchEvent(new Event("asnb-request")); };

function items(q, signOut) {
  const fixed = VIEWS.map((v) => ({ group: t("Go to"), label: viewName(v), run: () => (location.hash = "#/" + v) }));
  fixed.push(
    { group: t("Actions"), label: t("Apply rules"), hint: t("sync with CrowdSec"), run: () => startRun("apply") },
    { group: t("Actions"), label: t("Preview"), hint: t("compute without changing anything"), run: () => startRun("plan") },
    { group: t("Actions"), label: t("Suggested ASN lists"), run: () => goto("asns", { open: "suggestions" }) },
    { group: t("Actions"), label: t("Paste ASN list"), run: () => goto("asns", { open: "paste" }) },
    { group: t("Actions"), label: t("Change theme"), hint: THEME_NAMES[theme()], run: nextTheme },
  );
  if (getState().session?.auth_mode === "local") fixed.push({ group: t("Actions"), label: t("Sign out"), run: signOut });
  const s = q.trim(), dyn = [];
  if (IP_RE.test(s)) dyn.push({ group: t("Search"), label: t("Check IP {ip}", { ip: s }), hint: t("status, network, rules"), run: () => checkIp(s) },
    { group: t("Search"), label: t("Find the network of {ip}", { ip: s }), run: () => goto("asns", { search: s }) });
  else if (s.length >= 2) dyn.push({ group: t("Search"), label: t("Search ASNs for “{q}”", { q: s }), run: () => goto("asns", { search: s }) });
  const needle = s.toLowerCase();
  if (IP_RE.test(s)) return dyn;
  return [...fixed.filter((i) => !needle || i.label.toLowerCase().includes(needle) || i.group.toLowerCase().includes(needle)), ...dyn];
}

function Palette({ dlg, signOut }) {
  const [q, setQ] = useState(""), [sel, setSel] = useState(0);
  const input = useRef(null), list = useRef(null);
  const all = items(q, signOut), cur = Math.min(sel, Math.max(0, all.length - 1));
  useEffect(() => { list.current?.querySelector(`#cmdk-${cur}`)?.scrollIntoView({ block: "nearest" }); }, [cur, q]);
  // from the field itself: typing can be ahead of the last render (Enter right after the last key)
  const run = (i) => { const now = items(input.current?.value ?? q, signOut), it = now[i] ?? now[0]; if (!it) return; dlg.close(); it.run(); };
  const key = (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setSel((cur + 1) % Math.max(1, all.length)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setSel((cur - 1 + all.length) % Math.max(1, all.length)); }
    else if (e.key === "Enter") { e.preventDefault(); run(e.target.value === q ? cur : 0); }
  };
  let group = "";
  return html`<div class="cmdk-input"><input ref=${input} type="text" role="combobox" aria-expanded="true" aria-controls="cmdk-list" aria-autocomplete="list"
      aria-label=${t("Search or jump to")} placeholder=${t("Type a command, a view, an ASN or an IP …")} autocomplete="off" spellcheck="false"
      aria-activedescendant=${all.length ? `cmdk-${cur}` : ""} value=${q} onInput=${(e) => { setQ(e.target.value); setSel(0); }} onKeyDown=${key} /></div>
    <ul class="cmdk-list" id="cmdk-list" role="listbox" aria-label=${t("Results")} ref=${list}>
      ${all.length ? all.map((it, i) => {
        const head = it.group !== group ? html`<li class="cmdk-group eyebrow" role="presentation">${(group = it.group)}</li>` : null;
        return html`${head}<li class="cmdk-item" role="option" id=${"cmdk-" + i} aria-selected=${i === cur}
          onClick=${() => run(i)} onMouseMove=${() => i !== cur && setSel(i)}>${it.label}${it.hint ? html`<span class="hint">${it.hint}</span>` : null}</li>`;
      }) : html`<li class="empty" role="presentation">${t("No matches")}</li>`}
    </ul>
    <div class="cmdk-foot" aria-hidden="true"><span><kbd>↑</kbd><kbd>↓</kbd>${t("select")}</span><span><kbd>↵</kbd>${t("run")}</span><span><kbd>esc</kbd>${t("close")}</span></div>`;
}

export function openPalette(signOut) {
  let dlg = document.getElementById("cmdk");
  if (dlg?.open) return;
  if (!dlg) {
    dlg = document.createElement("dialog");
    dlg.id = "cmdk";
    dlg.setAttribute("aria-label", t("Command palette"));
    document.body.append(dlg);
    dlg.addEventListener("click", (e) => { if (e.target === dlg) dlg.close(); });  // click on the backdrop
    dlg.addEventListener("close", () => { if (!dlg.open) render(null, dlg); });  // not if it was reopened meanwhile
  }
  render(null, dlg);  // always start empty, even if the last close event has not been handled yet
  render(html`<${Palette} dlg=${dlg} signOut=${signOut} />`, dlg);
  dlg.showModal();
  dlg.querySelector("input")?.focus();
}
