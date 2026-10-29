// ASNs: search, the rules table (action, lifetime, note, bulk changes), suggested lists and pasting a list.
import { addAsnRule, expiresIn, putRules } from "../actions.js";
import { refreshOverview } from "../app-state.js";
import { act, ago, api, fmtAddr, fmtNum, fmtTime, getState, html, t, tx, useEffect, useLoad, useRef, useState } from "../lib.js";
import { ClassTag, confirmDlg, dialog, guard, SegAction, toast } from "../ui.js";

const LIFETIMES = [["", "Permanent"], ["7", "7 days"], ["30", "30 days"], ["90", "90 days"], ["365", "1 year"]];
const fields = (r) => ({ asn: r.asn, name: r.name, action: r.action, note: r.note, expires_at: r.expires_at ?? null });

// Rule lifetime: permanent, or removed automatically after a number of days (and released on the next run)
function Expiry({ r, onPick }) {
  return html`<select class="inline" data-exp aria-label=${t("Lifetime of AS{asn}", { asn: r.asn })} title=${r.expires_at ? fmtTime(r.expires_at) : ""}
      onChange=${(e) => e.target.value !== "keep" && onPick(e.target.value)}>
    ${r.expires_at ? html`<option value="keep" selected>${ago(r.expires_at)}</option>` : null}
    ${LIFETIMES.map(([v, l]) => html`<option value=${v} selected=${!r.expires_at && !v}>${t(l)}</option>`)}</select>`;
}

function Search({ rules, reload }) {
  const [q, setQ] = useState(""), [res, setRes] = useState(null), [open, setOpen] = useState(false);
  const seq = useRef(0), box = useRef(null), input = useRef(null);
  const search = async (term) => {
    const my = ++seq.current;
    if (!term) { setOpen(false); return; }
    let r;
    try { r = await api("/asn/search?q=" + encodeURIComponent(term)); } catch (e) { r = { error: e.message }; }
    if (my !== seq.current) return;
    setRes(r); setOpen(true);
  };
  useEffect(() => { const timer = setTimeout(() => search(q.trim()), 200); return () => clearTimeout(timer); }, [q]);
  useEffect(() => {
    const close = (e) => { if (!box.current?.contains(e.target)) setOpen(false); };
    document.addEventListener("click", close);
    const take = () => {  // a search handed over by the command palette
      const req = getState().request;
      if (req?.search) { getState().request = null; setQ(req.search); input.current?.focus(); }
    };
    take();
    window.addEventListener("asnb-request", take);
    return () => { document.removeEventListener("click", close); window.removeEventListener("asnb-request", take); };
  }, []);
  const add = guard(async (r, action) => {
    if (!(await addAsnRule(r, action))) return;
    await reload();
    toast(t("AS{asn} added", { asn: r.asn }));
    search(q.trim());
  });
  let content = null;
  if (res?.error) content = html`<div class="empty">${res.error}</div>`;
  else if (res && res.length === 1 && res[0].asn === null) {
    const v = res[0].via;
    content = html`<div class="empty">${tx("{ip} is not announced by any network right now, so there is no ASN to block.", { ip: html`<code>${v.ip}</code>` })}
      ${v.holder ? html`<br />${t("Registered to: {holder}", { holder: v.holder })}` : null}</div>`;
  } else if (res) {
    content = res.length ? res.map((r, i) => html`<div class="item" data-i=${i}><span class="mono">AS${r.asn}</span>
        <span>${r.name} ${r.cc ? html`<span class="muted small">${r.cc}</span>` : null}${r.via ? html`<br /><span class="muted small">${t("IP {ip} is in {prefix}", { ip: r.via.ip, prefix: r.via.prefix || "?" })}</span>` : null}</span>
        <span class="hide-sm"><${ClassTag} c=${r.class} /></span>
        <span class="row">${r.rule ? html`<span class=${"tag " + r.rule}>${act(r.rule)}</span>`
          : html`<button class="btn sm" data-a="ban" onClick=${() => add(r, "ban")}>${t("Block")}</button><button class="btn sm" data-a="captcha" onClick=${() => add(r, "captcha")}>${t("Captcha")}</button>`}</span></div>`)
      : html`<div class="empty">${t("No ASN found.")}</div>`;
  }
  return html`<div class="section"><div class="search" id="search" ref=${box}>
      <input type="search" id="q" ref=${input} value=${q} placeholder=${t("Search ASN – number, name or an IP, e.g. hetzner, AS16509, 8.8.8.8")} autocomplete="off"
        aria-label=${t("Search ASN")} aria-controls="suggest" onInput=${(e) => setQ(e.target.value)} onKeyDown=${(e) => e.key === "Escape" && setOpen(false)} />
      <div class="suggest box" id="suggest" hidden=${!open || !q.trim()}>${content}</div></div></div>`;
}

export function Asns() {
  const [rules, reload] = useLoad(() => api("/asns"));
  const [filter, setFilter] = useState(""), [selected, setSelected] = useState(() => new Set());
  const reloadAll = async () => { await reload(); refreshOverview(); };
  const save = async (rs) => { if (await putRules("/asns", rs.map(fields))) await reloadAll(); };
  useEffect(() => { if (rules?.some((r) => !r.stats)) api("/asns/stats", { method: "POST" }).then(reload).catch(() => {}); }, [rules === undefined]);

  // Review a list of rules before importing it (paste and suggestions)
  const reviewImport = async (preview, { title, note = null, chooseAction = false } = {}) => {
    const exist = new Set((rules || []).map((r) => r.asn));
    const ok = await dialog({ title: title || t("Import {n} ASNs", { n: preview.length }), body: html`${note}
      ${chooseAction ? html`<label class="field"><span>${t("Action")}</span><select id="sugg-action">
        ${["ban", "captcha"].map((a) => html`<option value=${a} selected=${(preview[0]?.action || "ban") === a}>${act(a)}</option>`)}</select></label>` : null}
      <table><tbody>${preview.map((p) => html`<tr><td class="mono">AS${p.asn}</td><td>${p.name}</td><td class="small muted">${p.note}</td><td>${exist.has(p.asn) ? html`<span class="tag">${t("replaced")}</span>` : null}</td></tr>`)}</tbody></table>`,
      actions: [["cancel", t("Cancel")], ["ok", t("Import"), "primary"]] });
    if (ok !== "ok") return;
    if (chooseAction) { const a = document.getElementById("sugg-action").value; preview = preview.map((p) => ({ ...p, action: a })); }
    if (!(await putRules("/asns", preview))) return;
    toast(t("{n} ASNs imported", { n: preview.length }));
    await reloadAll();
    api("/asns/stats", { method: "POST" }).then(reload).catch(() => {});
  };

  // Paste a list: one ASN per line, optional comment
  const paste = guard(async () => {
    const v = await dialog({ title: t("Paste list"), body: html`<p class="small muted">${t("One ASN per line, optionally with a comment:")} <code>16509   # Amazon AWS</code>. ${t("Commented-out lines are skipped.")}</p>
      <label class="field"><span class="sr-only">${t("ASN list")}</span><textarea id="paste-text" placeholder=${"15169    # Google\nAS8075 Microsoft"}></textarea></label>
      <label class="field"><span>${t("Action")}</span><select id="paste-action"><option value="ban">${t("Block")}</option><option value="captcha">${t("Captcha")}</option></select></label>`,
      actions: [["cancel", t("Cancel")], ["ok", t("Preview"), "primary"]] });
    if (v !== "ok") return;
    const preview = await api("/asns/parse", { method: "POST", body: { text: document.getElementById("paste-text").value, action: document.getElementById("paste-action").value } });
    if (!preview.length) return toast(t("No ASNs recognised"), true);
    await reviewImport(preview);
  });

  // Curated starting points
  const suggest = guard(async () => {
    const sg = await api("/asns/suggestions");
    const card = (l) => {
      const fresh = l.asns.filter((a) => !a.present && !a.protected).length;
      return html`<div class="box pad sugg"><div class="row"><h3>${t(l.title)}</h3><span class="spacer"></span>
        <button class="btn sm" value=${l.id} disabled=${!fresh}>${fresh ? t("Review {n} ASNs", { n: fresh }) : t("All added")}</button></div>
        <p class="small">${t(l.description)}</p><div class="note warn small">${t(l.warning)}</div>
        <p class="small muted mono">${l.asns.map((a) => `AS${a.asn} ${a.note}`).join(" · ")}</p></div>`;
    };
    const v = await dialog({ title: t("Suggested lists"), body: html`<p class="small muted">${t("Not sure where to start? Pick a list – you review every ASN before anything is added.")}</p>
      <div class="box pad sugg"><div class="row"><h3>Spamhaus ASN-DROP</h3><span class="spacer"></span>
        <button class="btn sm" value="spamhaus" disabled=${!!sg.spamhaus}>${sg.spamhaus ? t("Active") : t("Block automatically")}</button></div>
        <p class="small">${t("Networks run entirely by cybercriminals, maintained by Spamhaus and refreshed on every run. A safe first step.")}</p></div>
      ${sg.lists.map(card)}`, actions: [["cancel", t("Close")]] });
    if (v === "spamhaus") {
      const s = await api("/settings");
      const keep = ["interval_hours", "decision_hours", "include_ipv6", "sanity_percent", "trusted_proxies", "auth_user_header"];
      await api("/settings", { method: "PUT", body: { ...Object.fromEntries(keep.map((k) => [k, s[k]])), spamhaus_asndrop: "ban" } });
      toast(t("Spamhaus ASN-DROP enabled – takes effect with the next run")); refreshOverview();
      return;
    }
    const l = sg.lists.find((x) => x.id === v);
    if (!l) return;
    const skipped = l.asns.filter((a) => a.protected);
    const preview = l.asns.filter((a) => !a.present && !a.protected).map((a) => ({ asn: a.asn, name: a.name, note: a.note, action: l.action }));
    await reviewImport(preview, { title: t(l.title), chooseAction: true, note: html`<div class="note warn small">${t(l.warning)}</div>
      ${skipped.length ? html`<p class="small muted">${t("Skipped because protected: {list}", { list: skipped.map((a) => `AS${a.asn}`).join(", ") })}</p>` : null}` });
  });

  useEffect(() => {  // "Suggested ASN lists" / "Paste ASN list" from the command palette
    const take = () => {
      const req = getState().request;
      if (!req?.open || rules === undefined) return;
      getState().request = null;
      (req.open === "paste" ? paste : suggest)();
    };
    take();
    window.addEventListener("asnb-request", take);
    return () => window.removeEventListener("asnb-request", take);
  }, [rules === undefined]);

  if (!rules) return html`<p class="muted">${t("Loading …")}</p>`;
  const f = filter.toLowerCase();
  const visible = rules.filter((r) => !f || `as${r.asn} ${r.name} ${r.note}`.toLowerCase().includes(f));
  const sel = new Set([...selected].filter((a) => rules.some((r) => r.asn === a)));
  const pick = rules.filter((r) => sel.has(r.asn));
  const allSel = visible.length > 0 && visible.every((r) => sel.has(r.asn)), someSel = !allSel && visible.some((r) => sel.has(r.asn));
  const toggle = (asn, on) => setSelected((s) => { const n = new Set(s); on ? n.add(asn) : n.delete(asn); return n; });
  const bulk = guard(async (what) => {
    if (what === "clear") { setSelected(new Set()); return; }
    if (what === "delete") {
      if (!(await confirmDlg(t("Remove rules"), t("Remove {n} ASN rules? Their ranges are released on the next apply.", { n: pick.length }), t("Remove"), "danger"))) return;
      await api("/asns/delete", { method: "POST", body: { asns: pick.map((r) => r.asn) } });
      setSelected(new Set()); await reloadAll(); toast(t("{n} rules removed", { n: pick.length })); return;
    }
    await save(pick.map((r) => ({ ...r, action: what })));
    toast(t("{n} rules changed", { n: pick.length }));
  });
  const remove = guard(async (r) => {
    if (!(await confirmDlg(t("Remove rule"), t("Remove AS{asn} {name}? Its ranges are released on the next apply.", { asn: r.asn, name: r.name }), t("Remove"), "danger"))) return;
    await api("/asns/" + r.asn, { method: "DELETE" }); await reloadAll();
  });
  const setLifetime = guard(async (r, d) => {
    await save([{ ...r, expires_at: expiresIn(d) }]);
    toast(d ? t("AS{asn} expires {when}", { asn: r.asn, when: ago(expiresIn(d)) }) : t("AS{asn} is permanent", { asn: r.asn }));
  });
  const setNote = guard(async (r, note) => { await save([{ ...r, note }]); toast(t("Note saved")); });

  return html`<${Search} rules=${rules} reload=${reloadAll} />
    <div class="section"><div class="section-head"><div><h2>${t("Rules")}</h2><p class="small muted">${t("New rules take effect after “Apply”.")}</p></div>
      <div class="row"><input type="search" id="filter" value=${filter} placeholder=${t("Filter")} aria-label=${t("Filter rules")} onInput=${(e) => setFilter(e.target.value)} />
        <button class="btn" id="suggest-btn" onClick=${suggest}>${t("Suggestions")}</button><button class="btn" id="paste" onClick=${paste}>${t("Paste list")}</button></div></div>
      <div class="bulk row" id="bulk" hidden=${!sel.size}><span id="bulk-count">${t("{n} selected", { n: sel.size })}</span><span class="spacer"></span>
        <button class="btn sm" data-bulk="ban" onClick=${() => bulk("ban")}>${t("Block")}</button><button class="btn sm" data-bulk="captcha" onClick=${() => bulk("captcha")}>${t("Captcha")}</button>
        <button class="btn sm danger" data-bulk="delete" onClick=${() => bulk("delete")}>${t("Remove")}</button><button class="btn sm ghost" data-bulk="clear" onClick=${() => bulk("clear")}>${t("Clear selection")}</button></div>
      <div class="box table-wrap" id="rules">${rules.length ? html`<table><thead><tr>
          <th class="sel"><input type="checkbox" id="sel-all" aria-label=${t("Select all")} checked=${allSel} indeterminate=${someSel}
            onChange=${(e) => setSelected((s) => { const n = new Set(s); visible.forEach((r) => (e.target.checked ? n.add(r.asn) : n.delete(r.asn))); return n; })} /></th>
          <th>ASN</th><th>${t("Name")}</th><th class="hide-sm">${t("Type")}</th><th class="num hide-sm">${t("Prefixes")}</th><th class="num hide-sm">${t("IPv4 addresses")}</th>
          <th>${t("Action")}</th><th class="hide-sm">${t("Expires")}</th><th>${t("Note")}</th><th><span class="sr-only">${t("Remove")}</span></th></tr></thead><tbody>
        ${visible.map((r) => html`<tr key=${r.asn} data-asn=${r.asn}>
          <td class="sel"><input type="checkbox" data-sel checked=${sel.has(r.asn)} aria-label=${t("Select AS{asn}", { asn: r.asn })} onChange=${(e) => toggle(r.asn, e.target.checked)} /></td>
          <td class="mono">AS${r.asn}</td><td>${r.name}${r.cc ? html` <span class="muted small">${r.cc}</span>` : null}</td>
          <td class="hide-sm"><${ClassTag} c=${r.class} /></td>
          <td class="num mono hide-sm">${r.stats ? html`${fmtNum(r.stats.v4)}${r.stats.v6 ? html` <span class="muted">+${r.stats.v6}</span>` : null}` : html`<span class="muted">…</span>`}</td>
          <td class="num mono hide-sm">${r.stats ? fmtAddr(r.stats.addresses) : html`<span class="muted">…</span>`}</td>
          <td><${SegAction} value=${r.action} onPick=${guard((a) => a !== r.action && save([{ ...r, action: a }]))} /></td>
          <td class="hide-sm"><${Expiry} r=${r} onPick=${(d) => setLifetime(r, d)} /></td>
          <td><input class="inline" data-note value=${r.note} placeholder="—" aria-label=${t("Note for AS{asn}", { asn: r.asn })} onChange=${(e) => setNote(r, e.target.value)} /></td>
          <td class="actions"><button class="btn ghost sm danger" data-del aria-label=${t("Remove AS{asn}", { asn: r.asn })} onClick=${() => remove(r)}>${t("Remove")}</button></td></tr>`)}
        </tbody></table>` : html`<div class="empty">${t("No ASNs yet. Search above, paste an existing list, or start with the suggestions.")} <button class="btn sm" id="suggest-empty" onClick=${suggest}>${t("Show suggestions")}</button></div>`}</div></div>`;
}
