// VPN exemptions: per provider, the countries whose servers stay reachable.
import { refreshOverview } from "../app-state.js";
import { api, continentName, CONTINENTS, html, locale, t, tx, useLoad, useState } from "../lib.js";
import { guard, toast } from "../ui.js";

function Countries({ p, countries, chosen, setChosen }) {
  const [filter, setFilter] = useState("");
  const f = filter.toLowerCase();
  const list = countries.filter((c) => !f || c.name.toLowerCase().includes(f) || c.code.toLowerCase() === f);
  const groups = CONTINENTS.map((k) => [k, list.filter((c) => (c.continent || "") === k).sort((a, b) => a.name.localeCompare(b.name, locale()))]).filter(([, cs]) => cs.length);
  const set = (codes, on) => setChosen((s) => { const n = new Set(s); codes.forEach((c) => (on ? n.add(c) : n.delete(c))); return n; });
  const save = guard(async () => {
    await api(`/vpn/${p.id}`, { method: "PUT", body: { countries: [...chosen], mode: p.mode } });
    toast(t("{name}: {n} countries saved", { name: p.name, n: chosen.size }));
    refreshOverview();
  });
  return html`<div class="box"><div class="row pad-sm" id="ctools"><input type="search" id="cf" value=${filter} placeholder=${t("Filter countries")} aria-label=${t("Filter countries")} onInput=${(e) => setFilter(e.target.value)} />
      <span class="spacer"></span>
      <button class="btn sm ghost" id="none" onClick=${() => setChosen(new Set())}>${t("None")}</button><span class="muted small" id="selcount" aria-live="polite">${t("{n} selected", { n: chosen.size })}</span>
      <button class="btn primary" id="save" onClick=${save}>${t("Save")}</button></div>
    <div class="countries" id="ctry">${groups.length ? groups.map(([k, cs]) => {
      const n = cs.filter((c) => chosen.has(c.code)).length;
      return html`<fieldset class="continent" key=${k}><legend><span>${continentName(k)}</span><span class="muted small">${n ? t("{n} of {m}", { n, m: cs.length }) : cs.length}</span>
          <button type="button" class="btn ghost sm" data-all=${k} onClick=${() => set(cs.map((c) => c.code), n !== cs.length)}>${n === cs.length ? t("none") : t("all")}</button></legend>
        <div class="cgrid">${cs.map((c) => html`<label key=${c.code}><input type="checkbox" value=${c.code} checked=${chosen.has(c.code)} onChange=${(e) => set([c.code], e.target.checked)} />
          <span>${c.name}</span><span class="cc">${c.code} · ${c.servers}</span></label>`)}</div></fieldset>`;
    }) : html`<span class="muted">${t("No match")}</span>`}</div></div>`;
}

export function Vpn({ arg }) {
  const [provs] = useLoad(() => api("/vpn/providers"));
  const p0 = provs && (provs.find((x) => x.id === arg) || provs[0]);
  const [countries, , error] = useLoad(() => (p0 ? api(`/vpn/${p0.id}/countries`) : Promise.resolve(null)), [p0?.id]);
  const [mode, setMode] = useState(null), [chosen, setChosen] = useState(null);
  if (!provs) return html`<p class="muted">${t("Loading …")}</p>`;
  const p = { ...p0, mode: mode ?? p0.mode };
  const sel = chosen ?? new Set(p0.countries);
  const exitAsn = guard(async () => {
    await api("/exemptions", { method: "POST", body: { kind: "asn", value: String(p.exit_asn), note: t("{name} exit IPs", { name: p.name }) } });
    toast(t("AS{asn} saved as exemption", { asn: p.exit_asn })); refreshOverview();
  });
  return html`<p class="muted lead-p">${t("Server IPs of the selected countries are carved out of all blocks so users of these VPN locations get through.")}</p>
    <div class="split"><nav class="box plist" aria-label=${t("VPN providers")}>${provs.map((x) => html`<a href=${"#/vpn/" + x.id} aria-current=${x.id === p.id ? "true" : undefined}>
        <span>${x.name}</span><span class="mono muted small">${x.countries.length || ""}</span></a>`)}</nav>
    <div><div class="box pad"><div class="section-head"><div><h2>${p.name}</h2><p class="small muted">${p.note}</p></div></div>
      <div class="row small"><span id="mode-label">${t("Exempt as")}</span><div class="seg" id="mode" role="group" aria-labelledby="mode-label">
        <button type="button" data-m="exact" aria-pressed=${p.mode === "exact"} onClick=${() => setMode("exact")}>${t("exact server IPs")}</button>
        <button type="button" data-m="net" aria-pressed=${p.mode === "net"} onClick=${() => setMode("net")}>${t("whole network (/24, /64)")}</button></div></div>
      <div class="note warn small" id="netwarn" hidden=${p.mode !== "net"}>${t("VPN servers usually sit at hosting providers. A whole /24 also exempts other servers there – possibly exactly the ones you want to block.")}</div>
      ${p.exit_asn ? html`<div class="note small">${tx("{name} users often connect from an exit IP next to the listed server IP – choose “whole network” so the /24 is exempted. Other exits are in {asn}.", { name: p.name, asn: html`<code>AS${p.exit_asn}</code>` })}
        <button class="btn sm" id="exitasn" onClick=${exitAsn}>${t("Add AS{asn} as exempt ASN", { asn: p.exit_asn })}</button></div>` : null}
    </div>
    ${error ? html`<div class="box"><div class="note danger">${error.message}</div></div>`
      : countries ? html`<${Countries} p=${p} countries=${countries} chosen=${sel} setChosen=${(fn) => setChosen(fn(sel))} />`
      : html`<div class="box"><div class="countries" id="ctry"><span class="muted">${t("Loading server list …")}</span></div></div>`}</div></div>`;
}
