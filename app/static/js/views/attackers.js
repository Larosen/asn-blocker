// Attackers: networks behind CrowdSec's own detections, with a recommendation per ASN.
import { addAsnRule, expiresIn } from "../actions.js";
import { refreshOverview } from "../app-state.js";
import { act, ago, api, fmtNum, fmtTime, html, locale, t, useLoad, useState } from "../lib.js";
import { ClassTag, confirmDlg, dialog, guard, toast } from "../ui.js";

let lastDays = 7, lastLife = "";  // kept while the app is open

function RecTag({ x }) {
  return x.kind === "recommend" ? html`<span class=${"tag " + x.action}>${t("Recommended:")} ${act(x.action)}</span>`
    : x.kind === "active" ? html`<span class=${"tag " + x.action}>${act(x.action)}</span>`
    : x.kind === "protected" ? html`<span class="tag">${t("protected")}</span>` : html`<span class="tag">${t("watch")}</span>`;
}

// Opt-in: recommendations become rules with a lifetime after every collection
function AutoRules({ auto, onSaved }) {
  const submit = guard(async (e) => {
    e.preventDefault();
    const f = new FormData(e.target), mode = f.get("mode") || null, days = Number(f.get("days"));
    if (mode && !auto.mode && !(await confirmDlg(t("Add rules automatically?"),
      t("Every network that is recommended from now on becomes a rule for {d} days and is applied right away – up to 10 per collection. Consumer networks, exempt and protected networks are never added. You get a notification for each batch.", { d: days }),
      t("Switch on")))) return;
    const r = await api("/attackers/auto", { method: "PUT", body: { mode, days } });
    toast(r.added ? t("{n} networks added – they take effect right away", { n: r.added }) : t("Saved")); onSaved();
  });
  return html`<form class="box pad" id="att-auto" onSubmit=${submit}><h2>${t("Automatic rules")}</h2>
    <div class="grid2"><label class="field"><span>${t("Recommended networks")}</span><select name="mode" value=${auto.mode || ""}>
        <option value="">${t("only show them (off)")}</option><option value="captcha">${t("add as captcha")}</option>
        <option value="recommended">${t("add with the recommended action")}</option></select></label>
      <label class="field"><span>${t("Lifetime")}</span><select name="days" value=${String(auto.days)}>
        ${[7, 30, 90].map((d) => html`<option value=${d}>${t("{d} days", { d })}</option>`)}</select>
        <small>${t("Removing an automatic rule keeps the network off for this long.")}</small></label></div>
    <button class="btn primary">${t("Save")}</button></form>`;
}

export function Attackers() {
  const [days, setDays] = useState(lastDays), [life, setLife] = useState(lastLife);
  const [r, reload] = useLoad(() => api(`/attackers?days=${days}`), [days]);
  const pickDays = (d) => { lastDays = d; setDays(d); };
  const refresh = guard(async () => {
    const res = await api("/attackers/refresh", { method: "POST" });
    toast(t("{n} new alerts", { n: res.new_alerts })); reload();
  });
  const add = guard(async (row, action) => {
    if (await addAsnRule({ asn: row.asn, name: row.name, class: row.class }, action, { note: t("attacking network"), expires_at: expiresIn(life) })) {
      toast(t("AS{asn} added – takes effect with the next run", { asn: row.asn })); refreshOverview(); reload();
    }
  });
  const showIps = guard(async (row) => {
    const ips = await api(`/attackers/${row.asn}?days=${days}`);
    await dialog({ title: t("AS{asn} – attacking IPs", { asn: row.asn }),
      body: html`<p class="small">${row.name} · ${t("last {d} days", { d: days })}</p><div class="table-wrap"><table><thead><tr><th>IP</th><th class="num">${t("Alerts")}</th><th>${t("Scenarios")}</th><th>${t("Last seen")}</th></tr></thead><tbody>
        ${ips.map((i) => html`<tr><td class="mono">${i.ip}</td><td class="num mono">${fmtNum(i.alerts)}</td><td class="small mono">${i.scenarios.map((sc) => sc.split("/").pop()).join(", ")}</td><td class="small">${ago(i.last_seen)}</td></tr>`)}</tbody></table></div>`,
      actions: [["cancel", t("Close"), "primary"]] });
  });
  if (!r) return html`<p class="muted">${t("Loading …")}</p>`;
  const since = r.history_since ? new Date(r.history_since + "T00:00:00Z").toLocaleDateString(locale(), { dateStyle: "medium" }) : null;
  return html`<div class="section"><div class="section-head"><div>
      <p class="small muted">${t("Networks whose IPs CrowdSec's own detections caught on this server – community blocklists and manual decisions are not counted. A recommendation appears once a hosting network shows {n} or more attacking IPs; consumer networks are never recommended.", { n: 5 })}</p></div>
      <div class="row"><div class="seg" role="group" aria-label=${t("Period")}>${[7, 30, 90].map((d) => html`<button type="button" data-days=${d} aria-pressed=${d === days} onClick=${() => pickDays(d)}>${t("{d} days", { d })}</button>`)}</div>
        <label class="row small">${t("New rules:")} <select id="att-life" aria-label=${t("Lifetime of new rules")} onChange=${(e) => { lastLife = e.target.value; setLife(e.target.value); }}>
          ${[["", t("Permanent")], ["30", t("30 days")], ["90", t("90 days")]].map(([v, l]) => html`<option value=${v} selected=${v === life}>${l}</option>`)}</select></label>
        <button class="btn" id="att-refresh" onClick=${refresh}>${t("Update")}</button></div></div>
    <${AutoRules} auto=${r.auto} onSaved=${() => { reload(); refreshOverview(); }} />
    ${r.error ? html`<div class="note danger">${t("Could not read CrowdSec's alerts:")} ${r.error}</div>` : null}
    <p class="small muted">${r.updated ? t("Updated {when}", { when: ago(r.updated) }) : t("Not collected yet")}${since ? " · " + t("history since {d} (CrowdSec itself keeps alerts about a week; asn-blocker keeps a summary for 180 days)", { d: since }) : ""}</p>
    <div class="box table-wrap">${r.rows.length ? html`<table><thead><tr><th>ASN</th><th>${t("Name")}</th><th class="num">${t("Attacking IPs")}</th><th class="num hide-sm">${t("Alerts")}</th>
        <th class="hide-sm">${t("Mostly")}</th><th class="hide-sm">${t("Last seen")}</th><th>${t("Recommendation")}</th><th><span class="sr-only">${t("Actions")}</span></th></tr></thead><tbody>
      ${r.rows.map((x) => html`<tr key=${x.asn}><td class="mono">AS${x.asn}</td><td>${x.name || "–"} ${x.cc ? html`<span class="muted small">${x.cc}</span>` : null} <span class="hide-sm"><${ClassTag} c=${x.class} /></span></td>
        <td class="num"><button class="btn ghost sm mono" data-ips=${x.asn} aria-label=${t("Show the {n} IPs of AS{asn}", { n: x.ips, asn: x.asn })} onClick=${() => showIps(x)}>${fmtNum(x.ips)}</button></td>
        <td class="num mono hide-sm">${fmtNum(x.alerts)}</td>
        <td class="small mono hide-sm">${x.scenarios.map((sc) => sc.name.split("/").pop()).join(", ")}</td>
        <td class="small hide-sm" title=${fmtTime(x.last_seen)}>${ago(x.last_seen)}</td>
        <td><${RecTag} x=${x.recommendation} /><div class="small muted">${t(x.recommendation.reason)}</div></td>
        <td class="actions">${x.recommendation.kind === "active" || x.recommendation.kind === "protected" ? null : html`
          <button class=${"btn sm " + (x.recommendation.kind === "recommend" && x.recommendation.action === "ban" ? "danger" : "")} data-add=${"ban:" + x.asn} onClick=${() => add(x, "ban")}>${t("Block")}</button>
          <button class="btn sm" data-add=${"captcha:" + x.asn} onClick=${() => add(x, "captcha")}>${t("Captcha")}</button>`}</td></tr>`)}</tbody></table>`
      : html`<div class="empty">${r.updated ? t("No local detections in this period.") : t("The first collection runs shortly after CrowdSec is connected – or click “Update”.")}</div>`}</div></div>`;
}
