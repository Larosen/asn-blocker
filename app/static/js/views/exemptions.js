// Exemptions: self-protection, exempt ASNs, exempt networks and watched IPs.
import { refreshOverview } from "../app-state.js";
import { api, html, t, useLoad } from "../lib.js";
import { confirmDlg, guard, StatusTag, toast } from "../ui.js";

const modeName = (m) => (m === "captcha" ? t("at most captcha") : t("never blocked"));

function Removable({ rows, kind, cols, onRemove }) {
  if (!rows.length) return null;
  return html`<div class="table-wrap"><table><tbody>${rows.map((r) => html`<tr key=${r.value ?? r.ip}>${cols(r)}
    <td class="actions"><button class="btn ghost sm danger" data-del=${kind} aria-label=${t("Remove {v}", { v: r.value ?? r.ip })} onClick=${() => onRemove(r)}>${t("Remove")}</button></td></tr>`)}</tbody></table></div>`;
}

// A one-line form: value (+ note) and a button
function AddForm({ id, placeholder, label, note, onAdd, children }) {
  const submit = guard(async (e) => {
    e.preventDefault();
    const f = e.target;
    await onAdd(f.v.value.trim(), f.n?.value ?? "", f);
    f.reset();
  });
  return html`<form class="row pad-sm" id=${id} onSubmit=${submit}><input type="text" name="v" class="mono" placeholder=${placeholder} required aria-label=${label} />
    ${note ? html`<input type="text" name="n" placeholder=${note} aria-label=${t("Note")} />` : null}${children}<button class="btn">${t("Add")}</button></form>`;
}

export function Exemptions() {
  const [d, reload] = useLoad(() => Promise.all([api("/exemptions"), api("/watch"), api("/protect")]));
  if (!d) return html`<p class="muted">${t("Loading …")}</p>`;
  const [ex, watch, prot] = d;
  const re = () => { refreshOverview(); reload(); };
  const asns = ex.filter((e) => e.kind === "asn"), cidrs = ex.filter((e) => e.kind === "cidr");
  const protectedIps = new Set(prot.protected.filter((r) => r.kind === "ip").map((r) => r.value));
  const doProtect = guard(async (ip, withAsn = false, mode = "captcha") => {
    const r = await api("/protect", { method: "POST", body: { ip, with_asn: withAsn, asn_mode: mode } });
    toast(r.asns.length ? t("{ip} and {asns} protected ({mode})", { ip, asns: r.asns.map((a) => "AS" + a).join(", "), mode: modeName(mode) }) : t("{ip} protected", { ip }));
    re();
  });
  const setMode = guard(async (r, mode) => {
    if (r.mode === mode) return;
    await api(`/protect/asn/${r.value}`, { method: "PUT", body: { mode } });
    toast(t("AS{asn}: {mode} – takes effect with the next run", { asn: r.value, mode: modeName(mode) })); re();
  });
  const unprotect = guard(async (r) => {
    if (!(await confirmDlg(t("Remove protection"), t("{v} can then be blocked again. Continue?", { v: r.value }), t("Remove"), "danger"))) return;
    await api(`/protect/${r.kind}/${r.value}`, { method: "DELETE" }); re();
  });
  const del = (path) => guard(async () => { await api(path, { method: "DELETE" }); re(); });
  const add = (kind) => async (value, note) => { await api("/exemptions", { method: "POST", body: { kind, value, note } }); re(); };

  return html`
    <div class="section"><div class="section-head"><div><h2>${t("Self-protection")}</h2>
        <p class="small muted">${t("Protected IPs are never blocked – not via Spamhaus and not after confirming a sanity check; active SSH sessions on the host are protected automatically. A protected ASN is either never blocked or at most put behind a captcha – firewall bouncers ignore captchas, so SSH stays reachable. CrowdSec keeps banning single attacking IPs from every network either way.")}</p></div>
        ${prot.client_ip && !protectedIps.has(prot.client_ip) ? html`<button class="btn" data-protect=${prot.client_ip} onClick=${() => doProtect(prot.client_ip)}>${t("Protect my browser IP {ip}", { ip: prot.client_ip })}</button>` : null}</div>
      <div class="box">
        <div class="pad-sm row"><h3 class="inline-h">${t("Active SSH sessions")}</h3>
          ${prot.utmp === "ok" ? html`<span class="tag ok">${t("detected")}</span>` : html`<span class="tag captcha">${t("not available")}</span>`}</div>
        ${prot.utmp !== "ok" ? html`<div class="note warn small">${t("To protect SSH sessions automatically, mount the host's session registry read-only:")} <code>- /run/systemd/sessions:/host/sessions:ro</code> ${t("(older systems without systemd-logind:")} <code>- /var/run/utmp:/host/utmp:ro</code>). ${t("Or run this in your SSH session:")} <code>docker exec -e SSH_CLIENT asn-blocker python -m app.cli protect</code></div>`
          : prot.sessions.length ? html`<div class="table-wrap"><table><tbody>${prot.sessions.map((s) => html`<tr><td class="mono">${s.ip}</td><td class="hide-sm">${s.user}@${s.line}</td>
              <td>${s.asns.length ? s.asns.map((a, i) => html`${i ? html`<br />` : null}<span class="mono">AS${a.asn}</span> ${a.name} ${a.protected ? html`<span class=${"tag " + (a.protected === "captcha" ? "captcha" : "ok")}>${modeName(a.protected)}</span>` : null}`) : "–"}</td>
              <td><${StatusTag} s=${s.status || "clear"} /></td>
              <td class="actions">${protectedIps.has(s.ip) ? html`<span class="tag ok">${t("IP protected")}</span>` : html`<button class="btn sm" data-protect=${s.ip} onClick=${() => doProtect(s.ip)}>${t("Protect IP permanently")}</button>`}</td></tr>`)}</tbody></table></div>`
          : html`<div class="empty">${t("No remote SSH session active.")}</div>`}
        <div class="pad-sm"><h3 class="inline-h">${t("Permanently protected")}</h3></div>
        ${prot.protected.length ? html`<div class="table-wrap"><table><tbody>${prot.protected.map((r) => html`<tr key=${r.kind + r.value}><td>${r.kind === "asn" ? "ASN" : "IP"}</td><td class="mono">${r.kind === "asn" ? "AS" : ""}${r.value}</td>
            <td>${r.name || ""}${r.kind === "asn" ? html`<div class="seg mt-xs" role="group" aria-label=${t("Protection of AS{asn}", { asn: r.value })}>
              <button type="button" data-pmode=${r.value + ":captcha"} aria-pressed=${r.mode === "captcha"} title=${t("May be put behind a captcha, never blocked")} onClick=${() => setMode(r, "captcha")}>${t("at most captcha")}</button>
              <button type="button" data-pmode=${r.value + ":exempt"} aria-pressed=${r.mode !== "captcha"} title=${t("Cut out of every block and captcha")} onClick=${() => setMode(r, "exempt")}>${t("never blocked")}</button></div>` : null}</td>
            <td class="muted small hide-sm">${r.note}</td>
            <td class="actions"><button class="btn ghost sm danger" data-unprotect=${r.kind + "/" + r.value} aria-label=${t("Remove {v}", { v: r.value })} onClick=${() => unprotect(r)}>${t("Remove")}</button></td></tr>`)}</tbody></table></div>`
          : html`<div class="empty">${t("Nothing protected yet. Home connections change their IP – protect the ASN of your provider with “at most captcha”.")}</div>`}
        <${ProtectForm} onProtect=${doProtect} />
      </div></div>
    <div class="section"><div class="section-head"><div><h2>${t("Exempt ASNs")}</h2><p class="small muted">${t("Prefixes of these ASNs are never blocked, e.g. VPN providers’ exit networks.")}</p></div></div>
      <div class="box"><${Removable} rows=${asns} kind="asn" onRemove=${(r) => del(`/exemptions/asn/${encodeURIComponent(r.value)}`)()}
          cols=${(r) => html`<td class="mono">AS${r.value}</td><td>${r.name}</td><td class="muted hide-sm">${r.note}</td>`} />
        <${AddForm} id="add-asn" placeholder="AS207137" label="ASN" note=${t("Note")} onAdd=${add("asn")} /></div></div>
    <div class="section"><div class="section-head"><div><h2>${t("IPs and networks")}</h2><p class="small muted">${t("Single addresses or CIDRs, IPv4 and IPv6.")}</p></div></div>
      <div class="box"><${Removable} rows=${cidrs} kind="cidr" onRemove=${(r) => del(`/exemptions/cidr/${r.value}`)()}
          cols=${(r) => html`<td class="mono">${r.value}</td><td class="muted hide-sm">${r.note}</td>`} />
        <${AddForm} id="add-cidr" placeholder=${t("203.0.113.7 or 198.51.100.0/24")} label=${t("IP or CIDR")} note=${t("Note")} onAdd=${add("cidr")} /></div></div>
    <div class="section"><div class="section-head"><div><h2>${t("Watched IPs")}</h2><p class="small muted">${t("Checked on every run. If one would be affected, it shows in the run log and you get notified. They are not exemptions.")}</p></div></div>
      <div class="box"><${Removable} rows=${watch} kind="watch" onRemove=${(r) => del(`/watch/${encodeURIComponent(r.ip)}`)()}
          cols=${(r) => html`<td class="mono">${r.ip}</td><td class="muted hide-sm">${r.note}</td><td><${StatusTag} s=${r.last_status} /></td>`} />
        <${AddForm} id="add-watch" placeholder=${t("IP address")} label="IP" note=${t("Note, e.g. phone")} onAdd=${async (ip, note) => { await api("/watch", { method: "POST", body: { ip, note } }); re(); }} /></div></div>`;
}

function ProtectForm({ onProtect }) {
  const submit = (e) => { e.preventDefault(); const f = e.target; onProtect(f.v.value.trim(), f.asn.checked, f.mode.value); };
  return html`<form class="row pad-sm" id="add-protect" onSubmit=${submit}><input type="text" name="v" class="mono" placeholder=${t("IP address")} required aria-label="IP" />
    <label class="check-inline"><input type="checkbox" name="asn" onChange=${(e) => { e.target.form.mode.disabled = !e.target.checked; }} /> ${t("also its ASN:")}</label>
    <select name="mode" aria-label=${t("Protection of the ASN")} disabled><option value="captcha">${t("at most captcha")}</option><option value="exempt">${t("never blocked")}</option></select>
    <button class="btn">${t("Protect")}</button></form>`;
}
