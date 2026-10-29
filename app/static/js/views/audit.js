// Log: who changed what, and when.
import { api, fmtTime, html, t, useLoad } from "../lib.js";

const auditName = (a) => ({ "asn.put": t("ASN rule saved"), "asn.delete": t("ASN rule removed"), "vpn.put": t("VPN exemptions changed"),
  "exemption.add": t("Exemption added"), "exemption.delete": t("Exemption removed"), "watch.add": t("Watched IP added"),
  "watch.delete": t("Watched IP removed"), "settings.put": t("Settings changed"), "notify.put": t("Notifications changed"), "crowdsec.put": t("CrowdSec connection changed"),
  "crowdsec.cleanup": t("Old decisions removed"), "run.apply": t("Run started"), login: t("Signed in"), "setup.auth": t("Initial setup"),
  "account.password": t("Password changed"), import: t("Configuration imported"),
  "protect.add": t("Self-protection added"), "protect.delete": t("Self-protection removed"), "protect.mode": t("Self-protection changed"), "asn.expired": t("Rules expired"),
  "proxy.trust": t("Proxy trusted"), "proxy.names_learned": t("Proxy container name learned"), "routing.refresh": t("Routing table loaded on demand") }[a] ?? a);

function detail(d) {
  if (!d) return "";
  try {
    const o = JSON.parse(d);
    return (Array.isArray(o) ? o.map((x) => (x.asn ? `AS${x.asn} ${x.action}` : JSON.stringify(x))).join(", ")
      : Object.entries(o).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(",") : v}`).join(" ")).slice(0, 200);
  } catch { return d; }
}

export function Audit() {
  const [rows] = useLoad(() => api("/audit"));
  if (!rows) return html`<p class="muted">${t("Loading …")}</p>`;
  return html`<div class="box table-wrap">${rows.length ? html`<table><thead><tr><th>${t("Time")}</th><th>${t("User")}</th><th>${t("Action")}</th><th>${t("Details")}</th></tr></thead><tbody>
    ${rows.map((r) => html`<tr key=${r.id}><td class="mono small">${fmtTime(r.ts)}</td><td>${r.user}</td><td>${auditName(r.action)}</td><td class="mono small muted">${detail(r.detail)}</td></tr>`)}</tbody></table>`
    : html`<div class="empty">${t("No entries yet.")}</div>`}</div>`;
}
