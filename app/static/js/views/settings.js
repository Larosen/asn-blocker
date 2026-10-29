// Settings: CrowdSec connection, schedule and safety, access, notifications, password and maintenance.
import { putRules } from "../actions.js";
import { refreshOverview } from "../app-state.js";
import { ago, api, fmtNum, html, t, tx, useEffect, useLoad, useRef, useState } from "../lib.js";
import { confirmDlg, guard, toast } from "../ui.js";

const values = (form) => Object.fromEntries(new FormData(form));

function CrowdSec({ s, reload }) {
  const [mode, setMode] = useState(s.crowdsec_mode || "lapi");
  const submit = guard(async (e) => {
    e.preventDefault();
    const v = values(e.target);
    const r = await api("/crowdsec", { method: "PUT", body: { mode, lapi_url: (v.url || "").trim(), machine_id: (v.mid || "").trim(), password: v.pw || "", container: (v.container || "").trim() } });
    toast("CrowdSec: " + t(r.message)); refreshOverview(); reload();
  });
  return html`<div class="section"><div class="section-head"><div><h2>${t("CrowdSec connection")}</h2><p class="small muted">${t("Recommended: Local API. No Docker socket needed.")}</p></div>
      ${s.crowdsec_mode ? html`<span class="tag ok">${t("connected ({mode})", { mode: s.crowdsec_mode === "lapi" ? "LAPI" : "Docker" })}</span>` : html`<span class="tag captcha">${t("not connected")}</span>`}</div>
    <form class="box pad" id="cs" onSubmit=${submit}>
      <label class="field"><span>${t("Mode")}</span><select name="mode" value=${mode} onChange=${(e) => setMode(e.target.value)}>
        <option value="lapi">${t("Local API (recommended)")}</option><option value="docker">${t("Docker socket (legacy)")}</option></select></label>
      <div data-cs="lapi" hidden=${mode !== "lapi"}>
        <p class="small">${t("Run once in the CrowdSec container and enter the printed password below:")}</p>
        <pre class="cmd">docker exec crowdsec cscli machines add asn-blocker --auto -f -</pre>
        <label class="field"><span>${t("LAPI URL")}</span><input type="url" name="url" class="mono" value=${s.lapi_url} /><small>${t("Both containers must share a Docker network.")}</small></label>
        <label class="field"><span>${t("Machine ID")}</span><input type="text" name="mid" class="mono" value=${s.lapi_machine_id || "asn-blocker"} /></label>
        <label class="field"><span>${t("Password")}</span><input type="password" name="pw" class="mono" autocomplete="off" placeholder=${s.lapi_password_set ? t("saved – leave empty to keep (required again if URL or machine ID change)") : ""} /></label>
      </div>
      <div data-cs="docker" hidden=${mode !== "docker"}><div class="note danger small">${t("This requires mounting /var/run/docker.sock. Whoever takes over the UI then has root on the host.")}</div>
        <label class="field"><span>${t("Container name")}</span><input type="text" name="container" class="mono" value=${s.docker_container} /></label></div>
      <button class="btn primary">${t("Test connection and save")}</button></form></div>`;
}

function General({ s, reload }) {
  const submit = guard(async (e) => {
    e.preventDefault();
    const g = e.target;
    await api("/settings", { method: "PUT", body: {
      interval_hours: +g.interval_hours.value, decision_hours: +g.decision_hours.value, sanity_percent: +g.sanity_percent.value,
      include_ipv6: g.include_ipv6.checked, spamhaus_asndrop: g.spamhaus_asndrop.value || null,
      trusted_proxies: g.trusted_proxies.value.split(",").map((x) => x.trim()).filter(Boolean), auth_user_header: g.auth_user_header.value.trim() } });
    toast(t("Saved")); refreshOverview(); reload();
  });
  return html`<div class="section"><div class="section-head"><h2>${t("Schedule and safety")}</h2></div><form class="box pad" id="general" onSubmit=${submit}>
    <div class="grid2"><label class="field"><span>${t("Update every (hours)")}</span><input type="number" name="interval_hours" min="6" max="336" value=${s.interval_hours} /></label>
    <label class="field"><span>${t("Decision lifetime (hours)")}</span><input type="number" name="decision_hours" min="24" value=${s.decision_hours} />
      <small>${t("Decisions are renewed before they expire. If asn-blocker stops, they expire after this time.")}</small></label></div>
    <div class="grid2"><label class="field"><span>${t("Sanity limit (%)")}</span><input type="number" name="sanity_percent" min="5" max="100" value=${s.sanity_percent} />
      <small>${t("If the number of ranges changes more than this, a run stops and waits for confirmation.")}</small></label>
    <label class="field"><span>${t("Spamhaus ASN-DROP")}</span><select name="spamhaus_asndrop" value=${s.spamhaus_asndrop || ""}><option value="">${t("don’t use")}</option>
      <option value="ban">${t("block automatically")}</option><option value="captcha">${t("captcha automatically")}</option></select>
      <small>${t("Public list of known abuse networks, refreshed on every run.")}</small></label></div>
    <label class="check"><input type="checkbox" name="include_ipv6" checked=${s.include_ipv6} /><span>${t("Also block IPv6 prefixes")}</span></label>
    <h3>${t("Access")}</h3>
    <div class="grid2"><label class="field"><span>${t("Trusted proxies")}</span><input type="text" name="trusted_proxies" class="mono" value=${(s.trusted_proxies || []).join(", ")} />
      <small>${s.auth_mode === "proxy" ? t("Container names, IPs or CIDRs. X-Forwarded-For and the user header are only accepted from here.") : t("Container names, IPs or CIDRs. X-Forwarded-For is only accepted from here.")}</small></label>
    <label class="field"><span>${t("User header")}</span><input type="text" name="auth_user_header" class="mono" value=${s.auth_user_header} disabled=${s.auth_mode !== "proxy"} /></label></div>
    <button class="btn primary">${t("Save")}</button></form></div>`;
}

// Saving needs a successful test with exactly the current values (switching notifications off needs none)
function Notify({ s, reload }) {
  const [tested, setTested] = useState(false), [err, setErr] = useState(""), [url, setUrl] = useState(s.notify_url || "");
  const form = useRef(null);
  const cfg = () => { const n = form.current;
    return { notify_url: n.notify_url.value.trim(), notify_format: n.notify_format.value,
      notify_token: n.notify_token_clear?.checked ? "" : n.notify_token.value.trim() || null, public_url: location.origin }; };
  const off = !url.trim(), ready = tested || off;
  const test = async () => {
    setErr("");
    try { await api("/notify/test", { method: "POST", body: cfg() }); setTested(true); toast(t("Test notification delivered")); }
    catch (e) { setTested(false); setErr(t("Test failed: {e}", { e: e.message })); }
  };
  const submit = async (e) => {
    e.preventDefault();
    if (!ready) { setErr(t("Not saved: send a successful test with these settings first.")); return; }
    try { await api("/notify", { method: "PUT", body: cfg() }); toast(t("Saved")); reload(); } catch (x) { setErr(x.message); }
  };
  return html`<div class="section"><div class="section-head"><div><h2>${t("Notifications")}</h2><p class="small muted">${t("Sent when a run fails or is stopped, and when a watched IP is affected.")}</p></div>
      ${s.notify_url ? html`<span class="tag ok">${t("active")}</span>` : html`<span class="tag">${t("off")}</span>`}</div>
    <form class="box pad" id="notify" ref=${form} onSubmit=${submit} onInput=${(e) => { setTested(false); setErr(""); if (e.target.name === "notify_url") setUrl(e.target.value); }}>
      <div class="note danger small" id="nerr" role="alert" hidden=${!err}>${err}</div>
      <div class="grid2"><label class="field"><span>URL</span><input type="url" name="notify_url" class="mono" value=${s.notify_url} placeholder="https://ntfy.example.com/asn-blocker" />
        <small>${t("ntfy: server and topic. Gotify: …/message. Webhook: any URL that accepts JSON. Empty = off.")}</small></label>
      <label class="field"><span>${t("Format")}</span><select name="notify_format" value=${s.notify_format}><option value="ntfy">ntfy</option><option value="gotify">Gotify</option><option value="webhook">${t("Webhook (JSON)")}</option></select></label></div>
      <div class="grid2"><label class="field"><span>${t("Access token (optional)")}</span><input type="password" name="notify_token" class="mono" autocomplete="off" placeholder=${s.notify_token_set ? t("saved – leave empty to keep") : "tk_…"} />
        <small>${t("ntfy access token or Gotify app token. Sent as a header, never shown again. Required again if the server changes.")}</small></label>
      ${s.notify_token_set ? html`<label class="check mid"><input type="checkbox" name="notify_token_clear" /><span>${t("Remove saved token")}</span></label>` : html`<span></span>`}</div>
      <div class="row"><button type="button" class="btn" id="ntest" onClick=${test}>${t("Send test")}</button>
        <button class="btn primary" id="nsave" aria-disabled=${String(!ready)}>${t("Save")}</button>
        <span class="small muted" id="nhint">${off ? t("Saving with an empty URL turns notifications off.") : tested ? t("Test delivered – you can save now.") : t("Send a successful test first, then save.")}</span></div></form></div>`;
}

function RoutingStatus({ r }) {
  return html`<span class="small">${r.refreshing ? html`<span class="dot running"></span>${t("Loading …")}`
    : r.active ? html`<span class="dot ok"></span>${t("{n} prefixes, updated {when}", { n: fmtNum(r.prefixes), when: ago(r.updated) })}`
    : html`<span class="dot warn"></span>${t("Not loaded – RIPEstat is used")}`}${r.error ? html` <span class="muted">· ${t("last attempt failed: {e}", { e: r.error })}</span>` : null}</span>`;
}

function Maintenance({ s, reload }) {
  const [routing, setRouting] = useState(s.routing);
  useEffect(() => setRouting(s.routing), [s]);
  useEffect(() => {  // while the table loads, look every few seconds
    if (!routing.refreshing) return undefined;
    const timer = setTimeout(async () => {
      const st = (await api("/settings")).routing;
      setRouting(st);
      if (!st.refreshing) toast(st.error && st.updated < Date.now() / 1000 - 120 ? t("Routing table: {e}", { e: st.error }) : t("Routing table updated"), !!st.error);
    }, 3000);
    return () => clearTimeout(timer);
  }, [routing]);
  const refresh = guard(async () => {
    await api("/routing/refresh", { method: "POST" });
    toast(t("Loading the routing table – this takes about a minute"));
    setRouting({ ...routing, refreshing: true });
  });
  const importFile = guard(async (e) => {
    const data = JSON.parse(await e.target.files[0].text());
    e.target.value = "";
    const count = (x) => (Array.isArray(x) ? x.length : 0);
    if (!(await confirmDlg(t("Import configuration"), t("{a} ASN rules, {e} exemptions and {v} VPN countries will be added or overwritten.", { a: count(data.asns), e: count(data.exemptions), v: count(data.vpn) }), t("Import")))) return;
    if (!(await putRules("/import", data, "POST"))) return;
    toast(t("Imported")); refreshOverview(); reload();
  });
  const cleanup = guard(async (e) => {
    e.preventDefault();
    const reason = e.target.reason.value.trim();
    if (!(await confirmDlg(t("Remove old decisions"), tx("All decisions with reason {r} that were added via cscli will be deleted from CrowdSec.", { r: html`<code>${reason}</code>` }), t("Remove"), "danger"))) return;
    const r = await api("/crowdsec/cleanup", { method: "POST", body: { reason } });
    toast(t("{n} decisions removed", { n: r.deleted }));
  });
  return html`<div class="section"><div class="section-head"><h2>${t("Maintenance")}</h2></div><div class="box pad">
    <div class="row"><a class="btn" href="/api/export" download="asn-blocker.json">${t("Export configuration")}</a>
      <label class="btn">${t("Import configuration")}<input type="file" id="imp" accept="application/json" class="sr-only" onChange=${importFile} /></label>
      <a class="btn" href="/api/ranges/ban.txt">${t("Active ban ranges")}</a><a class="btn" href="/api/ranges/captcha.txt">${t("Active captcha ranges")}</a></div>
    <h3 class="mt">${t("Routing table")}</h3>
    <p class="small muted">${t("Which prefixes every network announces, from bgp.tools – loaded once a day (about 80 MB), so runs and IP lookups need no request per network. Without a current table, RIPEstat is asked instead.")}</p>
    <div class="row" id="routing"><${RoutingStatus} r=${routing} /><span class="spacer"></span><button type="button" class="btn sm" id="routing-refresh" disabled=${routing.refreshing} onClick=${refresh}>${t("Update now")}</button></div>
    <h3 class="mt">${t("Remove decisions of other tools")}</h3>
    <p class="small muted">${t("Remove decisions that other tools or scripts added via cscli, by their reason. CrowdSec's own detections and blocklists are never touched.")}</p>
    <form class="row" id="cleanup" onSubmit=${cleanup}><input type="text" name="reason" class="mono" required minlength="3" placeholder=${t("Reason, e.g. my-old-blocklist")} aria-label=${t("Reason")} /><button class="btn danger">${t("Remove")}</button></form>
  </div></div>`;
}

function Password({ onChanged }) {
  const submit = guard(async (e) => {
    e.preventDefault();
    await api("/account/password", { method: "PUT", body: { current: e.target.cur.value, new: e.target.new.value } });
    toast(t("Password changed – please sign in again")); onChanged();
  });
  return html`<div class="section"><div class="section-head"><h2>${t("Change password")}</h2></div><form class="box pad" id="pw" onSubmit=${submit}>
    <div class="grid2"><label class="field"><span>${t("Current password")}</span><input type="password" name="cur" autocomplete="current-password" required /></label>
    <label class="field"><span>${t("New password")}</span><input type="password" name="new" minlength="12" autocomplete="new-password" required /></label></div>
    <button class="btn">${t("Change")}</button></form></div>`;
}

export function Settings() {
  const [s, reload] = useLoad(() => api("/settings"));
  if (!s) return html`<p class="muted">${t("Loading …")}</p>`;
  // the forms are uncontrolled: a reload after saving re-creates them with the stored values
  const key = JSON.stringify([s.crowdsec_mode, s.lapi_url, s.interval_hours, s.decision_hours, s.sanity_percent, s.spamhaus_asndrop, s.include_ipv6, s.trusted_proxies, s.notify_url, s.notify_format, s.notify_token_set]);
  return html`<${CrowdSec} key=${"cs" + key} s=${s} reload=${reload} />
    <${General} key=${"g" + key} s=${s} reload=${reload} />
    <${Notify} key=${"n" + key} s=${s} reload=${reload} />
    ${s.auth_mode === "local" ? html`<${Password} onChanged=${() => window.dispatchEvent(new Event("asnb-signed-out"))} />` : null}
    <${Maintenance} s=${s} reload=${reload} />`;
}
