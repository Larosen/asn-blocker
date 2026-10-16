// asn-blocker UI – ohne Build-Schritt, ohne Inline-Skripte (CSP).
import { t, lang, setLang, locale } from "./i18n.js";

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtNum = (n) => (n ?? 0).toLocaleString(locale());
const fmtAddr = (n) => (n >= 1e6 ? t("{n} Mio.", { n: (n / 1e6).toLocaleString(locale(), { maximumFractionDigits: 1 }) })
  : n >= 1e3 ? t("{n} Tsd.", { n: (n / 1e3).toLocaleString(locale(), { maximumFractionDigits: 1 }) }) : fmtNum(n));
const fmtTime = (ts) => (ts ? new Date(ts * 1000).toLocaleString(locale(), { dateStyle: "short", timeStyle: "short" }) : "–");
function ago(ts) {
  if (!ts) return "–";
  const rtf = new Intl.RelativeTimeFormat(locale(), { numeric: "auto" });
  const s = ts - Date.now() / 1000, a = Math.abs(s);
  if (a < 90) return rtf.format(0, "second");
  if (a < 3600) return rtf.format(Math.round(s / 60), "minute");
  if (a < 172800) return rtf.format(Math.round(s / 3600), "hour");
  return rtf.format(Math.round(s / 86400), "day");
}
const act = (a) => ({ ban: t("Blockieren"), captcha: t("Captcha") }[a] ?? a);
const runStatus = (s) => ({ ok: t("erfolgreich"), failed: t("fehlgeschlagen"), blocked: t("angehalten"), running: t("läuft") }[s] ?? s);
const CONTINENTS = ["EU", "NA", "SA", "AS", "OC", "AF", "AN", ""];
const continentName = (c) => ({ EU: t("Europa"), NA: t("Nordamerika"), SA: t("Südamerika"), AS: t("Asien"), AF: t("Afrika"),
  OC: t("Ozeanien"), AN: t("Antarktis") }[c] ?? t("Sonstige"));

async function api(path, { method = "GET", body } = {}) {
  const res = await fetch("/api" + path, {
    method, credentials: "same-origin",
    headers: { "X-Requested-With": "asn-blocker", ...(body !== undefined ? { "Content-Type": "application/json" } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401 && path !== "/login") { boot(); throw new Error(t("Nicht angemeldet")); }
  const data = res.headers.get("content-type")?.includes("json") ? await res.json() : await res.text();
  if (!res.ok) {
    const d = data?.detail;
    throw new Error(Array.isArray(d) ? d.map((x) => t(x.msg?.replace(/^Value error, /, "") ?? "")).join("; ") : t(d || res.statusText));
  }
  return data;
}

function toast(msg, error = false) {
  const el = document.createElement("div");
  el.className = "toast" + (error ? " error" : "");
  el.setAttribute("role", error ? "alert" : "status");
  el.textContent = msg;
  $("#toasts").append(el);
  setTimeout(() => el.remove(), error ? 7000 : 3500);
}
const guard = (fn) => async (...a) => { try { await fn(...a); } catch (e) { toast(e.message, true); } };

// Dialog: gibt den Wert des geklickten Buttons zurueck (oder "" bei Abbruch)
function dialog({ title, body, actions = [["cancel", t("Abbrechen")], ["ok", "OK", "primary"]], onOpen }) {
  const dlg = $("#dlg");
  $("#dlg-form").innerHTML = `<div class="dh"><h2 id="dlg-title">${esc(title)}</h2></div><div class="db">${body}</div>
    <div class="df">${actions.map(([v, l, c]) => `<button class="btn ${c || ""}" value="${v}">${esc(l)}</button>`).join("")}</div>`;
  dlg.setAttribute("aria-labelledby", "dlg-title");
  return new Promise((resolve) => {
    dlg.onclose = () => resolve(dlg.returnValue === "cancel" ? "" : dlg.returnValue);
    dlg.returnValue = "";
    dlg.showModal();
    onOpen?.(dlg);
  });
}
const confirmDlg = (title, text, ok = t("Bestätigen"), cls = "primary") =>
  dialog({ title, body: `<p>${text}</p>`, actions: [["cancel", t("Abbrechen")], ["ok", ok, cls]] }).then((v) => v === "ok");

// --- Start: Session / Einrichtung / Login ------------------------------------------------------
let session = null;
async function boot() {
  document.documentElement.lang = lang();
  session = await api("/session").catch(() => null);
  if (!session) { $("#root").textContent = t("Server nicht erreichbar."); return; }
  if (session.setup_required) return renderSetup();
  if (!session.user) return session.auth_mode === "local" ? renderLogin() : renderProxyDenied();
  renderShell();
}

const langSwitch = () => `<button type="button" class="btn ghost sm" id="lang" aria-label="${t("Sprache wechseln")}">${lang() === "de" ? "English" : "Deutsch"}</button>`;
const bindLang = () => $("#lang")?.addEventListener("click", () => { setLang(lang() === "de" ? "en" : "de"); boot(); });

function renderSetup() {
  $("#root").className = "";
  $("#root").innerHTML = `<main class="center"><form class="card" id="setup">
    <div class="row"><div class="steps"><span class="on">${t("1 Zugang")}</span><span aria-hidden="true">›</span><span>${t("2 CrowdSec")}</span></div><span class="spacer"></span>${langSwitch()}</div>
    <h1>${t("Ersteinrichtung")}</h1>
    <p class="lead">${t("Lege fest, wie die Oberfläche geschützt wird.")}</p>
    <label class="field"><span>${t("Setup-Token")}</span><input type="text" name="token" class="mono" required autocomplete="off">
      <small>${t("Steht im Container-Log:")} <code>docker logs asn-blocker</code></small></label>
    <label class="field"><span>${t("Anmeldung")}</span><select name="mode">
      <option value="proxy">${t("Reverse Proxy mit SSO (Pangolin, Authelia, Authentik …)")}</option>
      <option value="local">${t("Eigener Login mit Passwort")}</option></select></label>
    <div data-mode="proxy">
      <label class="field"><span>${t("Vertrauenswürdige Proxy-IPs")}</span><input type="text" name="trusted" class="mono" value="${esc(session.peer_ip || "")}">
        <small>${t("IP oder CIDR des Reverse Proxys, kommagetrennt. Diese Anfrage kam von {ip}.", { ip: `<code>${esc(session.peer_ip)}</code>` })}</small></label>
      <label class="field"><span>${t("Header mit Benutzername")}</span><input type="text" name="header" class="mono" value="Remote-User">
        <small>${t("Den Header muss der Proxy nach erfolgreichem SSO setzen.")}</small></label>
    </div>
    <div data-mode="local" hidden>
      <label class="field"><span>${t("Benutzername")}</span><input type="text" name="username" value="admin" autocomplete="username"></label>
      <label class="field"><span>${t("Passwort")}</span><input type="password" name="password" minlength="12" autocomplete="new-password"><small>${t("Mindestens 12 Zeichen.")}</small></label>
    </div>
    <button class="btn primary">${t("Weiter")}</button>
  </form></main>`;
  bindLang();
  const f = $("#setup");
  f.mode.onchange = () => $$("[data-mode]", f).forEach((d) => (d.hidden = d.dataset.mode !== f.mode.value));
  f.onsubmit = guard(async (e) => {
    e.preventDefault();
    await api("/setup/auth", { method: "POST", body: {
      token: f.token.value.trim(), mode: f.mode.value, user_header: f.header.value.trim(),
      trusted_proxies: f.trusted.value.split(",").map((s) => s.trim()).filter(Boolean),
      username: f.username.value.trim(), password: f.password.value } });
    location.hash = "#/settings";
    boot();
  });
}

function renderLogin() {
  $("#root").className = "";
  $("#root").innerHTML = `<main class="center"><form class="card" id="login">
    <div class="row"><h1>asn-blocker</h1><span class="spacer"></span>${langSwitch()}</div><p class="lead">${t("Anmelden")}</p>
    <label class="field"><span>${t("Benutzername")}</span><input type="text" name="u" autocomplete="username" required></label>
    <label class="field"><span>${t("Passwort")}</span><input type="password" name="p" autocomplete="current-password" required></label>
    <button class="btn primary" id="login-btn">${t("Anmelden")}</button></form></main>`;
  bindLang();
  const f = $("#login");
  f.onsubmit = guard(async (e) => {
    e.preventDefault();
    await api("/login", { method: "POST", body: { username: f.u.value, password: f.p.value } });
    boot();
  });
}

function renderProxyDenied() {
  $("#root").className = "";
  $("#root").innerHTML = `<main class="center"><div class="card"><h1>${t("Kein Zugriff")}</h1>
    <p class="lead">${t("Diese Instanz erwartet eine Anmeldung über den Reverse Proxy (SSO). Die Anfrage kam nicht über einen vertrauenswürdigen Proxy oder ohne Benutzer-Header.")}</p>
    <p class="muted small">${t("Zurücksetzen:")} <code>docker exec asn-blocker python -m app.cli reset-auth</code>, ${t("danach Container neu starten.")}</p></div></main>`;
}

// --- Shell ---------------------------------------------------------------------------------------
const VIEWS = ["overview", "asns", "vpn", "exemptions", "runs", "audit", "settings"];
const viewName = (v) => ({ overview: t("Übersicht"), asns: t("ASNs"), vpn: t("VPN-Ausnahmen"), exemptions: t("Ausnahmen"),
  runs: t("Läufe"), audit: t("Protokoll"), settings: t("Einstellungen") }[v]);
let ov = null, pollTimer = null, runPoll = null;

function renderShell() {
  $("#root").className = "";
  $("#root").innerHTML = `<div class="shell">
    <aside class="side"><div class="brand"><img src="/static/icon.svg" alt="">asn-blocker</div>
      <nav class="nav" aria-label="${t("Hauptnavigation")}">${VIEWS.map((id) => `<a href="#/${id}" data-view="${id}">${viewName(id)}<span class="count" data-count="${id}"></span></a>`).join("")}</nav>
      <div class="side-foot"><span>${esc(session.user)}</span>${session.auth_mode === "local" ? `<a href="#" id="logout">${t("Abmelden")}</a>` : ""}${langSwitch()}<span>v${esc(session.version)}</span></div>
    </aside>
    <div class="main"><div id="banners" role="region" aria-label="${t("Hinweise")}"></div>
      <header class="top"><h1 id="title"></h1>
        <form class="ipcheck" id="ipcheck" role="search"><input type="search" name="ip" placeholder="${t("IP prüfen …")}" aria-label="${t("IP prüfen")}" autocomplete="off"></form></header>
      <main class="content" id="view"></main></div></div>
    <div id="applybar" role="region" aria-label="${t("Änderungen")}" aria-live="polite"></div>`;
  bindLang();
  $("#logout")?.addEventListener("click", guard(async (e) => { e.preventDefault(); await api("/logout", { method: "POST" }); boot(); }));
  $("#ipcheck").onsubmit = (e) => { e.preventDefault(); const ip = e.target.ip.value.trim(); if (ip) checkIp(ip); };
  window.onhashchange = route;
  route();
  refreshOverview();
}

async function refreshOverview() {
  clearTimeout(pollTimer);
  try { ov = await api("/overview"); } catch { return; }
  const c = { asns: ov.rules.asns, vpn: ov.rules.vpn, exemptions: ov.rules.exemptions + ov.rules.watch };
  $$("[data-count]").forEach((el) => (el.textContent = c[el.dataset.count] || ""));
  renderBanners();
  renderApplyBar();
  pollTimer = setTimeout(refreshOverview, ov.running ? 2000 : 30000);
}

function renderBanners() {
  const b = [];
  if (!ov.crowdsec_mode) b.push(`<div class="banner warn"><span class="dot warn"></span><span>${t("CrowdSec ist noch nicht verbunden.")}</span><a class="btn sm" href="#/settings">${t("Einrichten")}</a></div>`);
  if (ov.me?.status) b.push(`<div class="banner danger" role="alert"><span class="dot ban"></span><span>${t("Deine IP {ip} ist aktuell von {action} betroffen. Du riskierst, dich auszusperren.", { ip: `<code>${esc(ov.me.ip)}</code>`, action: `<b>${act(ov.me.status)}</b>` })}</span>
    <button class="btn sm" data-exempt-me="${esc(ov.me.ip)}">${t("Als Ausnahme hinzufügen")}</button></div>`);
  if (ov.last_apply?.status === "failed") b.push(`<div class="banner danger"><span class="dot failed"></span><span>${t("Letzter Lauf fehlgeschlagen ({when}).", { when: ago(ov.last_apply.started_at) })}</span><a class="btn sm" href="#/runs/${ov.last_apply.id}">${t("Details")}</a></div>`);
  if (ov.last_apply?.status === "blocked") b.push(`<div class="banner warn"><span class="dot blocked"></span><span>${t("Letzter Lauf wurde von der Plausibilitätsprüfung angehalten.")}</span><a class="btn sm" href="#/runs/${ov.last_apply.id}">${t("Prüfen")}</a></div>`);
  $("#banners").innerHTML = b.join("");
  $("[data-exempt-me]")?.addEventListener("click", guard(async (e) => {
    await api("/exemptions", { method: "POST", body: { kind: "cidr", value: e.target.dataset.exemptMe, note: t("eigene IP") } });
    toast(t("Eigene IP als Ausnahme gespeichert. Jetzt anwenden, damit es wirkt."));
    refreshOverview();
  }));
}

// Apply-Leiste: zeigt bei ungespeicherten Regeln die erwartete Aenderung (+/- Ranges)
let previewSeq = 0;
function renderApplyBar() {
  const el = $("#applybar");
  if (ov.running) {
    el.innerHTML = `<div class="applybar"><span class="dot running"></span><span>${t("Lauf wird ausgeführt …")}</span><span class="spacer"></span><a class="btn sm" href="#/runs">${t("Ansehen")}</a></div>`;
    return;
  }
  if (!ov.pending) { el.innerHTML = ""; return; }
  el.innerHTML = `<div class="applybar"><span class="dot warn"></span><span>${t("Regeln geändert – noch nicht in CrowdSec aktiv.")}</span>
    <span class="muted small mono" id="preview">${t("Vorschau wird berechnet …")}</span><span class="spacer"></span>
    <button class="btn" data-run="plan">${t("Vorschau")}</button><button class="btn primary" data-run="apply" ${ov.crowdsec_mode ? "" : "disabled"}>${t("Anwenden")}</button></div>`;
  $$("[data-run]", el).forEach((b) => (b.onclick = () => startRun(b.dataset.run)));
  const my = ++previewSeq;
  api("/preview").then((p) => {
    if (my !== previewSeq || !$("#preview")) return;
    if (p.busy) { setTimeout(renderApplyBar, 1500); return; }
    $("#preview").textContent = p.error ? t("Vorschau nicht möglich: {e}", { e: t(p.error) })
      : ["ban", "captcha"].map((k) => `${act(k)} +${fmtNum(p[k].add)} −${fmtNum(p[k].remove)}`).join(" · ");
  }).catch(() => { if ($("#preview")) $("#preview").textContent = ""; });
}

const startRun = guard(async (kind, force = false) => {
  if (kind === "apply" && !(await confirmDlg(t("Regeln anwenden"), force
    ? t("Die Plausibilitätsprüfung wird übergangen. Die berechneten Ranges werden trotz großer Abweichung übertragen.")
    : t("Ranges werden neu berechnet und mit CrowdSec abgeglichen. Bestehende Sperren bleiben bis zum Abschluss aktiv."), t("Anwenden")))) return;
  await api("/runs", { method: "POST", body: { kind, force } });
  toast(kind === "plan" ? t("Vorschau wird berechnet …") : t("Lauf gestartet"));
  if (location.hash === "#/runs") route(); else location.hash = "#/runs";
  setTimeout(refreshOverview, 300);
});

function route() {
  const [view = "overview", arg] = location.hash.replace(/^#\/?/, "").split("/");
  const v = VIEWS.includes(view) ? view : "overview";
  $$(".nav a").forEach((a) => (a.dataset.view === v ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current")));
  $("#title").textContent = viewName(v);
  document.title = `${viewName(v)} · asn-blocker`;
  clearTimeout(runPoll);
  const el = $("#view");
  el.innerHTML = `<p class="muted">${t("Lade …")}</p>`;
  ({ overview: viewOverview, asns: viewAsns, vpn: viewVpn, exemptions: viewExemptions, runs: viewRuns, audit: viewAudit, settings: viewSettings })[v](el, arg)
    ?.catch?.((e) => (el.innerHTML = `<div class="note danger">${esc(e.message)}</div>`));
}

// --- IP-Pruefer ----------------------------------------------------------------------------------------
const checkIp = guard(async (ip) => {
  const r = await api("/check/" + encodeURIComponent(ip));
  const st = r.status ? `<span class="tag ${r.status}">${act(r.status)}</span>` : r.exempt.length ? `<span class="tag ok">${t("Ausgenommen")}</span>` : `<span class="tag">${t("nicht betroffen")}</span>`;
  const asns = r.asns.map((a) => `<tr><td class="mono">AS${a.asn}</td><td>${esc(a.name)}</td><td>${a.rule ? `<span class="tag ${a.rule}">${act(a.rule)}</span>` : `<span class="muted">${t("keine Regel")}</span>`}</td></tr>`).join("");
  const body = `<p>${st}</p>
    ${asns ? `<h3>${t("Herkunft")}</h3><table><tbody>${asns}</tbody></table>${r.prefix ? `<p class="small muted">${t("Prefix")} ${esc(r.prefix)}</p>` : ""}` : r.global ? "" : `<p class="muted">${t("Keine öffentliche Adresse.")}</p>`}
    ${Object.entries(r.ranges).map(([k, v]) => `<p>${t("Erfasst durch {action}:", { action: `<b>${act(k)}</b>` })} <code>${v.map(esc).join(", ")}</code></p>`).join("")}
    ${r.exempt.length ? `<p>${t("Ausgenommen durch:")} ${r.exempt.map(esc).join(", ")}</p>` : ""}
    ${r.lookup_error ? `<p class="small muted">${esc(r.lookup_error)}</p>` : ""}
    <p class="small muted">${t("Stand: zuletzt angewendeter Lauf.")}</p>`;
  const v = await dialog({ title: r.ip, body, actions: [["watch", t("Als Wächter-IP überwachen")], ["exempt", t("Als Ausnahme")], ["cancel", t("Schließen"), "primary"]] });
  if (v === "watch") { await api("/watch", { method: "POST", body: { ip: r.ip } }); toast(t("Wächter-IP hinzugefügt")); refreshOverview(); }
  if (v === "exempt") { await api("/exemptions", { method: "POST", body: { kind: "cidr", value: r.ip } }); toast(t("Ausnahme gespeichert")); refreshOverview(); }
});

// --- Uebersicht ----------------------------------------------------------------------------------------------
async function viewOverview(el) {
  const [o, watch] = await Promise.all([api("/overview"), api("/watch")]);
  ov = o;
  const la = o.last_apply;
  el.innerHTML = `<div class="section"><div class="stats">
      <div class="stat"><div class="label">${t("Blockiert")}</div><div class="value">${fmtNum(o.applied.ban)}</div><div class="sub">${t("Ranges aktiv")}</div></div>
      <div class="stat"><div class="label">${t("Captcha")}</div><div class="value">${fmtNum(o.applied.captcha)}</div><div class="sub">${t("Ranges aktiv")}</div></div>
      <div class="stat"><div class="label">${t("Letzter Lauf")}</div><div class="value small">${la ? `<span class="dot ${la.status}"></span>${runStatus(la.status)}` : "–"}</div><div class="sub">${la ? ago(la.started_at) + " · " + esc(la.triggered_by) : t("noch nie angewendet")}</div></div>
      <div class="stat"><div class="label">${t("Nächster Lauf")}</div><div class="value small">${o.next_run ? ago(o.next_run) : "–"}</div><div class="sub">${o.next_run ? fmtTime(o.next_run) : la ? t("CrowdSec nicht verbunden") : t("startet nach erstem Anwenden")} · ${t("alle {h} h", { h: o.interval_hours })}</div></div>
    </div></div>
    <div class="grid2">
      <div class="section"><div class="section-head"><h2>${t("Regeln")}</h2></div><div class="box"><table><tbody>
        <tr><td><a href="#/asns">${t("ASNs")}</a></td><td class="num mono">${o.rules.asns}</td></tr>
        <tr><td><a href="#/vpn">${t("VPN-Länder ausgenommen")}</a></td><td class="num mono">${o.rules.vpn}</td></tr>
        <tr><td><a href="#/exemptions">${t("Weitere Ausnahmen")}</a></td><td class="num mono">${o.rules.exemptions}</td></tr>
        <tr><td>${t("ASN-Namensliste")}</td><td class="num mono">${o.asn_names ? fmtNum(o.asn_names) : `<span class="muted">${t("wird geladen")}</span>`}</td></tr>
      </tbody></table></div></div>
      <div class="section"><div class="section-head"><h2>${t("Wächter-IPs")}</h2><a class="small" href="#/exemptions">${t("Verwalten")}</a></div><div class="box">
        ${watch.length ? `<table><tbody>${watch.map((w) => `<tr><td class="mono">${esc(w.ip)}</td><td>${esc(w.note)}</td><td class="actions">${statusTag(w.last_status)}</td></tr>`).join("")}</tbody></table>`
          : `<div class="empty">${t("Wächter-IPs werden nach jedem Lauf geprüft und melden sich, wenn sie gesperrt würden – z. B. die eigene Mobilfunk-IP.")}</div>`}
      </div></div>
    </div>
    ${o.me ? `<p class="small muted">${t("Deine IP:")} <code>${esc(o.me.ip)}</code> – ${o.me.status ? act(o.me.status) : t("nicht betroffen")}</p>` : ""}`;
}
const statusTag = (s) => (!s ? `<span class="muted small">${t("noch nicht geprüft")}</span>` : s === "frei" ? `<span class="tag ok">${t("frei")}</span>` : `<span class="tag ${s}">${act(s)}</span>`);

// --- ASNs ------------------------------------------------------------------------------------------------------
async function viewAsns(el) {
  el.innerHTML = `<div class="section"><div class="search" id="search">
      <input type="search" id="q" placeholder="${t("ASN suchen – Nummer oder Name, z. B. hetzner, AS16509")}" autocomplete="off" aria-label="${t("ASN suchen")}" aria-controls="suggest">
      <div class="suggest box" id="suggest" hidden></div></div></div>
    <div class="section"><div class="section-head"><div><h2>${t("Regeln")}</h2><p class="small muted">${t("Neue Regeln wirken nach „Anwenden“.")}</p></div>
      <div class="row"><input type="search" id="filter" placeholder="${t("Filtern")}" aria-label="${t("Regeln filtern")}"><button class="btn" id="paste">${t("Liste einfügen")}</button></div></div>
      <div class="bulk row" id="bulk" hidden><span id="bulk-count"></span><span class="spacer"></span>
        <button class="btn sm" data-bulk="ban">${t("Blockieren")}</button><button class="btn sm" data-bulk="captcha">${t("Captcha")}</button>
        <button class="btn sm danger" data-bulk="delete">${t("Entfernen")}</button><button class="btn sm ghost" data-bulk="clear">${t("Auswahl aufheben")}</button></div>
      <div class="box table-wrap" id="rules"></div></div>`;
  let rules = await api("/asns");
  const selected = new Set();
  const visible = () => {
    const f = $("#filter").value.toLowerCase();
    return rules.filter((r) => !f || `as${r.asn} ${r.name} ${r.note}`.toLowerCase().includes(f));
  };
  const syncBulk = () => {
    for (const a of [...selected]) if (!rules.some((r) => r.asn === a)) selected.delete(a);
    $("#bulk").hidden = !selected.size;
    $("#bulk-count").textContent = t("{n} ausgewählt", { n: selected.size });
    const all = $("#sel-all");
    if (all) { const vis = visible(); all.checked = vis.length > 0 && vis.every((r) => selected.has(r.asn)); all.indeterminate = !all.checked && vis.some((r) => selected.has(r.asn)); }
  };
  const draw = () => {
    const list = visible();
    $("#rules").innerHTML = rules.length ? `<table><thead><tr><th class="sel"><input type="checkbox" id="sel-all" aria-label="${t("Alle auswählen")}"></th><th>ASN</th><th>${t("Name")}</th><th class="hide-sm">${t("Typ")}</th><th class="num hide-sm">${t("Prefixe")}</th><th class="num hide-sm">${t("IPv4-Adressen")}</th><th>${t("Aktion")}</th><th>${t("Notiz")}</th><th><span class="sr-only">${t("Entfernen")}</span></th></tr></thead><tbody>
      ${list.map((r) => `<tr data-asn="${r.asn}"><td class="sel"><input type="checkbox" data-sel ${selected.has(r.asn) ? "checked" : ""} aria-label="${t("AS{asn} auswählen", { asn: r.asn })}"></td><td class="mono">AS${r.asn}</td><td>${esc(r.name)}${r.cc ? ` <span class="muted small">${esc(r.cc)}</span>` : ""}</td>
        <td class="hide-sm">${classTag(r.class)}</td>
        <td class="num mono hide-sm">${r.stats ? fmtNum(r.stats.v4) + (r.stats.v6 ? ` <span class="muted">+${r.stats.v6}</span>` : "") : `<span class="muted">…</span>`}</td>
        <td class="num mono hide-sm">${r.stats ? fmtAddr(r.stats.addresses) : `<span class="muted">…</span>`}</td>
        <td>${segAction(r.action)}</td>
        <td><input class="inline" data-note value="${esc(r.note)}" placeholder="—" aria-label="${t("Notiz zu AS{asn}", { asn: r.asn })}"></td>
        <td class="actions"><button class="btn ghost sm danger" data-del aria-label="${t("AS{asn} entfernen", { asn: r.asn })}">${t("Entfernen")}</button></td></tr>`).join("")}
      </tbody></table>` : `<div class="empty">${t("Noch keine ASNs. Oben suchen oder eine bestehende Liste einfügen.")}</div>`;
    $("#sel-all")?.addEventListener("change", (e) => { for (const r of visible()) e.target.checked ? selected.add(r.asn) : selected.delete(r.asn); draw(); });
    $$("#rules tr[data-asn]").forEach((tr) => {
      const r = rules.find((x) => x.asn == tr.dataset.asn);
      $("[data-sel]", tr).onchange = (e) => { e.target.checked ? selected.add(r.asn) : selected.delete(r.asn); syncBulk(); };
      $$(".seg button", tr).forEach((b) => (b.onclick = guard(async () => { await save([{ ...r, action: b.dataset.a }]); })));
      $("[data-note]", tr).onchange = guard(async (e) => { await save([{ ...r, note: e.target.value }]); toast(t("Notiz gespeichert")); });
      $("[data-del]", tr).onclick = guard(async () => {
        if (!(await confirmDlg(t("Regel entfernen"), t("AS{asn} {name} entfernen? Die Ranges werden beim nächsten Anwenden freigegeben.", { asn: r.asn, name: esc(r.name) }), t("Entfernen"), "danger"))) return;
        await api("/asns/" + r.asn, { method: "DELETE" }); await reload();
      });
    });
    syncBulk();
  };
  const reload = async () => { rules = await api("/asns"); draw(); refreshOverview(); };
  const save = async (rs) => { await api("/asns", { method: "PUT", body: rs.map((r) => ({ asn: r.asn, name: r.name, action: r.action, note: r.note })) }); await reload(); };
  draw();
  $("#filter").oninput = draw;
  $$("[data-bulk]").forEach((b) => (b.onclick = guard(async () => {
    const pick = rules.filter((r) => selected.has(r.asn));
    if (b.dataset.bulk === "clear") { selected.clear(); draw(); return; }
    if (b.dataset.bulk === "delete") {
      if (!(await confirmDlg(t("Regeln entfernen"), t("{n} ASN-Regeln entfernen? Die Ranges werden beim nächsten Anwenden freigegeben.", { n: pick.length }), t("Entfernen"), "danger"))) return;
      await api("/asns/delete", { method: "POST", body: { asns: pick.map((r) => r.asn) } });
      selected.clear(); await reload(); toast(t("{n} Regeln entfernt", { n: pick.length })); return;
    }
    await save(pick.map((r) => ({ ...r, action: b.dataset.bulk })));
    toast(t("{n} Regeln geändert", { n: pick.length }));
  })));
  if (rules.some((r) => !r.stats)) api("/asns/stats", { method: "POST" }).then(reload).catch(() => {});

  // Suche mit Debounce
  let timer, seq = 0;
  const q = $("#q"), sug = $("#suggest");
  q.oninput = () => { clearTimeout(timer); timer = setTimeout(search, 200); };
  q.onkeydown = (e) => { if (e.key === "Escape") sug.hidden = true; };
  el.addEventListener("click", (e) => { if (!$("#search")?.contains(e.target)) sug.hidden = true; });
  async function search() {
    const term = q.value.trim(), my = ++seq;
    if (!term) { sug.hidden = true; return; }
    let res;
    try { res = await api("/asn/search?q=" + encodeURIComponent(term)); } catch (e) { sug.innerHTML = `<div class="empty">${esc(e.message)}</div>`; sug.hidden = false; return; }
    if (my !== seq) return;
    sug.innerHTML = res.length ? res.map((r, i) => `<div class="item" data-i="${i}"><span class="mono">AS${r.asn}</span><span>${esc(r.name)} ${r.cc ? `<span class="muted small">${esc(r.cc)}</span>` : ""}</span>
        <span class="hide-sm">${classTag(r.class)}</span>
        <span class="row">${r.rule ? `<span class="tag ${r.rule}">${act(r.rule)}</span>` : `<button class="btn sm" data-a="ban">${t("Blockieren")}</button><button class="btn sm" data-a="captcha">${t("Captcha")}</button>`}</span></div>`).join("")
      : `<div class="empty">${t("Kein ASN gefunden.")}</div>`;
    sug.hidden = false;
    $$(".item", sug).forEach((it) => $$("[data-a]", it).forEach((b) => (b.onclick = guard(async () => {
      const r = res[it.dataset.i];
      if (/eyeball/i.test(r.class || "") && !(await confirmDlg(t("Endkunden-Netz"), t("AS{asn} {name} ist als Eyeball-Netz (Internetanbieter für Endkunden) eingestuft. Eine Sperre trifft echte Besucher. Trotzdem hinzufügen?", { asn: r.asn, name: esc(r.name) }), t("Hinzufügen"), "danger"))) return;
      await save([{ asn: r.asn, name: r.name, action: b.dataset.a, note: "" }]);
      toast(t("AS{asn} hinzugefügt", { asn: r.asn }));
      search();
    }))));
  }

  // Liste einfuegen (z. B. ASN_LIST aus dem Bash-Skript)
  $("#paste").onclick = guard(async () => {
    const v = await dialog({ title: t("Liste einfügen"), body: `<p class="small muted">${t("Eine ASN pro Zeile, optional mit Kommentar:")} <code>16509   # Amazon AWS</code>. ${t("Auskommentierte Zeilen werden übersprungen.")}</p>
      <label class="field"><span class="sr-only">${t("ASN-Liste")}</span><textarea id="paste-text" placeholder="15169    # Google&#10;AS8075 Microsoft"></textarea></label>
      <label class="field"><span>${t("Aktion")}</span><select id="paste-action"><option value="ban">${t("Blockieren")}</option><option value="captcha">${t("Captcha")}</option></select></label>`,
      actions: [["cancel", t("Abbrechen")], ["ok", t("Vorschau"), "primary"]] });
    if (v !== "ok") return;
    const preview = await api("/asns/parse", { method: "POST", body: { text: $("#paste-text").value, action: $("#paste-action").value } });
    if (!preview.length) return toast(t("Keine ASNs erkannt"), true);
    const exist = new Set(rules.map((r) => r.asn));
    const ok = await dialog({ title: t("{n} ASNs übernehmen", { n: preview.length }), body: `<table><tbody>${preview.map((p) => `<tr><td class="mono">AS${p.asn}</td><td>${esc(p.name)}</td><td class="small muted">${esc(p.note)}</td><td>${exist.has(p.asn) ? `<span class="tag">${t("ersetzt")}</span>` : ""}</td></tr>`).join("")}</tbody></table>`,
      actions: [["cancel", t("Abbrechen")], ["ok", t("Übernehmen"), "primary"]] });
    if (ok !== "ok") return;
    await api("/asns", { method: "PUT", body: preview });
    toast(t("{n} ASNs übernommen", { n: preview.length }));
    await reload();
    api("/asns/stats", { method: "POST" }).then(reload).catch(() => {});
  });
}
const segAction = (a) => `<div class="seg" role="group" aria-label="${t("Aktion")}">${["ban", "captcha"].map((x) => `<button type="button" class="${x}" data-a="${x}" aria-pressed="${a === x}">${act(x)}</button>`).join("")}</div>`;
const classTag = (c) => (!c || c === "Unknown" ? "" : `<span class="tag" title="${t("Einstufung laut bgp.tools")}">${esc(c)}</span>`);

// --- VPN -------------------------------------------------------------------------------------------------------
async function viewVpn(el, sel) {
  const provs = await api("/vpn/providers");
  const p = provs.find((x) => x.id === sel) || provs[0];
  el.innerHTML = `<p class="muted lead-p">${t("Server-IPs der gewählten Länder werden aus allen Sperren herausgeschnitten, damit Nutzer dieser VPN-Standorte durchkommen.")}</p>
    <div class="split"><nav class="box plist" aria-label="${t("VPN-Anbieter")}">${provs.map((x) => `<a href="#/vpn/${x.id}" ${x.id === p.id ? `aria-current="true"` : ""}><span>${esc(x.name)}</span><span class="mono muted small">${x.countries.length || ""}</span></a>`).join("")}</nav>
    <div><div class="box pad"><div class="section-head"><div><h2>${esc(p.name)}</h2><p class="small muted">${esc(p.note)}</p></div></div>
      <div class="row small"><span id="mode-label">${t("Ausnahme als")}</span><div class="seg" id="mode" role="group" aria-labelledby="mode-label">
        <button type="button" data-m="exact" aria-pressed="${p.mode === "exact"}">${t("exakte Server-IPs")}</button>
        <button type="button" data-m="net" aria-pressed="${p.mode === "net"}">${t("ganzes Netz (/24, /64)")}</button></div></div>
      <div class="note warn small" id="netwarn" ${p.mode === "net" ? "" : "hidden"}>${t("VPN-Server stehen meist bei Hostern. Ein ganzes /24 nimmt dort auch fremde Server aus – möglicherweise genau die, die gesperrt werden sollen.")}</div>
      ${p.exit_asn ? `<div class="note small">${t("Exit-IPs von {name} können von den Einwahl-IPs abweichen und liegen meist in {asn}.", { name: esc(p.name), asn: `<code>AS${p.exit_asn}</code>` })} <button class="btn sm" id="exitasn">${t("AS{asn} als Ausnahme-ASN hinzufügen", { asn: p.exit_asn })}</button></div>` : ""}
    </div>
    <div class="box"><div class="row pad-sm" id="ctools"><input type="search" id="cf" placeholder="${t("Länder filtern")}" aria-label="${t("Länder filtern")}"><span class="spacer"></span>
      <button class="btn sm ghost" id="none">${t("Keine")}</button><span class="muted small" id="selcount" aria-live="polite"></span><button class="btn primary" id="save">${t("Speichern")}</button></div>
      <div class="countries" id="ctry"><span class="muted">${t("Lade Serverliste …")}</span></div></div></div></div>`;
  let mode = p.mode;
  const chosen = new Set(p.countries);
  $$("#mode button").forEach((b) => (b.onclick = () => { mode = b.dataset.m; $$("#mode button").forEach((x) => x.setAttribute("aria-pressed", x === b)); $("#netwarn").hidden = mode !== "net"; }));
  $("#exitasn")?.addEventListener("click", guard(async () => { await api("/exemptions", { method: "POST", body: { kind: "asn", value: String(p.exit_asn), note: t("{name} Exit-IPs", { name: p.name }) } }); toast(t("AS{asn} als Ausnahme gespeichert", { asn: p.exit_asn })); refreshOverview(); }));
  let countries = [];
  try { countries = await api(`/vpn/${p.id}/countries`); } catch (e) { $("#ctry").innerHTML = `<div class="note danger">${esc(e.message)}</div>`; }
  const count = () => ($("#selcount").textContent = t("{n} gewählt", { n: chosen.size }));
  const draw = () => {
    if (!countries.length) { count(); return; }
    const f = $("#cf").value.toLowerCase();
    const list = countries.filter((c) => !f || c.name.toLowerCase().includes(f) || c.code.toLowerCase() === f);
    const groups = CONTINENTS.map((k) => [k, list.filter((c) => (c.continent || "") === k).sort((a, b) => a.name.localeCompare(b.name, locale()))]).filter(([, cs]) => cs.length);
    $("#ctry").innerHTML = groups.map(([k, cs]) => {
      const n = cs.filter((c) => chosen.has(c.code)).length;
      return `<fieldset class="continent"><legend><span>${continentName(k)}</span><span class="muted small">${n ? t("{n} von {m}", { n, m: cs.length }) : cs.length}</span>
          <button type="button" class="btn ghost sm" data-all="${k}">${n === cs.length ? t("keine") : t("alle")}</button></legend>
        <div class="cgrid">${cs.map((c) => `<label><input type="checkbox" value="${esc(c.code)}" ${chosen.has(c.code) ? "checked" : ""}><span>${esc(c.name)}</span><span class="cc">${esc(c.code)} · ${c.servers}</span></label>`).join("")}</div></fieldset>`;
    }).join("") || `<span class="muted">${t("Kein Treffer")}</span>`;
    $$("#ctry input").forEach((i) => (i.onchange = () => { i.checked ? chosen.add(i.value) : chosen.delete(i.value); draw(); }));
    $$("#ctry [data-all]").forEach((b) => (b.onclick = () => {
      const cs = groups.find(([k]) => k === b.dataset.all)[1];
      const all = cs.every((c) => chosen.has(c.code));
      cs.forEach((c) => (all ? chosen.delete(c.code) : chosen.add(c.code)));
      draw();
    }));
    count();
  };
  draw();
  $("#cf").oninput = draw;
  $("#none").onclick = () => { chosen.clear(); draw(); };
  $("#save").onclick = guard(async () => {
    await api(`/vpn/${p.id}`, { method: "PUT", body: { countries: [...chosen], mode } });
    toast(t("{name}: {n} Länder gespeichert", { name: p.name, n: chosen.size }));
    refreshOverview();
  });
}

// --- Ausnahmen & Waechter ----------------------------------------------------------------------------------------
async function viewExemptions(el) {
  const [ex, watch, prot] = await Promise.all([api("/exemptions"), api("/watch"), api("/protect")]);
  const asns = ex.filter((e) => e.kind === "asn"), cidrs = ex.filter((e) => e.kind === "cidr");
  const table = (rows, cols, kind) => rows.length ? `<table><tbody>${rows.map((r) => `<tr>${cols(r)}<td class="actions"><button class="btn ghost sm danger" data-del-${kind}="${esc(r.value ?? r.ip)}" aria-label="${t("{v} entfernen", { v: esc(r.value ?? r.ip) })}">${t("Entfernen")}</button></td></tr>`).join("")}</tbody></table>` : "";
  const sessRows = prot.sessions.map((s) => `<tr><td class="mono">${esc(s.ip)}</td><td>${esc(s.user)}@${esc(s.line)}</td>
      <td>${s.asns.map((a) => `<span class="mono">AS${a.asn}</span> ${esc(a.name)} ${a.protected ? `<span class="tag ok">${t("geschützt")}</span>` : ""}`).join("<br>") || "–"}</td>
      <td>${statusTag(s.status || "frei")}</td>
      <td class="actions">${s.asns.every((a) => a.protected) && s.asns.length ? "" : `<button class="btn sm" data-protect="${esc(s.ip)}">${t("IP und ASN schützen")}</button>`}</td></tr>`).join("");
  const protRows = prot.protected.map((r) => `<tr><td>${r.kind === "asn" ? "ASN" : "IP"}</td><td class="mono">${r.kind === "asn" ? "AS" : ""}${esc(r.value)}</td>
      <td>${esc(r.name || "")}</td><td class="muted">${esc(r.note)}</td>
      <td class="actions"><button class="btn ghost sm danger" data-unprotect="${r.kind}/${esc(r.value)}" aria-label="${t("{v} entfernen", { v: esc(r.value) })}">${t("Entfernen")}</button></td></tr>`).join("");
  el.innerHTML = `
    <div class="section"><div class="section-head"><div><h2>${t("Selbstschutz")}</h2>
        <p class="small muted">${t("Geschützte IPs und ASNs werden nie gesperrt – auch nicht über Spamhaus oder eine bestätigte Plausibilitätsprüfung. Aktive SSH-Sitzungen des Hosts sind automatisch geschützt.")}</p></div>
        ${prot.client_ip ? `<button class="btn" data-protect="${esc(prot.client_ip)}">${t("Meine Browser-IP {ip} schützen", { ip: esc(prot.client_ip) })}</button>` : ""}</div>
      <div class="box">
        <div class="pad-sm row"><h3 class="inline-h">${t("Aktive SSH-Sitzungen")}</h3>
          ${prot.utmp === "ok" ? `<span class="tag ok">${t("erkannt")}</span>` : `<span class="tag captcha">${t("nicht verfügbar")}</span>`}</div>
        ${prot.utmp !== "ok" ? `<div class="note warn small">${t("Damit SSH-Sitzungen automatisch geschützt werden, /var/run/utmp des Hosts schreibgeschützt einbinden:")} <code>- /var/run/utmp:/host/utmp:ro</code>. ${t("Alternativ in der SSH-Sitzung ausführen:")} <code>docker exec -e SSH_CLIENT asn-blocker python -m app.cli protect</code></div>`
          : sessRows ? `<table><tbody>${sessRows}</tbody></table>` : `<div class="empty">${t("Keine SSH-Sitzung von außen aktiv.")}</div>`}
        <div class="pad-sm"><h3 class="inline-h">${t("Dauerhaft geschützt")}</h3></div>
        ${protRows ? `<table><tbody>${protRows}</tbody></table>` : `<div class="empty">${t("Noch nichts geschützt. Schütze mindestens den ASN deines Internetanschlusses.")}</div>`}
        <form class="row pad-sm" id="add-protect"><input type="text" name="v" class="mono" placeholder="${t("IP-Adresse")}" required aria-label="IP"><label class="check-inline"><input type="checkbox" name="asn" checked> ${t("ganzen ASN schützen")}</label><button class="btn">${t("Schützen")}</button></form>
      </div></div>
    <div class="section"><div class="section-head"><div><h2>${t("Ausnahme-ASNs")}</h2><p class="small muted">${t("Prefixe dieser ASNs werden nie gesperrt, z. B. Exit-Netze von VPN-Anbietern.")}</p></div></div>
      <div class="box">${table(asns, (r) => `<td class="mono">AS${esc(r.value)}</td><td>${esc(r.name)}</td><td class="muted">${esc(r.note)}</td>`, "asn")}
      <form class="row pad-sm" id="add-asn"><input type="text" name="v" class="mono" placeholder="AS207137" required aria-label="ASN"><input type="text" name="n" placeholder="${t("Notiz")}" aria-label="${t("Notiz")}"><button class="btn">${t("Hinzufügen")}</button></form></div></div>
    <div class="section"><div class="section-head"><div><h2>${t("IPs und Netze")}</h2><p class="small muted">${t("Einzelne Adressen oder CIDRs, IPv4 und IPv6.")}</p></div></div>
      <div class="box">${table(cidrs, (r) => `<td class="mono">${esc(r.value)}</td><td class="muted">${esc(r.note)}</td>`, "cidr")}
      <form class="row pad-sm" id="add-cidr"><input type="text" name="v" class="mono" placeholder="${t("203.0.113.7 oder 198.51.100.0/24")}" required aria-label="${t("IP oder CIDR")}"><input type="text" name="n" placeholder="${t("Notiz")}" aria-label="${t("Notiz")}"><button class="btn">${t("Hinzufügen")}</button></form></div></div>
    <div class="section"><div class="section-head"><div><h2>${t("Wächter-IPs")}</h2><p class="small muted">${t("Werden bei jedem Lauf geprüft. Wäre eine davon betroffen, steht es im Lauf-Protokoll und du wirst benachrichtigt. Sie sind keine Ausnahme.")}</p></div></div>
      <div class="box">${table(watch, (r) => `<td class="mono">${esc(r.ip)}</td><td class="muted">${esc(r.note)}</td><td>${statusTag(r.last_status)}</td>`, "watch")}
      <form class="row pad-sm" id="add-watch"><input type="text" name="v" class="mono" placeholder="${t("IP-Adresse")}" required aria-label="IP"><input type="text" name="n" placeholder="${t("Notiz, z. B. Handy")}" aria-label="${t("Notiz")}"><button class="btn">${t("Hinzufügen")}</button></form></div></div>`;
  const re = () => { refreshOverview(); viewExemptions(el); };
  const doProtect = async (ip, withAsn = true) => {
    const r = await api("/protect", { method: "POST", body: { ip, with_asn: withAsn } });
    toast(r.asns.length ? t("{ip} und {asns} geschützt", { ip, asns: r.asns.map((a) => "AS" + a).join(", ") }) : t("{ip} geschützt", { ip }));
    re();
  };
  $$("[data-protect]").forEach((b) => (b.onclick = guard(() => doProtect(b.dataset.protect))));
  $("#add-protect").onsubmit = guard(async (e) => { e.preventDefault(); await doProtect(e.target.v.value.trim(), e.target.asn.checked); });
  $$("[data-unprotect]").forEach((b) => (b.onclick = guard(async () => {
    if (!(await confirmDlg(t("Schutz entfernen"), t("Danach kann {v} wieder gesperrt werden. Fortfahren?", { v: esc(b.dataset.unprotect.split("/")[1]) }), t("Entfernen"), "danger"))) return;
    await api(`/protect/${b.dataset.unprotect}`, { method: "DELETE" }); re();
  })));
  $("#add-asn").onsubmit = guard(async (e) => { e.preventDefault(); await api("/exemptions", { method: "POST", body: { kind: "asn", value: e.target.v.value.trim(), note: e.target.n.value } }); re(); });
  $("#add-cidr").onsubmit = guard(async (e) => { e.preventDefault(); await api("/exemptions", { method: "POST", body: { kind: "cidr", value: e.target.v.value.trim(), note: e.target.n.value } }); re(); });
  $("#add-watch").onsubmit = guard(async (e) => { e.preventDefault(); await api("/watch", { method: "POST", body: { ip: e.target.v.value.trim(), note: e.target.n.value } }); re(); });
  $$("[data-del-asn]").forEach((b) => (b.onclick = guard(async () => { await api(`/exemptions/asn/${encodeURIComponent(b.dataset.delAsn)}`, { method: "DELETE" }); re(); })));
  $$("[data-del-cidr]").forEach((b) => (b.onclick = guard(async () => { await api(`/exemptions/cidr/${b.dataset.delCidr}`, { method: "DELETE" }); re(); })));
  $$("[data-del-watch]").forEach((b) => (b.onclick = guard(async () => { await api(`/watch/${encodeURIComponent(b.dataset.delWatch)}`, { method: "DELETE" }); re(); })));
}

// --- Laeufe ----------------------------------------------------------------------------------------------------------
const kindName = (k) => (k === "plan" ? t("Vorschau") : t("Anwenden"));
async function viewRuns(el, id) {
  const runs = await api("/runs");
  const sel = id ? Number(id) : runs[0]?.id;
  el.innerHTML = `<div class="section"><div class="section-head"><div><p class="small muted">${t("Ein Lauf berechnet die Ranges neu und gleicht sie mit CrowdSec ab. „Vorschau“ ändert nichts.")}</p></div>
      <div class="row"><button class="btn" data-run="plan">${t("Vorschau")}</button><button class="btn primary" data-run="apply">${t("Jetzt anwenden")}</button></div></div>
    <div class="box table-wrap">${runs.length ? `<table><thead><tr><th>#</th><th>${t("Art")}</th><th>${t("Status")}</th><th>${t("Gestartet")}</th><th class="hide-sm">${t("Von")}</th><th class="num">Ban</th><th class="num">Captcha</th><th class="num hide-sm">${t("Änderungen")}</th></tr></thead><tbody>
      ${runs.map((r) => { const s = r.summary || {}; const ch = (s.ban_added || 0) + (s.captcha_added || 0), rm = (s.ban_removed || 0) + (s.captcha_removed || 0);
        return `<tr data-id="${r.id}" ${r.id === sel ? `aria-current="true"` : ""}><td class="mono"><a href="#/runs/${r.id}">${r.id}</a></td><td>${kindName(r.kind)}</td>
        <td><span class="dot ${r.status}"></span>${runStatus(r.status)}</td><td title="${fmtTime(r.started_at)}">${ago(r.started_at)}</td><td class="hide-sm">${esc(r.triggered_by)}</td>
        <td class="num mono">${s.ban ?? "–"}</td><td class="num mono">${s.captcha ?? "–"}</td>
        <td class="num mono hide-sm">${r.summary ? `<span class="diff-add">+${ch}</span> <span class="diff-del">−${rm}</span>` : ""}</td></tr>`; }).join("")}
      </tbody></table>` : `<div class="empty">${t("Noch keine Läufe.")}</div>`}</div></div>
    <div id="detail"></div>`;
  $$("[data-run]", el).forEach((b) => (b.onclick = () => startRun(b.dataset.run)));
  const r = sel ? await runDetail(sel) : null;
  if (runs.some((x) => x.status === "running") || r?.status === "running") {
    clearTimeout(runPoll);
    runPoll = setTimeout(() => { if (location.hash.startsWith("#/runs")) viewRuns(el, id).then(refreshOverview); }, 1500);
  }
}

async function runDetail(id) {
  const r = await api("/runs/" + id);
  const s = r.summary || {};
  const changes = r.changes.length ? `<div class="box table-wrap"><table><tbody>${r.changes.slice(0, 200).map((c) => `<tr><td class="mono ${c.op === "+" ? "diff-add" : "diff-del"}">${c.op}</td><td>${statusTag(c.type)}</td><td class="mono">${esc(c.value)}</td></tr>`).join("")}</tbody></table></div>
    ${r.changes.length >= 200 ? `<p class="small muted">${t("Erste 200 von {n} Änderungen.", { n: r.changes.length >= 500 ? "500+" : r.changes.length })}</p>` : ""}` : `<p class="muted small">${t("Keine Änderungen an Ranges.")}</p>`;
  $("#detail").innerHTML = `<div class="section"><div class="section-head"><h2>${t("Lauf")} #${r.id} · ${kindName(r.kind)} · ${runStatus(r.status)}</h2>
      ${r.status === "blocked" ? `<button class="btn danger" id="force">${t("Trotzdem anwenden")}</button>` : ""}
      ${r.kind === "plan" && r.status === "ok" ? `<button class="btn primary" id="apply-now">${t("Diesen Stand anwenden")}</button>` : ""}</div>
    ${s.watch_hits?.length ? `<div class="note danger">${t("Wächter-IPs betroffen:")} <code>${s.watch_hits.map(esc).join(", ")}</code></div>` : ""}
    <div class="grid2"><div><h3>${t("Änderungen")}</h3>${changes}</div><div><h3>${t("Protokoll")}</h3><pre class="log" tabindex="0">${esc(r.log)}</pre></div></div></div>`;
  $("#force")?.addEventListener("click", () => startRun("apply", true));
  $("#apply-now")?.addEventListener("click", () => startRun("apply"));
  return r;
}

// --- Protokoll -------------------------------------------------------------------------------------------------------
const auditName = (a) => ({ "asn.put": t("ASN-Regel gespeichert"), "asn.delete": t("ASN-Regel entfernt"), "vpn.put": t("VPN-Ausnahmen geändert"),
  "exemption.add": t("Ausnahme hinzugefügt"), "exemption.delete": t("Ausnahme entfernt"), "watch.add": t("Wächter-IP hinzugefügt"),
  "watch.delete": t("Wächter-IP entfernt"), "settings.put": t("Einstellungen geändert"), "crowdsec.put": t("CrowdSec-Verbindung geändert"),
  "crowdsec.cleanup": t("Alte Decisions entfernt"), "run.apply": t("Lauf gestartet"), login: t("Angemeldet"), "setup.auth": t("Ersteinrichtung"),
  "account.password": t("Passwort geändert"), import: t("Konfiguration importiert"),
  "protect.add": t("Selbstschutz hinzugefügt"), "protect.delete": t("Selbstschutz entfernt") }[a] ?? a);
async function viewAudit(el) {
  const rows = await api("/audit");
  el.innerHTML = `<div class="box table-wrap">${rows.length ? `<table><thead><tr><th>${t("Zeit")}</th><th>${t("Benutzer")}</th><th>${t("Aktion")}</th><th>${t("Details")}</th></tr></thead><tbody>
    ${rows.map((r) => `<tr><td class="mono small">${fmtTime(r.ts)}</td><td>${esc(r.user)}</td><td>${esc(auditName(r.action))}</td><td class="mono small muted">${esc(auditDetail(r.detail))}</td></tr>`).join("")}</tbody></table>` : `<div class="empty">${t("Noch keine Einträge.")}</div>`}</div>`;
}
function auditDetail(d) {
  if (!d) return "";
  try { const o = JSON.parse(d); return Array.isArray(o) ? o.map((x) => x.asn ? `AS${x.asn} ${x.action}` : JSON.stringify(x)).join(", ").slice(0, 200) : Object.entries(o).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(",") : v}`).join(" ").slice(0, 200); } catch { return d; }
}

// --- Einstellungen -------------------------------------------------------------------------------------------------------
async function viewSettings(el) {
  const s = await api("/settings");
  el.innerHTML = `
  <div class="section"><div class="section-head"><div><h2>${t("CrowdSec-Verbindung")}</h2><p class="small muted">${t("Empfohlen: Local API. Kein Docker-Socket nötig.")}</p></div>${s.crowdsec_mode ? `<span class="tag ok">${t("verbunden ({mode})", { mode: s.crowdsec_mode === "lapi" ? "LAPI" : "Docker" })}</span>` : `<span class="tag captcha">${t("nicht verbunden")}</span>`}</div>
   <form class="box pad" id="cs">
    <label class="field"><span>${t("Modus")}</span><select name="mode"><option value="lapi">${t("Local API (empfohlen)")}</option><option value="docker">${t("Docker-Socket (Legacy)")}</option></select></label>
    <div data-cs="lapi">
      <p class="small">${t("Einmalig im CrowdSec-Container ausführen und das ausgegebene Passwort unten eintragen:")}</p>
      <pre class="cmd">docker exec crowdsec cscli machines add asn-blocker --auto -f -</pre>
      <label class="field"><span>${t("LAPI-URL")}</span><input type="url" name="url" class="mono" value="${esc(s.lapi_url)}"><small>${t("Beide Container müssen im selben Docker-Netz sein.")}</small></label>
      <label class="field"><span>${t("Machine-ID")}</span><input type="text" name="mid" class="mono" value="${esc(s.lapi_machine_id || "asn-blocker")}"></label>
      <label class="field"><span>${t("Passwort")}</span><input type="password" name="pw" class="mono" autocomplete="off" placeholder="${s.lapi_password_set ? t("gespeichert – leer lassen zum Behalten") : ""}"></label>
    </div>
    <div data-cs="docker" hidden><div class="note danger small">${t("Dafür muss /var/run/docker.sock eingebunden werden. Wer die Oberfläche übernimmt, hat dann Root-Rechte auf dem Host.")}</div>
      <label class="field"><span>${t("Container-Name")}</span><input type="text" name="container" class="mono" value="${esc(s.docker_container)}"></label></div>
    <button class="btn primary">${t("Verbindung testen und speichern")}</button></form></div>

  <div class="section"><div class="section-head"><h2>${t("Zeitplan und Sicherheit")}</h2></div><form class="box pad" id="general">
    <div class="grid2"><label class="field"><span>${t("Aktualisierung alle (Stunden)")}</span><input type="number" name="interval_hours" min="6" max="336" value="${s.interval_hours}"></label>
    <label class="field"><span>${t("Gültigkeit einer Sperre (Stunden)")}</span><input type="number" name="decision_hours" min="24" value="${s.decision_hours}">
      <small>${t("Sperren werden vor Ablauf erneuert. Fällt asn-blocker aus, laufen sie nach dieser Zeit aus.")}</small></label></div>
    <div class="grid2"><label class="field"><span>${t("Plausibilitätsgrenze (%)")}</span><input type="number" name="sanity_percent" min="5" max="100" value="${s.sanity_percent}">
      <small>${t("Ändert sich die Anzahl der Ranges stärker, hält ein Lauf an und wartet auf Bestätigung.")}</small></label>
    <label class="field"><span>${t("Spamhaus ASN-DROP")}</span><select name="spamhaus_asndrop"><option value="">${t("nicht verwenden")}</option><option value="ban">${t("automatisch blockieren")}</option><option value="captcha">${t("automatisch Captcha")}</option></select>
      <small>${t("Öffentliche Liste bekannter Abuse-Netze, wird bei jedem Lauf aktualisiert.")}</small></label></div>
    <label class="check"><input type="checkbox" name="include_ipv6" ${s.include_ipv6 ? "checked" : ""}><span>${t("IPv6-Prefixe ebenfalls sperren")}</span></label>
    <h3>${t("Benachrichtigung")}</h3>
    <div class="grid2"><label class="field"><span>URL</span><input type="url" name="notify_url" class="mono" value="${esc(s.notify_url)}" placeholder="https://ntfy.sh/…"></label>
    <label class="field"><span>${t("Format")}</span><select name="notify_format"><option value="ntfy">ntfy</option><option value="gotify">${t("Gotify (Token in der URL)")}</option><option value="webhook">${t("Webhook (JSON)")}</option></select></label></div>
    <h3>${t("Zugriff")}</h3>
    <div class="grid2"><label class="field"><span>${t("Vertrauenswürdige Proxys")}</span><input type="text" name="trusted_proxies" class="mono" value="${esc((s.trusted_proxies || []).join(", "))}">
      <small>${s.auth_mode === "proxy" ? t("Nur von hier werden X-Forwarded-For und der Benutzer-Header akzeptiert.") : t("Nur von hier wird X-Forwarded-For akzeptiert.")}</small></label>
    <label class="field"><span>${t("Benutzer-Header")}</span><input type="text" name="auth_user_header" class="mono" value="${esc(s.auth_user_header)}" ${s.auth_mode === "proxy" ? "" : "disabled"}></label></div>
    <div class="row"><button class="btn primary">${t("Speichern")}</button><button type="button" class="btn" id="ntest">${t("Test-Benachrichtigung")}</button></div></form></div>

  ${s.auth_mode === "local" ? `<div class="section"><div class="section-head"><h2>${t("Passwort ändern")}</h2></div><form class="box pad" id="pw">
    <div class="grid2"><label class="field"><span>${t("Aktuelles Passwort")}</span><input type="password" name="cur" autocomplete="current-password" required></label>
    <label class="field"><span>${t("Neues Passwort")}</span><input type="password" name="new" minlength="12" autocomplete="new-password" required></label></div>
    <button class="btn">${t("Ändern")}</button></form></div>` : ""}

  <div class="section"><div class="section-head"><h2>${t("Wartung")}</h2></div><div class="box pad">
    <div class="row"><a class="btn" href="/api/export" download="asn-blocker.json">${t("Konfiguration exportieren")}</a>
      <label class="btn">${t("Konfiguration importieren")}<input type="file" id="imp" accept="application/json" class="sr-only"></label>
      <a class="btn" href="/api/ranges/ban.txt">${t("Aktive Ban-Ranges")}</a><a class="btn" href="/api/ranges/captcha.txt">${t("Aktive Captcha-Ranges")}</a></div>
    <h3 class="mt">${t("Alte Decisions entfernen")}</h3>
    <p class="small muted">${t("Decisions des alten Bash-Skripts werden von asn-blocker nicht angefasst. Nach dem ersten erfolgreichen Lauf hier entfernen.")}</p>
    <form class="row" id="cleanup"><input type="text" name="reason" value="Auto-Block via ASN Bulk" class="mono" aria-label="Reason"><button class="btn danger">${t("Entfernen")}</button></form>
  </div></div>`;

  const cs = $("#cs");
  cs.mode.value = s.crowdsec_mode || "lapi";
  const csToggle = () => $$("[data-cs]", cs).forEach((d) => (d.hidden = d.dataset.cs !== cs.mode.value));
  cs.mode.onchange = csToggle; csToggle();
  cs.onsubmit = guard(async (e) => {
    e.preventDefault();
    const r = await api("/crowdsec", { method: "PUT", body: { mode: cs.mode.value, lapi_url: cs.url.value.trim(), machine_id: cs.mid.value.trim(), password: cs.pw.value, container: cs.container.value.trim() } });
    toast("CrowdSec: " + t(r.message)); refreshOverview(); viewSettings(el);
  });
  const g = $("#general");
  g.spamhaus_asndrop.value = s.spamhaus_asndrop || "";
  g.notify_format.value = s.notify_format;
  g.onsubmit = guard(async (e) => {
    e.preventDefault();
    await api("/settings", { method: "PUT", body: {
      interval_hours: +g.interval_hours.value, decision_hours: +g.decision_hours.value, sanity_percent: +g.sanity_percent.value,
      include_ipv6: g.include_ipv6.checked, spamhaus_asndrop: g.spamhaus_asndrop.value || null,
      notify_url: g.notify_url.value.trim(), notify_format: g.notify_format.value,
      trusted_proxies: g.trusted_proxies.value.split(",").map((x) => x.trim()).filter(Boolean), auth_user_header: g.auth_user_header.value.trim() } });
    toast(t("Gespeichert")); refreshOverview();
  });
  $("#ntest").onclick = guard(async () => { await api("/notify/test", { method: "POST" }); toast(t("Test gesendet")); });
  $("#pw")?.addEventListener("submit", guard(async (e) => {
    e.preventDefault();
    await api("/account/password", { method: "PUT", body: { current: e.target.cur.value, new: e.target.new.value } });
    toast(t("Passwort geändert – bitte neu anmelden")); boot();
  }));
  $("#imp").onchange = guard(async (e) => {
    const data = JSON.parse(await e.target.files[0].text());
    if (!(await confirmDlg(t("Konfiguration importieren"), t("{a} ASN-Regeln, {e} Ausnahmen und {v} VPN-Länder werden ergänzt bzw. überschrieben.", { a: data.asns?.length || 0, e: data.exemptions?.length || 0, v: data.vpn?.length || 0 }), t("Importieren")))) return;
    await api("/import", { method: "POST", body: data }); toast(t("Importiert")); refreshOverview();
  });
  $("#cleanup").onsubmit = guard(async (e) => {
    e.preventDefault();
    const reason = e.target.reason.value.trim();
    if (!(await confirmDlg(t("Alte Decisions entfernen"), t("Alle Decisions mit Reason {r} werden aus CrowdSec gelöscht.", { r: `<code>${esc(reason)}</code>` }), t("Entfernen"), "danger"))) return;
    const r = await api("/crowdsec/cleanup", { method: "POST", body: { reason } });
    toast(t("{n} Decisions entfernt", { n: r.deleted }));
  });
}

boot();
