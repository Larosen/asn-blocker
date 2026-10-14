// asn-blocker UI – ohne Build-Schritt, ohne Inline-Skripte (CSP).
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtNum = (n) => (n ?? 0).toLocaleString("de-DE");
const fmtAddr = (n) => (n >= 1e6 ? (n / 1e6).toLocaleString("de-DE", { maximumFractionDigits: 1 }) + " Mio." : n >= 1e3 ? (n / 1e3).toLocaleString("de-DE", { maximumFractionDigits: 1 }) + " Tsd." : fmtNum(n));
const fmtTime = (t) => (t ? new Date(t * 1000).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" }) : "–");
function ago(t) {
  if (!t) return "–";
  const s = Date.now() / 1000 - t, f = (v, u) => `${Math.round(v)} ${u}`;
  if (s < 0) { const d = -s; return d < 3600 ? `in ${f(d / 60, "min")}` : d < 172800 ? `in ${f(d / 3600, "h")}` : `in ${f(d / 86400, "Tagen")}`; }
  return s < 90 ? "gerade eben" : s < 3600 ? `vor ${f(s / 60, "min")}` : s < 172800 ? `vor ${f(s / 3600, "h")}` : `vor ${f(s / 86400, "Tagen")}`;
}
const ACTION = { ban: "Blockieren", captcha: "Captcha" };
const RUNSTATUS = { ok: "erfolgreich", failed: "fehlgeschlagen", blocked: "angehalten", running: "läuft" };

async function api(path, { method = "GET", body } = {}) {
  const res = await fetch("/api" + path, {
    method, credentials: "same-origin",
    headers: { "X-Requested-With": "asn-blocker", ...(body !== undefined ? { "Content-Type": "application/json" } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401 && path !== "/login") { boot(); throw new Error("Nicht angemeldet"); }
  const data = res.headers.get("content-type")?.includes("json") ? await res.json() : await res.text();
  if (!res.ok) {
    const d = data?.detail;
    throw new Error(Array.isArray(d) ? d.map((x) => x.msg?.replace(/^Value error, /, "")).join("; ") : d || res.statusText);
  }
  return data;
}

function toast(msg, error = false) {
  const el = document.createElement("div");
  el.className = "toast" + (error ? " error" : "");
  el.textContent = msg;
  $("#toasts").append(el);
  setTimeout(() => el.remove(), error ? 7000 : 3500);
}
const guard = (fn) => async (...a) => { try { await fn(...a); } catch (e) { toast(e.message, true); } };

// Dialog: gibt den Wert des geklickten Buttons zurueck (oder "" bei Abbruch)
function dialog({ title, body, actions = [["cancel", "Abbrechen"], ["ok", "OK", "primary"]], onOpen }) {
  const dlg = $("#dlg");
  $("#dlg-form").innerHTML = `<div class="dh"><h2>${esc(title)}</h2></div><div class="db">${body}</div>
    <div class="df">${actions.map(([v, l, c]) => `<button class="btn ${c || ""}" value="${v}">${esc(l)}</button>`).join("")}</div>`;
  return new Promise((resolve) => {
    dlg.onclose = () => resolve(dlg.returnValue === "cancel" ? "" : dlg.returnValue);
    dlg.returnValue = "";
    dlg.showModal();
    onOpen?.(dlg);
  });
}
const confirmDlg = (title, text, ok = "Bestätigen", cls = "primary") =>
  dialog({ title, body: `<p>${text}</p>`, actions: [["cancel", "Abbrechen"], ["ok", ok, cls]] }).then((v) => v === "ok");

// --- Start: Session / Einrichtung / Login ------------------------------------------------------
let session = null;
async function boot() {
  session = await api("/session").catch(() => null);
  if (!session) { $("#root").textContent = "Server nicht erreichbar."; return; }
  if (session.setup_required) return renderSetup();
  if (!session.user) return session.auth_mode === "local" ? renderLogin() : renderProxyDenied();
  renderShell();
}

function renderSetup() {
  $("#root").className = "";
  $("#root").innerHTML = `<div class="center"><form class="card" id="setup">
    <div class="steps"><span class="on">1 Zugang</span><span>›</span><span>2 CrowdSec</span></div>
    <h1>Ersteinrichtung</h1>
    <p class="lead">Lege fest, wie die Oberfläche geschützt wird.</p>
    <label class="field"><span>Setup-Token</span><input type="text" name="token" class="mono" required autocomplete="off">
      <small>Steht im Container-Log: <code>docker logs asn-blocker</code></small></label>
    <label class="field"><span>Anmeldung</span><select name="mode">
      <option value="proxy">Reverse Proxy mit SSO (Pangolin, Authelia, Authentik …)</option>
      <option value="local">Eigener Login mit Passwort</option></select></label>
    <div data-mode="proxy">
      <label class="field"><span>Vertrauenswürdige Proxy-IPs</span><input type="text" name="trusted" class="mono" value="${esc(session.peer_ip || "")}">
        <small>IP oder CIDR des Reverse Proxys, kommagetrennt. Diese Anfrage kam von <code>${esc(session.peer_ip)}</code>.</small></label>
      <label class="field"><span>Header mit Benutzername</span><input type="text" name="header" class="mono" value="Remote-User">
        <small>Den Header muss der Proxy nach erfolgreichem SSO setzen.</small></label>
    </div>
    <div data-mode="local" hidden>
      <label class="field"><span>Benutzername</span><input type="text" name="username" value="admin" autocomplete="username"></label>
      <label class="field"><span>Passwort</span><input type="password" name="password" minlength="12" autocomplete="new-password"><small>Mindestens 12 Zeichen.</small></label>
    </div>
    <button class="btn primary">Weiter</button>
  </form></div>`;
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
  $("#root").innerHTML = `<div class="center"><form class="card" id="login">
    <h1>asn-blocker</h1><p class="lead">Anmelden</p>
    <label class="field"><span>Benutzername</span><input type="text" name="u" autocomplete="username" required></label>
    <label class="field"><span>Passwort</span><input type="password" name="p" autocomplete="current-password" required></label>
    <button class="btn primary">Anmelden</button></form></div>`;
  const f = $("#login");
  f.onsubmit = guard(async (e) => {
    e.preventDefault();
    await api("/login", { method: "POST", body: { username: f.u.value, password: f.p.value } });
    boot();
  });
}

function renderProxyDenied() {
  $("#root").className = "";
  $("#root").innerHTML = `<div class="center"><div class="card"><h1>Kein Zugriff</h1>
    <p class="lead">Diese Instanz erwartet eine Anmeldung über den Reverse Proxy (SSO). Die Anfrage kam nicht über einen
    vertrauenswürdigen Proxy oder ohne Benutzer-Header.</p>
    <p class="muted small">Zurücksetzen: <code>docker exec asn-blocker python -m app.cli reset-auth</code>, danach Container neu starten.</p></div></div>`;
}

// --- Shell ---------------------------------------------------------------------------------------
const VIEWS = [
  ["overview", "Übersicht"], ["asns", "ASNs"], ["vpn", "VPN-Ausnahmen"], ["exemptions", "Ausnahmen"],
  ["runs", "Läufe"], ["audit", "Protokoll"], ["settings", "Einstellungen"],
];
let ov = null, pollTimer = null;

function renderShell() {
  $("#root").className = "";
  $("#root").innerHTML = `<div class="shell">
    <aside class="side"><div class="brand"><img src="/static/icon.svg" alt="">asn-blocker</div>
      <nav class="nav" aria-label="Hauptnavigation">${VIEWS.map(([id, l]) => `<a href="#/${id}" data-view="${id}">${l}<span class="count" data-count="${id}"></span></a>`).join("")}</nav>
      <div class="side-foot"><span>${esc(session.user)}</span>${session.auth_mode === "local" ? `<a href="#" id="logout">Abmelden</a>` : ""}<span>v${esc(session.version)}</span></div>
    </aside>
    <div class="main"><div id="banners"></div>
      <header class="top"><h1 id="title"></h1>
        <form class="ipcheck" id="ipcheck" role="search"><input type="search" name="ip" placeholder="IP prüfen …" aria-label="IP prüfen" autocomplete="off"></form></header>
      <main class="content" id="view"></main></div></div>
    <div id="applybar"></div>`;
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
let runPoll = null;

function renderBanners() {
  const b = [];
  if (!ov.crowdsec_mode) b.push(`<div class="banner warn"><span class="dot warn"></span><span>CrowdSec ist noch nicht verbunden.</span><a class="btn sm" href="#/settings">Einrichten</a></div>`);
  if (ov.me?.status) b.push(`<div class="banner danger"><span class="dot ban"></span><span>Deine IP <code>${esc(ov.me.ip)}</code> ist aktuell von <b>${ACTION[ov.me.status]}</b> betroffen. Du riskierst, dich auszusperren.</span>
    <button class="btn sm" data-exempt-me="${esc(ov.me.ip)}">Als Ausnahme hinzufügen</button></div>`);
  if (ov.last_apply?.status === "failed") b.push(`<div class="banner danger"><span class="dot failed"></span><span>Letzter Lauf fehlgeschlagen (${ago(ov.last_apply.started_at)}).</span><a class="btn sm" href="#/runs/${ov.last_apply.id}">Details</a></div>`);
  if (ov.last_apply?.status === "blocked") b.push(`<div class="banner warn"><span class="dot blocked"></span><span>Letzter Lauf wurde von der Plausibilitätsprüfung angehalten.</span><a class="btn sm" href="#/runs/${ov.last_apply.id}">Prüfen</a></div>`);
  $("#banners").innerHTML = b.join("");
  $("[data-exempt-me]")?.addEventListener("click", guard(async (e) => {
    await api("/exemptions", { method: "POST", body: { kind: "cidr", value: e.target.dataset.exemptMe, note: "eigene IP" } });
    toast("Eigene IP als Ausnahme gespeichert. Jetzt anwenden, damit es wirkt.");
    refreshOverview();
  }));
}

function renderApplyBar() {
  const el = $("#applybar");
  if (ov.running) {
    el.innerHTML = `<div class="applybar"><span class="dot running"></span><span>Lauf wird ausgeführt …</span><span class="spacer"></span><a class="btn sm" href="#/runs">Ansehen</a></div>`;
  } else if (ov.pending) {
    el.innerHTML = `<div class="applybar"><span class="dot warn"></span><span>Regeln geändert – noch nicht in CrowdSec aktiv.</span><span class="spacer"></span>
      <button class="btn" data-run="plan">Vorschau</button><button class="btn primary" data-run="apply" ${ov.crowdsec_mode ? "" : "disabled"}>Anwenden</button></div>`;
  } else el.innerHTML = "";
  $$("[data-run]", el).forEach((b) => (b.onclick = () => startRun(b.dataset.run)));
}

const startRun = guard(async (kind, force = false) => {
  if (kind === "apply" && !(await confirmDlg("Regeln anwenden", force
    ? "Die Plausibilitätsprüfung wird übergangen. Die berechneten Ranges werden trotz großer Abweichung übertragen."
    : "Ranges werden neu berechnet und mit CrowdSec abgeglichen. Bestehende Sperren bleiben bis zum Abschluss aktiv.", "Anwenden"))) return;
  await api("/runs", { method: "POST", body: { kind, force } });
  toast(kind === "plan" ? "Vorschau wird berechnet …" : "Lauf gestartet");
  if (location.hash === "#/runs") route(); else location.hash = "#/runs";
  setTimeout(refreshOverview, 300);
});

function route() {
  const [view = "overview", arg] = location.hash.replace(/^#\/?/, "").split("/");
  const v = VIEWS.find(([id]) => id === view) ? view : "overview";
  $$(".nav a").forEach((a) => a.setAttribute("aria-current", a.dataset.view === v ? "page" : "false"));
  $("#title").textContent = VIEWS.find(([id]) => id === v)[1];
  clearTimeout(runPoll);
  const el = $("#view");
  el.innerHTML = `<p class="muted">Lade …</p>`;
  ({ overview: viewOverview, asns: viewAsns, vpn: viewVpn, exemptions: viewExemptions, runs: viewRuns, audit: viewAudit, settings: viewSettings })[v](el, arg)
    ?.catch?.((e) => (el.innerHTML = `<div class="note danger">${esc(e.message)}</div>`));
}

// --- IP-Pruefer ----------------------------------------------------------------------------------------
const checkIp = guard(async (ip) => {
  const r = await api("/check/" + encodeURIComponent(ip));
  const st = r.status ? `<span class="tag ${r.status}">${ACTION[r.status]}</span>` : r.exempt.length ? `<span class="tag ok">Ausgenommen</span>` : `<span class="tag">nicht betroffen</span>`;
  const asns = r.asns.map((a) => `<tr><td class="mono">AS${a.asn}</td><td>${esc(a.name)}</td><td>${a.rule ? `<span class="tag ${a.rule}">${ACTION[a.rule]}</span>` : `<span class="muted">keine Regel</span>`}</td></tr>`).join("");
  const body = `<p>${st}</p>
    ${asns ? `<h3>Herkunft</h3><table><tbody>${asns}</tbody></table>${r.prefix ? `<p class="small muted">Prefix ${esc(r.prefix)}</p>` : ""}` : r.global ? "" : `<p class="muted">Keine öffentliche Adresse.</p>`}
    ${Object.entries(r.ranges).map(([t, v]) => `<p>Erfasst durch <b>${ACTION[t]}</b>: <code>${v.map(esc).join(", ")}</code></p>`).join("")}
    ${r.exempt.length ? `<p>Ausgenommen durch: ${r.exempt.map(esc).join(", ")}</p>` : ""}
    ${r.lookup_error ? `<p class="small muted">${esc(r.lookup_error)}</p>` : ""}
    <p class="small muted">Stand: zuletzt angewendeter Lauf.</p>`;
  const v = await dialog({ title: r.ip, body, actions: [["watch", "Als Wächter-IP überwachen"], ["exempt", "Als Ausnahme"], ["cancel", "Schließen", "primary"]] });
  if (v === "watch") { await api("/watch", { method: "POST", body: { ip: r.ip } }); toast("Wächter-IP hinzugefügt"); refreshOverview(); }
  if (v === "exempt") { await api("/exemptions", { method: "POST", body: { kind: "cidr", value: r.ip } }); toast("Ausnahme gespeichert"); refreshOverview(); }
});

// --- Uebersicht ----------------------------------------------------------------------------------------------
async function viewOverview(el) {
  const [o, watch] = await Promise.all([api("/overview"), api("/watch")]);
  ov = o;
  const la = o.last_apply;
  el.innerHTML = `<div class="section"><div class="stats">
      <div class="stat"><div class="label">Blockiert</div><div class="value">${fmtNum(o.applied.ban)}</div><div class="sub">Ranges aktiv</div></div>
      <div class="stat"><div class="label">Captcha</div><div class="value">${fmtNum(o.applied.captcha)}</div><div class="sub">Ranges aktiv</div></div>
      <div class="stat"><div class="label">Letzter Lauf</div><div class="value small">${la ? `<span class="dot ${la.status}"></span>${RUNSTATUS[la.status]}` : "–"}</div><div class="sub">${la ? ago(la.started_at) + " · " + esc(la.triggered_by) : "noch nie angewendet"}</div></div>
      <div class="stat"><div class="label">Nächster Lauf</div><div class="value small">${o.next_run ? ago(o.next_run) : "–"}</div><div class="sub">${o.next_run ? fmtTime(o.next_run) : la ? "CrowdSec nicht verbunden" : "startet nach erstem Anwenden"} · alle ${o.interval_hours} h</div></div>
    </div></div>
    <div class="grid2">
      <div class="section"><div class="section-head"><h2>Regeln</h2></div><div class="box"><table><tbody>
        <tr><td><a href="#/asns">ASNs</a></td><td class="num mono">${o.rules.asns}</td></tr>
        <tr><td><a href="#/vpn">VPN-Länder ausgenommen</a></td><td class="num mono">${o.rules.vpn}</td></tr>
        <tr><td><a href="#/exemptions">Weitere Ausnahmen</a></td><td class="num mono">${o.rules.exemptions}</td></tr>
        <tr><td>ASN-Namensliste</td><td class="num mono">${o.asn_names ? fmtNum(o.asn_names) : `<span class="muted">wird geladen</span>`}</td></tr>
      </tbody></table></div></div>
      <div class="section"><div class="section-head"><h2>Wächter-IPs</h2><a class="small" href="#/exemptions">Verwalten</a></div><div class="box">
        ${watch.length ? `<table><tbody>${watch.map((w) => `<tr><td class="mono">${esc(w.ip)}</td><td>${esc(w.note)}</td><td class="actions">${statusTag(w.last_status)}</td></tr>`).join("")}</tbody></table>`
          : `<div class="empty">Wächter-IPs werden nach jedem Lauf geprüft und melden sich, wenn sie gesperrt würden – z.&nbsp;B. die eigene Mobilfunk-IP.</div>`}
      </div></div>
    </div>
    ${o.me ? `<p class="small muted">Deine IP: <code>${esc(o.me.ip)}</code> – ${o.me.status ? ACTION[o.me.status] : "nicht betroffen"}</p>` : ""}`;
}
const statusTag = (s) => (!s ? `<span class="muted small">noch nicht geprüft</span>` : s === "frei" ? `<span class="tag ok">frei</span>` : `<span class="tag ${s}">${ACTION[s]}</span>`);

// --- ASNs ------------------------------------------------------------------------------------------------------
async function viewAsns(el) {
  el.innerHTML = `<div class="section"><div class="search" id="search">
      <input type="search" id="q" placeholder="ASN suchen – Nummer oder Name, z. B. hetzner, AS16509" autocomplete="off" aria-label="ASN suchen">
      <div class="suggest box" id="suggest" hidden></div></div></div>
    <div class="section"><div class="section-head"><div><h2>Regeln</h2><p class="small muted">Neue Regeln wirken nach „Anwenden“.</p></div>
      <div class="row"><input type="search" id="filter" placeholder="Filtern" aria-label="Regeln filtern"><button class="btn" id="paste">Liste einfügen</button></div></div>
      <div class="box table-wrap" id="rules"></div></div>`;
  let rules = await api("/asns");
  const draw = () => {
    const f = $("#filter").value.toLowerCase();
    const list = rules.filter((r) => !f || `as${r.asn} ${r.name} ${r.note}`.toLowerCase().includes(f));
    $("#rules").innerHTML = rules.length ? `<table><thead><tr><th>ASN</th><th>Name</th><th class="hide-sm">Typ</th><th class="num hide-sm">Prefixe</th><th class="num hide-sm">IPv4-Adressen</th><th>Aktion</th><th>Notiz</th><th></th></tr></thead><tbody>
      ${list.map((r) => `<tr data-asn="${r.asn}"><td class="mono">AS${r.asn}</td><td>${esc(r.name)}${r.cc ? ` <span class="muted small">${esc(r.cc)}</span>` : ""}</td>
        <td class="hide-sm">${classTag(r.class)}</td>
        <td class="num mono hide-sm">${r.stats ? fmtNum(r.stats.v4) + (r.stats.v6 ? ` <span class="muted">+${r.stats.v6}</span>` : "") : `<span class="muted">…</span>`}</td>
        <td class="num mono hide-sm">${r.stats ? fmtAddr(r.stats.addresses) : `<span class="muted">…</span>`}</td>
        <td>${segAction(r.action)}</td>
        <td><input class="inline" data-note value="${esc(r.note)}" placeholder="—" aria-label="Notiz"></td>
        <td class="actions"><button class="btn ghost sm danger" data-del title="Entfernen" aria-label="AS${r.asn} entfernen">Entfernen</button></td></tr>`).join("")}
      </tbody></table>` : `<div class="empty">Noch keine ASNs. Oben suchen oder eine bestehende Liste einfügen.</div>`;
    $$("#rules tr[data-asn]").forEach((tr) => {
      const r = rules.find((x) => x.asn == tr.dataset.asn);
      $$(".seg button", tr).forEach((b) => (b.onclick = guard(async () => { await save({ ...r, action: b.dataset.a }); })));
      $("[data-note]", tr).onchange = guard(async (e) => { await save({ ...r, note: e.target.value }); toast("Notiz gespeichert"); });
      $("[data-del]", tr).onclick = guard(async () => {
        if (!(await confirmDlg("Regel entfernen", `AS${r.asn} ${esc(r.name)} entfernen? Die Ranges werden beim nächsten Anwenden freigegeben.`, "Entfernen", "danger"))) return;
        await api("/asns/" + r.asn, { method: "DELETE" }); await reload();
      });
    });
  };
  const reload = async () => { rules = await api("/asns"); draw(); refreshOverview(); };
  const save = async (r) => { await api("/asns", { method: "PUT", body: [{ asn: r.asn, name: r.name, action: r.action, note: r.note }] }); await reload(); };
  draw();
  $("#filter").oninput = draw;
  if (rules.some((r) => !r.stats)) api("/asns/stats", { method: "POST" }).then(reload).catch(() => {});

  // Suche mit Debounce
  let t, seq = 0;
  const q = $("#q"), sug = $("#suggest");
  q.oninput = () => { clearTimeout(t); t = setTimeout(search, 200); };
  q.onkeydown = (e) => { if (e.key === "Escape") sug.hidden = true; };
  document.addEventListener("click", (e) => { if (!$("#search")?.contains(e.target)) sug.hidden = true; }, { once: false });
  async function search() {
    const term = q.value.trim(), my = ++seq;
    if (!term) { sug.hidden = true; return; }
    let res;
    try { res = await api("/asn/search?q=" + encodeURIComponent(term)); } catch (e) { sug.innerHTML = `<div class="empty">${esc(e.message)}</div>`; sug.hidden = false; return; }
    if (my !== seq) return;
    sug.innerHTML = res.length ? res.map((r, i) => `<div class="item" data-i="${i}"><span class="mono">AS${r.asn}</span><span>${esc(r.name)} ${r.cc ? `<span class="muted small">${esc(r.cc)}</span>` : ""}</span>
        <span class="hide-sm">${classTag(r.class)}</span>
        <span class="row">${r.rule ? `<span class="tag ${r.rule}">${ACTION[r.rule]}</span>` : `<button class="btn sm" data-a="ban">Blockieren</button><button class="btn sm" data-a="captcha">Captcha</button>`}</span></div>`).join("")
      : `<div class="empty">Kein ASN gefunden.</div>`;
    sug.hidden = false;
    $$(".item", sug).forEach((it) => $$("[data-a]", it).forEach((b) => (b.onclick = guard(async () => {
      const r = res[it.dataset.i];
      if (/eyeball/i.test(r.class || "") && !(await confirmDlg("Endkunden-Netz", `AS${r.asn} ${esc(r.name)} ist als <b>Eyeball</b>-Netz (Internetanbieter für Endkunden) eingestuft. Eine Sperre trifft echte Besucher. Trotzdem hinzufügen?`, "Hinzufügen", "danger"))) return;
      await save({ asn: r.asn, name: r.name, action: b.dataset.a, note: "" });
      toast(`AS${r.asn} hinzugefügt`);
      search();
    }))));
  }

  // Liste einfuegen (z. B. ASN_LIST aus dem Bash-Skript)
  $("#paste").onclick = guard(async () => {
    const v = await dialog({ title: "Liste einfügen", body: `<p class="small muted">Eine ASN pro Zeile, optional mit Kommentar: <code>16509   # Amazon AWS</code>. Auskommentierte Zeilen werden übersprungen.</p>
      <textarea id="paste-text" placeholder="15169    # Google&#10;AS8075 Microsoft"></textarea>
      <label class="field"><span>Aktion</span><select id="paste-action"><option value="ban">Blockieren</option><option value="captcha">Captcha</option></select></label>`,
      actions: [["cancel", "Abbrechen"], ["ok", "Vorschau", "primary"]] });
    if (v !== "ok") return;
    const preview = await api("/asns/parse", { method: "POST", body: { text: $("#paste-text").value, action: $("#paste-action").value } });
    if (!preview.length) return toast("Keine ASNs erkannt", true);
    const exist = new Set(rules.map((r) => r.asn));
    const ok = await dialog({ title: `${preview.length} ASNs übernehmen`, body: `<table><tbody>${preview.map((p) => `<tr><td class="mono">AS${p.asn}</td><td>${esc(p.name)}</td><td class="small muted">${esc(p.note)}</td><td>${exist.has(p.asn) ? `<span class="tag">ersetzt</span>` : ""}</td></tr>`).join("")}</tbody></table>`,
      actions: [["cancel", "Abbrechen"], ["ok", "Übernehmen", "primary"]] });
    if (ok !== "ok") return;
    await api("/asns", { method: "PUT", body: preview });
    toast(`${preview.length} ASNs übernommen`);
    await reload();
    api("/asns/stats", { method: "POST" }).then(reload).catch(() => {});
  });
}
const segAction = (a) => `<div class="seg" role="group" aria-label="Aktion">${["ban", "captcha"].map((x) => `<button type="button" class="${x}" data-a="${x}" aria-pressed="${a === x}">${ACTION[x]}</button>`).join("")}</div>`;
const classTag = (c) => (!c || c === "Unknown" ? "" : `<span class="tag" title="Einstufung laut bgp.tools">${esc(c)}</span>`);

// --- VPN -------------------------------------------------------------------------------------------------------
async function viewVpn(el, sel) {
  const provs = await api("/vpn/providers");
  const p = provs.find((x) => x.id === sel) || provs[0];
  el.innerHTML = `<p class="muted lead-p">Server-IPs der gewählten Länder werden aus allen Sperren herausgeschnitten, damit Nutzer dieser VPN-Standorte durchkommen.</p>
    <div class="split"><div class="box plist">${provs.map((x) => `<a href="#/vpn/${x.id}" aria-current="${x.id === p.id}"><span>${esc(x.name)}</span><span class="mono muted small">${x.countries.length || ""}</span></a>`).join("")}</div>
    <div><div class="box pad"><div class="section-head"><div><h2>${esc(p.name)}</h2><p class="small muted">${esc(p.note)}</p></div></div>
      <div class="row small"><span>Ausnahme als</span><div class="seg" id="mode">
        <button type="button" data-m="exact" aria-pressed="${p.mode === "exact"}">exakte Server-IPs</button>
        <button type="button" data-m="net" aria-pressed="${p.mode === "net"}">ganzes Netz (/24, /64)</button></div></div>
      <div class="note warn small" id="netwarn" ${p.mode === "net" ? "" : "hidden"}>VPN-Server stehen meist bei Hostern. Ein ganzes /24 nimmt dort auch fremde Server aus – möglicherweise genau die, die gesperrt werden sollen.</div>
      ${p.exit_asn ? `<div class="note small">Exit-IPs von ${esc(p.name)} können von den Einwahl-IPs abweichen und liegen meist in <code>AS${p.exit_asn}</code>. <button class="btn sm" id="exitasn">AS${p.exit_asn} als Ausnahme-ASN hinzufügen</button></div>` : ""}
    </div>
    <div class="box"><div class="row" id="ctools"><input type="search" id="cf" placeholder="Länder filtern" aria-label="Länder filtern"><span class="spacer"></span>
      <button class="btn sm ghost" id="none">Keine</button><span class="muted small" id="selcount"></span><button class="btn primary" id="save">Speichern</button></div>
      <div class="countries" id="ctry"><span class="muted">Lade Serverliste …</span></div></div></div></div>`;
  $("#ctools").classList.add("pad-sm");
  let mode = p.mode;
  const chosen = new Set(p.countries);
  $$("#mode button").forEach((b) => (b.onclick = () => { mode = b.dataset.m; $$("#mode button").forEach((x) => x.setAttribute("aria-pressed", x === b)); $("#netwarn").hidden = mode !== "net"; }));
  $("#exitasn")?.addEventListener("click", guard(async () => { await api("/exemptions", { method: "POST", body: { kind: "asn", value: String(p.exit_asn), note: `${p.name} Exit-IPs` } }); toast(`AS${p.exit_asn} als Ausnahme gespeichert`); refreshOverview(); }));
  let countries = [];
  try { countries = await api(`/vpn/${p.id}/countries`); } catch (e) { $("#ctry").innerHTML = `<div class="note danger">${esc(e.message)}</div>`; }
  const draw = () => {
    const f = $("#cf").value.toLowerCase();
    const list = countries.filter((c) => !f || c.name.toLowerCase().includes(f) || c.code.toLowerCase() === f)
      .sort((a, b) => chosen.has(b.code) - chosen.has(a.code) || a.name.localeCompare(b.name, "de"));
    if (countries.length) $("#ctry").innerHTML = list.map((c) => `<label><input type="checkbox" value="${esc(c.code)}" ${chosen.has(c.code) ? "checked" : ""}><span>${esc(c.name)}</span><span class="cc">${esc(c.code)} · ${c.servers}</span></label>`).join("") || `<span class="muted">Kein Treffer</span>`;
    $$("#ctry input").forEach((i) => (i.onchange = () => { i.checked ? chosen.add(i.value) : chosen.delete(i.value); $("#selcount").textContent = `${chosen.size} gewählt`; }));
    $("#selcount").textContent = `${chosen.size} gewählt`;
  };
  draw();
  $("#cf").oninput = draw;
  $("#none").onclick = () => { chosen.clear(); draw(); };
  $("#save").onclick = guard(async () => {
    await api(`/vpn/${p.id}`, { method: "PUT", body: { countries: [...chosen], mode } });
    toast(`${p.name}: ${chosen.size === 1 ? "1 Land" : chosen.size + " Länder"} gespeichert`);
    refreshOverview();
  });
}

// --- Ausnahmen & Waechter ----------------------------------------------------------------------------------------
async function viewExemptions(el) {
  const [ex, watch] = await Promise.all([api("/exemptions"), api("/watch")]);
  const asns = ex.filter((e) => e.kind === "asn"), cidrs = ex.filter((e) => e.kind === "cidr");
  const table = (rows, cols, kind) => rows.length ? `<table><tbody>${rows.map((r) => `<tr>${cols(r)}<td class="actions"><button class="btn ghost sm danger" data-del-${kind}="${esc(r.value ?? r.ip)}">Entfernen</button></td></tr>`).join("")}</tbody></table>` : "";
  el.innerHTML = `
    <div class="section"><div class="section-head"><div><h2>Ausnahme-ASNs</h2><p class="small muted">Prefixe dieser ASNs werden nie gesperrt, z. B. Exit-Netze von VPN-Anbietern.</p></div></div>
      <div class="box">${table(asns, (r) => `<td class="mono">AS${esc(r.value)}</td><td>${esc(r.name)}</td><td class="muted">${esc(r.note)}</td>`, "asn")}
      <form class="row pad-sm" id="add-asn"><input type="text" name="v" class="mono" placeholder="AS207137" required aria-label="ASN"><input type="text" name="n" placeholder="Notiz" aria-label="Notiz"><button class="btn">Hinzufügen</button></form></div></div>
    <div class="section"><div class="section-head"><div><h2>IPs und Netze</h2><p class="small muted">Einzelne Adressen oder CIDRs, IPv4 und IPv6.</p></div></div>
      <div class="box">${table(cidrs, (r) => `<td class="mono">${esc(r.value)}</td><td class="muted">${esc(r.note)}</td>`, "cidr")}
      <form class="row pad-sm" id="add-cidr"><input type="text" name="v" class="mono" placeholder="203.0.113.7 oder 198.51.100.0/24" required aria-label="IP oder CIDR"><input type="text" name="n" placeholder="Notiz" aria-label="Notiz"><button class="btn">Hinzufügen</button></form></div></div>
    <div class="section"><div class="section-head"><div><h2>Wächter-IPs</h2><p class="small muted">Werden bei jedem Lauf geprüft. Wäre eine davon betroffen, steht es im Lauf-Protokoll und du wirst benachrichtigt. Sie sind <b>keine</b> Ausnahme.</p></div></div>
      <div class="box">${table(watch, (r) => `<td class="mono">${esc(r.ip)}</td><td class="muted">${esc(r.note)}</td><td>${statusTag(r.last_status)}</td>`, "watch")}
      <form class="row pad-sm" id="add-watch"><input type="text" name="v" class="mono" placeholder="IP-Adresse" required aria-label="IP"><input type="text" name="n" placeholder="Notiz, z. B. Handy" aria-label="Notiz"><button class="btn">Hinzufügen</button></form></div></div>`;
  const re = () => { refreshOverview(); viewExemptions(el); };
  $("#add-asn").onsubmit = guard(async (e) => { e.preventDefault(); await api("/exemptions", { method: "POST", body: { kind: "asn", value: e.target.v.value.trim(), note: e.target.n.value } }); re(); });
  $("#add-cidr").onsubmit = guard(async (e) => { e.preventDefault(); await api("/exemptions", { method: "POST", body: { kind: "cidr", value: e.target.v.value.trim(), note: e.target.n.value } }); re(); });
  $("#add-watch").onsubmit = guard(async (e) => { e.preventDefault(); await api("/watch", { method: "POST", body: { ip: e.target.v.value.trim(), note: e.target.n.value } }); re(); });
  $$("[data-del-asn]").forEach((b) => (b.onclick = guard(async () => { await api(`/exemptions/asn/${encodeURIComponent(b.dataset.delAsn)}`, { method: "DELETE" }); re(); })));
  $$("[data-del-cidr]").forEach((b) => (b.onclick = guard(async () => { await api(`/exemptions/cidr/${b.dataset.delCidr}`, { method: "DELETE" }); re(); })));
  $$("[data-del-watch]").forEach((b) => (b.onclick = guard(async () => { await api(`/watch/${encodeURIComponent(b.dataset.delWatch)}`, { method: "DELETE" }); re(); })));
}

// --- Laeufe ----------------------------------------------------------------------------------------------------------
async function viewRuns(el, id) {
  const runs = await api("/runs");
  const sel = id ? Number(id) : runs[0]?.id;
  el.innerHTML = `<div class="section"><div class="section-head"><div><p class="small muted">Ein Lauf berechnet die Ranges neu und gleicht sie mit CrowdSec ab. „Vorschau“ ändert nichts.</p></div>
      <div class="row"><button class="btn" data-run="plan">Vorschau</button><button class="btn primary" data-run="apply">Jetzt anwenden</button></div></div>
    <div class="box table-wrap">${runs.length ? `<table><thead><tr><th>#</th><th>Art</th><th>Status</th><th>Gestartet</th><th class="hide-sm">Von</th><th class="num">Ban</th><th class="num">Captcha</th><th class="num hide-sm">Änderungen</th></tr></thead><tbody>
      ${runs.map((r) => { const s = r.summary || {}; const ch = (s.ban_added || 0) + (s.captcha_added || 0), rm = (s.ban_removed || 0) + (s.captcha_removed || 0);
        return `<tr data-id="${r.id}" ${r.id === sel ? `aria-selected="true"` : ""}><td class="mono"><a href="#/runs/${r.id}">${r.id}</a></td><td>${r.kind === "plan" ? "Vorschau" : "Anwenden"}</td>
        <td><span class="dot ${r.status}"></span>${RUNSTATUS[r.status]}</td><td title="${fmtTime(r.started_at)}">${ago(r.started_at)}</td><td class="hide-sm">${esc(r.triggered_by)}</td>
        <td class="num mono">${s.ban ?? "–"}</td><td class="num mono">${s.captcha ?? "–"}</td>
        <td class="num mono hide-sm">${r.summary ? `<span class="diff-add">+${ch}</span> <span class="diff-del">−${rm}</span>` : ""}</td></tr>`; }).join("")}
      </tbody></table>` : `<div class="empty">Noch keine Läufe.</div>`}</div></div>
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
    ${r.changes.length >= 200 ? `<p class="small muted">Erste 200 von ${r.changes.length >= 500 ? "500+" : r.changes.length} Änderungen.</p>` : ""}` : `<p class="muted small">Keine Änderungen an Ranges.</p>`;
  $("#detail").innerHTML = `<div class="section"><div class="section-head"><h2>Lauf #${r.id} · ${r.kind === "plan" ? "Vorschau" : "Anwenden"} · ${RUNSTATUS[r.status]}</h2>
      ${r.status === "blocked" ? `<button class="btn danger" id="force">Trotzdem anwenden</button>` : ""}
      ${r.kind === "plan" && r.status === "ok" ? `<button class="btn primary" id="apply-now">Diesen Stand anwenden</button>` : ""}</div>
    ${s.watch_hits?.length ? `<div class="note danger">Wächter-IPs betroffen: <code>${s.watch_hits.map(esc).join(", ")}</code></div>` : ""}
    <div class="grid2"><div><h3>Änderungen</h3>${changes}</div><div><h3>Protokoll</h3><pre class="log">${esc(r.log)}</pre></div></div></div>`;
  $("#force")?.addEventListener("click", () => startRun("apply", true));
  $("#apply-now")?.addEventListener("click", () => startRun("apply"));
  return r;
}

// --- Protokoll -------------------------------------------------------------------------------------------------------
const AUDIT = { "asn.put": "ASN-Regel gespeichert", "asn.delete": "ASN-Regel entfernt", "vpn.put": "VPN-Ausnahmen geändert", "exemption.add": "Ausnahme hinzugefügt",
  "exemption.delete": "Ausnahme entfernt", "watch.add": "Wächter-IP hinzugefügt", "watch.delete": "Wächter-IP entfernt", "settings.put": "Einstellungen geändert",
  "crowdsec.put": "CrowdSec-Verbindung geändert", "crowdsec.cleanup": "Alte Decisions entfernt", "run.apply": "Lauf gestartet", "login": "Angemeldet",
  "setup.auth": "Ersteinrichtung", "account.password": "Passwort geändert", import: "Konfiguration importiert" };
async function viewAudit(el) {
  const rows = await api("/audit");
  el.innerHTML = `<div class="box table-wrap">${rows.length ? `<table><thead><tr><th>Zeit</th><th>Benutzer</th><th>Aktion</th><th>Details</th></tr></thead><tbody>
    ${rows.map((r) => `<tr><td class="mono small">${fmtTime(r.ts)}</td><td>${esc(r.user)}</td><td>${esc(AUDIT[r.action] || r.action)}</td><td class="mono small muted">${esc(auditDetail(r.detail))}</td></tr>`).join("")}</tbody></table>` : `<div class="empty">Noch keine Einträge.</div>`}</div>`;
}
function auditDetail(d) {
  if (!d) return "";
  try { const o = JSON.parse(d); return Array.isArray(o) ? o.map((x) => x.asn ? `AS${x.asn} ${x.action}` : JSON.stringify(x)).join(", ").slice(0, 200) : Object.entries(o).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(",") : v}`).join(" ").slice(0, 200); } catch { return d; }
}

// --- Einstellungen -------------------------------------------------------------------------------------------------------
async function viewSettings(el) {
  const s = await api("/settings");
  el.innerHTML = `
  <div class="section"><div class="section-head"><div><h2>CrowdSec-Verbindung</h2><p class="small muted">Empfohlen: Local API. Kein Docker-Socket nötig.</p></div>${s.crowdsec_mode ? `<span class="tag ok">verbunden (${s.crowdsec_mode === "lapi" ? "LAPI" : "Docker"})</span>` : `<span class="tag captcha">nicht verbunden</span>`}</div>
   <form class="box pad" id="cs">
    <label class="field"><span>Modus</span><select name="mode"><option value="lapi">Local API (empfohlen)</option><option value="docker">Docker-Socket (Legacy)</option></select></label>
    <div data-cs="lapi">
      <p class="small">Einmalig im CrowdSec-Container ausführen und das ausgegebene Passwort unten eintragen:</p>
      <pre class="cmd">docker exec crowdsec cscli machines add asn-blocker --auto -f -</pre>
      <label class="field"><span>LAPI-URL</span><input type="url" name="url" class="mono" value="${esc(s.lapi_url)}"><small>Beide Container müssen im selben Docker-Netz sein.</small></label>
      <label class="field"><span>Machine-ID</span><input type="text" name="mid" class="mono" value="${esc(s.lapi_machine_id || "asn-blocker")}"></label>
      <label class="field"><span>Passwort</span><input type="password" name="pw" class="mono" autocomplete="off" placeholder="${s.lapi_password_set ? "gespeichert – leer lassen zum Behalten" : ""}"></label>
    </div>
    <div data-cs="docker" hidden><div class="note danger small">Dafür muss <code>/var/run/docker.sock</code> eingebunden werden. Wer die Oberfläche übernimmt, hat dann Root-Rechte auf dem Host.</div>
      <label class="field"><span>Container-Name</span><input type="text" name="container" class="mono" value="${esc(s.docker_container)}"></label></div>
    <button class="btn primary">Verbindung testen und speichern</button></form></div>

  <div class="section"><div class="section-head"><h2>Zeitplan und Sicherheit</h2></div><form class="box pad" id="general">
    <div class="grid2"><label class="field"><span>Aktualisierung alle (Stunden)</span><input type="number" name="interval_hours" min="6" max="336" value="${s.interval_hours}"></label>
    <label class="field"><span>Gültigkeit einer Sperre (Stunden)</span><input type="number" name="decision_hours" min="24" value="${s.decision_hours}">
      <small>Sperren werden vor Ablauf erneuert. Fällt asn-blocker aus, laufen sie nach dieser Zeit aus.</small></label></div>
    <div class="grid2"><label class="field"><span>Plausibilitätsgrenze (%)</span><input type="number" name="sanity_percent" min="5" max="100" value="${s.sanity_percent}">
      <small>Ändert sich die Anzahl der Ranges stärker, hält ein Lauf an und wartet auf Bestätigung.</small></label>
    <label class="field"><span>Spamhaus ASN-DROP</span><select name="spamhaus_asndrop"><option value="">nicht verwenden</option><option value="ban">automatisch blockieren</option><option value="captcha">automatisch Captcha</option></select>
      <small>Öffentliche Liste bekannter Abuse-Netze, wird bei jedem Lauf aktualisiert.</small></label></div>
    <label class="check"><input type="checkbox" name="include_ipv6" ${s.include_ipv6 ? "checked" : ""}><span>IPv6-Prefixe ebenfalls sperren</span></label>
    <h3>Benachrichtigung</h3>
    <div class="grid2"><label class="field"><span>URL</span><input type="url" name="notify_url" class="mono" value="${esc(s.notify_url)}" placeholder="https://ntfy.sh/mein-thema"></label>
    <label class="field"><span>Format</span><select name="notify_format"><option value="ntfy">ntfy</option><option value="gotify">Gotify (Token in der URL)</option><option value="webhook">Webhook (JSON)</option></select></label></div>
    <h3>Zugriff</h3>
    <div class="grid2"><label class="field"><span>Vertrauenswürdige Proxys</span><input type="text" name="trusted_proxies" class="mono" value="${esc((s.trusted_proxies || []).join(", "))}">
      <small>Nur von hier werden <code>X-Forwarded-For</code>${s.auth_mode === "proxy" ? " und der Benutzer-Header" : ""} akzeptiert.</small></label>
    <label class="field"><span>Benutzer-Header</span><input type="text" name="auth_user_header" class="mono" value="${esc(s.auth_user_header)}" ${s.auth_mode === "proxy" ? "" : "disabled"}></label></div>
    <div class="row"><button class="btn primary">Speichern</button><button type="button" class="btn" id="ntest">Test-Benachrichtigung</button></div></form></div>

  ${s.auth_mode === "local" ? `<div class="section"><div class="section-head"><h2>Passwort ändern</h2></div><form class="box pad" id="pw">
    <div class="grid2"><label class="field"><span>Aktuelles Passwort</span><input type="password" name="cur" autocomplete="current-password" required></label>
    <label class="field"><span>Neues Passwort</span><input type="password" name="new" minlength="12" autocomplete="new-password" required></label></div>
    <button class="btn">Ändern</button></form></div>` : ""}

  <div class="section"><div class="section-head"><h2>Wartung</h2></div><div class="box pad">
    <div class="row"><a class="btn" href="/api/export" download="asn-blocker.json">Konfiguration exportieren</a>
      <label class="btn">Konfiguration importieren<input type="file" id="imp" accept="application/json" hidden></label>
      <a class="btn" href="/api/ranges/ban.txt">Aktive Ban-Ranges</a><a class="btn" href="/api/ranges/captcha.txt">Aktive Captcha-Ranges</a></div>
    <h3 class="mt">Alte Decisions entfernen</h3>
    <p class="small muted">Decisions des alten Bash-Skripts werden von asn-blocker nicht angefasst. Nach dem ersten erfolgreichen Lauf hier entfernen.</p>
    <form class="row" id="cleanup"><input type="text" name="reason" value="Auto-Block via ASN Bulk" class="mono" aria-label="Reason"><button class="btn danger">Entfernen</button></form>
  </div></div>`;

  const cs = $("#cs");
  cs.mode.value = s.crowdsec_mode || "lapi";
  const csToggle = () => $$("[data-cs]", cs).forEach((d) => (d.hidden = d.dataset.cs !== cs.mode.value));
  cs.mode.onchange = csToggle; csToggle();
  cs.onsubmit = guard(async (e) => {
    e.preventDefault();
    const r = await api("/crowdsec", { method: "PUT", body: { mode: cs.mode.value, lapi_url: cs.url.value.trim(), machine_id: cs.mid.value.trim(), password: cs.pw.value, container: cs.container.value.trim() } });
    toast("CrowdSec: " + r.message); refreshOverview(); viewSettings(el);
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
    toast("Gespeichert"); refreshOverview();
  });
  $("#ntest").onclick = guard(async () => { await api("/notify/test", { method: "POST" }); toast("Test gesendet"); });
  $("#pw")?.addEventListener("submit", guard(async (e) => {
    e.preventDefault();
    await api("/account/password", { method: "PUT", body: { current: e.target.cur.value, new: e.target.new.value } });
    toast("Passwort geändert – bitte neu anmelden"); boot();
  }));
  $("#imp").onchange = guard(async (e) => {
    const data = JSON.parse(await e.target.files[0].text());
    if (!(await confirmDlg("Konfiguration importieren", `${data.asns?.length || 0} ASN-Regeln, ${data.exemptions?.length || 0} Ausnahmen und ${data.vpn?.length || 0} VPN-Länder werden ergänzt bzw. überschrieben.`, "Importieren"))) return;
    await api("/import", { method: "POST", body: data }); toast("Importiert"); refreshOverview();
  });
  $("#cleanup").onsubmit = guard(async (e) => {
    e.preventDefault();
    const reason = e.target.reason.value.trim();
    if (!(await confirmDlg("Alte Decisions entfernen", `Alle Decisions mit Reason <code>${esc(reason)}</code> werden aus CrowdSec gelöscht.`, "Entfernen", "danger"))) return;
    const r = await api("/crowdsec/cleanup", { method: "POST", body: { reason } });
    toast(`${r.deleted} Decisions entfernt`);
  });
}

boot();
