// asn-blocker UI – no build step, no inline scripts (CSP).
import { t } from "./text.js";
import { coverage, mountAtlas } from "./atlas.js";

const LOCALE = "en-GB";
const locale = () => LOCALE;

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtNum = (n) => (n ?? 0).toLocaleString(locale());
const fmtAddr = (n) => (n >= 1e6 ? t("{n} M", { n: (n / 1e6).toLocaleString(locale(), { maximumFractionDigits: 1 }) })
  : n >= 1e3 ? t("{n} K", { n: (n / 1e3).toLocaleString(locale(), { maximumFractionDigits: 1 }) }) : fmtNum(n));
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
const act = (a) => ({ ban: t("Block"), captcha: t("Captcha") }[a] ?? esc(a));
const runStatus = (s) => ({ ok: t("succeeded"), failed: t("failed"), blocked: t("stopped"), running: t("running") }[s] ?? esc(s));
const CONTINENTS = ["EU", "NA", "SA", "AS", "OC", "AF", "AN", ""];
const continentName = (c) => ({ EU: t("Europe"), NA: t("North America"), SA: t("South America"), AS: t("Asia"), AF: t("Africa"),
  OC: t("Oceania"), AN: t("Antarctica") }[c] ?? t("Other"));

async function api(path, { method = "GET", body } = {}) {
  const res = await fetch("/api" + path, {
    method, credentials: "same-origin",
    headers: { "X-Requested-With": "asn-blocker", ...(body !== undefined ? { "Content-Type": "application/json" } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401 && path !== "/login") { boot(); throw new Error(t("Not signed in")); }
  const data = res.headers.get("content-type")?.includes("json") ? await res.json() : await res.text();
  if (!res.ok) {
    const d = data?.detail;
    const err = new Error(Array.isArray(d) ? d.map((x) => t(x.msg?.replace(/^Value error, /, "") ?? "")).join("; ")
      : d && typeof d === "object" ? d.message : t(d || res.statusText));
    err.status = res.status; err.detail = d;
    throw err;
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

// Dialog: resolves to the value of the clicked button ("" on cancel)
function dialog({ title, body, actions = [["cancel", t("Cancel")], ["ok", "OK", "primary"]], onOpen }) {
  const dlg = $("#dlg");
  $("#dlg-form").innerHTML = `<div class="dh"><h2 id="dlg-title">${esc(title)}</h2></div><div class="db">${body}</div>
    <div class="df">${actions.map(([v, l, c]) => `<button class="btn ${c || ""}" value="${v}">${esc(l)}</button>`).join("")}</div>`;
  dlg.setAttribute("aria-labelledby", "dlg-title");
  return new Promise((resolve) => {
    dlg.onclose = () => resolve(dlg.returnValue === "cancel" ? "" : dlg.returnValue);
    dlg.returnValue = "";
    dlg.showModal();
    // Never start on an action button: a stray Enter must not block a network or change a setting
    $('.df button[value="cancel"]', dlg)?.focus();
    onOpen?.(dlg);
  });
}
const confirmDlg = (title, text, ok = t("Confirm"), cls = "primary") =>
  dialog({ title, body: `<p>${text}</p>`, actions: [["cancel", t("Cancel")], ["ok", ok, cls]] }).then((v) => v === "ok");

// --- Start: session / setup / login ------------------------------------------------------
let session = null;
async function boot() {
  applyTheme();
  session = await api("/session").catch(() => null);
  if (!session) { $("#root").textContent = t("Server unreachable."); return; }
  if (session.setup_required) return renderSetup();
  if (!session.user) return session.auth_mode === "local" ? renderLogin() : renderProxyDenied();
  renderShell();
}

// Theme: auto (follows the system), light, dark, or OLED (pure black, for OLED screens)
const THEMES = ["auto", "light", "dark", "oled"];
const THEME_NAMES = { auto: "Auto", light: "Light", dark: "Dark", oled: "OLED black" };
function theme() {
  try { const v = localStorage.getItem("asnb-theme"); if (THEMES.includes(v)) return v; } catch { /* private mode */ }
  return "auto";
}
function applyTheme() {
  const v = theme();
  if (v === "auto") document.documentElement.removeAttribute("data-theme"); else document.documentElement.dataset.theme = v;
  const dark = v === "dark" || v === "oled" || (v === "auto" && matchMedia("(prefers-color-scheme: dark)").matches);
  $('meta[name="theme-color"]')?.setAttribute("content", v === "oled" ? "#000000" : dark ? "#0f1013" : "#f6f6f7");
  atlas?.redraw();
}
const themeSwitch = () => `<button type="button" class="btn ghost sm" id="theme" title="${t("Change theme")}">${t("Theme: {name}", { name: THEME_NAMES[theme()] })}</button>`;
const bindTheme = () => $("#theme")?.addEventListener("click", (e) => {
  const next = THEMES[(THEMES.indexOf(theme()) + 1) % THEMES.length];
  try { localStorage.setItem("asnb-theme", next); } catch { /* private mode */ }
  applyTheme();
  e.currentTarget.textContent = t("Theme: {name}", { name: THEME_NAMES[next] });
});
matchMedia("(prefers-color-scheme: dark)").addEventListener?.("change", applyTheme);

function renderSetup() {
  $("#root").className = "";
  $("#root").innerHTML = `<main class="center"><form class="card" id="setup">
    <div class="row"><div class="steps"><span class="on">${t("1 Access")}</span><span aria-hidden="true">›</span><span>${t("2 CrowdSec")}</span></div><span class="spacer"></span>${themeSwitch()}</div>
    <h1>${t("Initial setup")}</h1>
    <p class="lead">${t("Choose how the interface is protected.")}</p>
    <label class="field"><span>${t("Setup token")}</span><input type="text" name="token" class="mono" required autocomplete="off">
      <small>${t("Printed in the container log:")} <code>docker logs asn-blocker</code></small></label>
    <label class="field"><span>${t("Authentication")}</span><select name="mode">
      <option value="proxy">${t("Reverse proxy with SSO (Pangolin, Authelia, Authentik …)")}</option>
      <option value="local">${t("Built-in login with password")}</option></select></label>
    <div data-mode="proxy">
      <label class="field"><span>${t("Trusted proxies")}</span><input type="text" name="trusted" class="mono" value="${esc(session.peer_name || session.peer_ip || "")}">
        <small>${t("Container name (recommended – it keeps working when the proxy gets a new IP), IP or CIDR of the reverse proxy, comma separated. This request came from {ip}.", { ip: `<code>${esc(session.peer_ip)}</code>${session.peer_name ? ` (<code>${esc(session.peer_name)}</code>)` : ""}` })}</small></label>
      <label class="field"><span>${t("Header with username")}</span><input type="text" name="header" class="mono" value="Remote-User">
        <small>${t("The proxy must set this header after a successful SSO login.")}</small></label>
    </div>
    <div data-mode="local" hidden>
      <label class="field"><span>${t("Username")}</span><input type="text" name="username" value="admin" autocomplete="username"></label>
      <label class="field"><span>${t("Password")}</span><input type="password" name="password" minlength="12" autocomplete="new-password"><small>${t("At least 12 characters.")}</small></label>
    </div>
    <button class="btn primary">${t("Continue")}</button>
  </form></main>`;
  bindTheme();
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
    <div class="row"><h1>asn-blocker</h1><span class="spacer"></span>${themeSwitch()}</div><p class="lead">${t("Sign in")}</p>
    <label class="field"><span>${t("Username")}</span><input type="text" name="u" autocomplete="username" required></label>
    <label class="field"><span>${t("Password")}</span><input type="password" name="p" autocomplete="current-password" required></label>
    <button class="btn primary" id="login-btn">${t("Sign in")}</button></form></main>`;
  bindTheme();
  const f = $("#login");
  f.onsubmit = guard(async (e) => {
    e.preventDefault();
    await api("/login", { method: "POST", body: { username: f.u.value, password: f.p.value } });
    boot();
  });
}

function renderProxyDenied() {
  const d = session.denied || {};
  const who = d.peer_name ? `${d.peer_ip} (${d.peer_name})` : d.peer_ip || "?";
  const fix = !d.peer_trusted && d.peer_ip
    ? `<p class="small">${t("If {ip} is your reverse proxy (e.g. it got a new IP after its container was recreated), trust it:", { ip: `<code>${esc(who)}</code>` })}<br>
      <code>docker exec asn-blocker python -m app.cli trust-proxy ${esc(d.peer_name || d.peer_ip)}</code></p>` : "";
  $("#root").className = "";
  $("#root").innerHTML = `<main class="center"><div class="card"><h1>${t("No access")}</h1>
    <p class="lead">${t("This instance expects authentication via the reverse proxy (SSO). The request did not come through a trusted proxy or lacked the user header.")}</p>
    <div class="note small"><ul>
      <li>${t("Request from")} <code>${esc(who)}</code> – ${d.peer_trusted ? t("trusted proxy") : `<b>${t("not a trusted proxy")}</b>`}</li>
      <li>${t("User header")}: ${d.user_header_present ? t("present") : `<b>${t("missing")}</b>`}</li>
      <li>${t("Headers received (names only):")} <code>${esc((d.headers || []).join(", "))}</code></li></ul></div>
    ${fix}
    <p class="muted small">${t("Start over:")} <code>docker exec asn-blocker python -m app.cli reset-auth</code></p></div></main>`;
}

// --- Shell ---------------------------------------------------------------------------------------
const VIEWS = ["overview", "asns", "attackers", "vpn", "exemptions", "runs", "audit", "settings"];
const viewName = (v) => ({ overview: t("Overview"), asns: t("ASNs"), attackers: t("Attackers"), vpn: t("VPN exemptions"), exemptions: t("Exemptions"),
  runs: t("Runs"), audit: t("Log"), settings: t("Settings") }[v]);
let ov = null, pollTimer = null, runPoll = null;

function renderShell() {
  $("#root").className = "";
  $("#root").innerHTML = `<div class="shell">
    <aside class="side"><div class="brand"><img src="/static/icon.svg" alt=""><span>asn-blocker</span></div>
      <nav class="nav" aria-label="${t("Main navigation")}">${VIEWS.map((id) => `<a href="#/${id}" data-view="${id}">${viewName(id)}<span class="count" data-count="${id}"></span></a>`).join("")}</nav>
      <div class="side-foot"><span>${esc(session.user)}</span>${session.auth_mode === "local" ? `<a href="#" id="logout">${t("Sign out")}</a>` : ""}${themeSwitch()}<span>v${esc(session.version)}</span></div>
    </aside>
    <div class="main"><div id="banners" role="region" aria-label="${t("Notices")}"></div>
      <header class="top"><h1 id="title"></h1>
        <button type="button" class="cmdk-btn" id="cmdk-open" aria-keyshortcuts="${IS_MAC ? "Meta+K" : "Control+K"}"><span class="lbl">${t("Search or jump to …")}</span><kbd>${IS_MAC ? "⌘" : "Ctrl"}</kbd><kbd>K</kbd></button>
        <form class="ipcheck" id="ipcheck" role="search"><input type="search" name="ip" placeholder="${t("Check IP …")}" aria-label="${t("Check IP")}" autocomplete="off"></form></header>
      <main class="content" id="view"></main></div></div>
    <div id="applybar" role="region" aria-label="${t("Changes")}" aria-live="polite"></div>`;
  bindTheme();
  $("#logout")?.addEventListener("click", guard(async (e) => { e.preventDefault(); await api("/logout", { method: "POST" }); boot(); }));
  $("#ipcheck").onsubmit = (e) => { e.preventDefault(); const ip = e.target.ip.value.trim(); if (ip) checkIp(ip); };
  $("#cmdk-open").onclick = openPalette;
  window.onhashchange = route;
  route();
  refreshOverview();
}

// --- Command palette (⌘K / Ctrl+K): every main action from the keyboard ------------------------------------
const IS_MAC = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
const IP_RE = /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f:]*:[0-9a-f:.]+)$/i;
document.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && !e.altKey && e.key.toLowerCase() === "k" && session?.user) { e.preventDefault(); openPalette(); }
});

function goSearch(q) {
  location.hash = "#/asns";
  const fill = () => { const i = $("#q"); if (!i) return false; i.value = q; i.dispatchEvent(new Event("input")); i.focus(); return true; };
  if (!fill()) { const iv = setInterval(() => fill() && clearInterval(iv), 60); setTimeout(() => clearInterval(iv), 3000); }
}
function clickWhenReady(sel) {
  const iv = setInterval(() => { const b = $(sel); if (b) { clearInterval(iv); b.click(); } }, 60);
  setTimeout(() => clearInterval(iv), 3000);
}

function paletteItems(q) {
  const items = VIEWS.map((v) => ({ group: t("Go to"), label: viewName(v), run: () => (location.hash = "#/" + v) }));
  items.push(
    { group: t("Actions"), label: t("Apply rules"), hint: t("sync with CrowdSec"), run: () => startRun("apply") },
    { group: t("Actions"), label: t("Preview"), hint: t("compute without changing anything"), run: () => startRun("plan") },
    { group: t("Actions"), label: t("Suggested ASN lists"), run: () => { location.hash = "#/asns"; clickWhenReady("#suggest-btn"); } },
    { group: t("Actions"), label: t("Paste ASN list"), run: () => { location.hash = "#/asns"; clickWhenReady("#paste"); } },
    { group: t("Actions"), label: t("Change theme"), hint: THEME_NAMES[theme()], run: () => $("#theme")?.click() },
  );
  if (session.auth_mode === "local") items.push({ group: t("Actions"), label: t("Sign out"), run: () => $("#logout")?.click() });
  const s = q.trim();
  const dyn = [];
  if (IP_RE.test(s)) dyn.push({ group: t("Search"), label: t("Check IP {ip}", { ip: s }), hint: t("status, network, rules"), run: () => checkIp(s) },
    { group: t("Search"), label: t("Find the network of {ip}", { ip: s }), run: () => goSearch(s) });
  else if (s.length >= 2) dyn.push({ group: t("Search"), label: t("Search ASNs for “{q}”", { q: s }), run: () => goSearch(s) });
  const needle = s.toLowerCase();
  const fixed = IP_RE.test(s) ? [] : items.filter((i) => !needle || i.label.toLowerCase().includes(needle) || i.group.toLowerCase().includes(needle));
  return IP_RE.test(s) ? dyn : [...fixed, ...dyn];  // matching commands first, free-text search last
}

function openPalette() {
  let dlg = $("#cmdk");
  if (dlg?.open) return;
  if (!dlg) {
    dlg = document.createElement("dialog");
    dlg.id = "cmdk";
    dlg.setAttribute("aria-label", t("Command palette"));
    dlg.innerHTML = `<div class="cmdk-input"><input type="text" role="combobox" aria-expanded="true" aria-controls="cmdk-list" aria-autocomplete="list"
        aria-label="${t("Search or jump to")}" placeholder="${t("Type a command, a view, an ASN or an IP …")}" autocomplete="off" spellcheck="false"></div>
      <ul class="cmdk-list" id="cmdk-list" role="listbox" aria-label="${t("Results")}"></ul>
      <div class="cmdk-foot" aria-hidden="true"><span><kbd>↑</kbd><kbd>↓</kbd>${t("select")}</span><span><kbd>↵</kbd>${t("run")}</span><span><kbd>esc</kbd>${t("close")}</span></div>`;
    document.body.append(dlg);
    dlg.addEventListener("click", (e) => { if (e.target === dlg) dlg.close(); });  // click on the backdrop
  }
  const input = $("input", dlg), list = $("#cmdk-list", dlg);
  let items = [], sel = 0;
  const render = () => {
    items = paletteItems(input.value);
    sel = Math.min(sel, Math.max(0, items.length - 1));
    let group = "";
    list.innerHTML = items.length ? items.map((it, i) => {
      const head = it.group !== group ? `<li class="cmdk-group eyebrow" role="presentation">${esc((group = it.group))}</li>` : "";
      return `${head}<li class="cmdk-item" role="option" id="cmdk-${i}" data-i="${i}" aria-selected="${i === sel}">${esc(it.label)}${it.hint ? `<span class="hint">${esc(it.hint)}</span>` : ""}</li>`;
    }).join("") : `<li class="empty" role="presentation">${t("No matches")}</li>`;
    input.setAttribute("aria-activedescendant", items.length ? `cmdk-${sel}` : "");
    $(`#cmdk-${sel}`, list)?.scrollIntoView({ block: "nearest" });
  };
  const run = (i) => { const it = items[i]; if (!it) return; dlg.close(); it.run(); };
  input.value = ""; sel = 0;
  input.oninput = () => { sel = 0; render(); };
  input.onkeydown = (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); sel = (sel + 1) % Math.max(1, items.length); render(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); sel = (sel - 1 + items.length) % Math.max(1, items.length); render(); }
    else if (e.key === "Enter") { e.preventDefault(); run(sel); }
  };
  list.onclick = (e) => { const li = e.target.closest("[data-i]"); if (li) run(+li.dataset.i); };
  list.onmousemove = (e) => { const li = e.target.closest("[data-i]"); if (li && +li.dataset.i !== sel) { sel = +li.dataset.i; render(); } };
  render();
  dlg.showModal();
  input.focus();
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
  if (!ov.crowdsec_mode) b.push(`<div class="banner warn"><span class="dot warn"></span><span>${t("CrowdSec is not connected yet.")}</span><a class="btn sm" href="#/settings">${t("Set up")}</a></div>`);
  if (ov.me?.status) b.push(`<div class="banner danger" role="alert"><span class="dot ban"></span><span>${t("Your IP {ip} is currently affected by {action}. You risk locking yourself out.", { ip: `<code>${esc(ov.me.ip)}</code>`, action: `<b>${act(ov.me.status)}</b>` })}</span>
    <button class="btn sm" data-exempt-me="${esc(ov.me.ip)}">${t("Add as exemption")}</button></div>`);
  if (ov.untrusted_proxy) b.push(`<div class="banner warn"><span class="dot warn"></span><span>${t("Requests arrive through proxy {ip}, which is not a trusted proxy. Sign-in throttling then applies to everyone behind it together.", { ip: `<code>${esc(ov.untrusted_proxy)}</code>` })}</span><a class="btn sm" href="#/settings">${t("Settings")}</a></div>`);
  if (ov.broad_proxies?.length) b.push(`<div class="banner warn"><span class="dot warn"></span><span>${t("Trusted proxies {nets} cover more than one address. Every host in them can claim any client IP or username – trust only the proxy's own IP.", { nets: `<code>${esc(ov.broad_proxies.join(", "))}</code>` })}</span><a class="btn sm" href="#/settings">${t("Settings")}</a></div>`);
  if (ov.last_apply?.status === "failed") b.push(`<div class="banner danger"><span class="dot failed"></span><span>${t("Last run failed ({when}).", { when: ago(ov.last_apply.started_at) })}</span><a class="btn sm" href="#/runs/${ov.last_apply.id}">${t("Details")}</a></div>`);
  if (ov.last_apply?.status === "blocked") b.push(`<div class="banner warn"><span class="dot blocked"></span><span>${t("The last run was stopped by the sanity check – CrowdSec is unchanged.")} ${esc(stopReasons(ov.last_apply).join(" · "))}</span>
    <a class="btn sm" href="#/runs/${ov.last_apply.id}">${t("Review changes")}</a><button class="btn sm danger" data-confirm-run>${t("Apply anyway")}</button></div>`);
  $("#banners").innerHTML = b.join("");
  $("[data-confirm-run]")?.addEventListener("click", () => reviewStopped(ov.last_apply));
  $("[data-exempt-me]")?.addEventListener("click", guard(async (e) => {
    await api("/exemptions", { method: "POST", body: { kind: "cidr", value: e.target.dataset.exemptMe, note: t("own IP") } });
    toast(t("Your IP was saved as an exemption. Apply to make it effective."));
    refreshOverview();
  }));
}

// Apply bar: shows the expected change (+/- ranges) while rules are not applied yet
let previewSeq = 0;
function renderApplyBar() {
  const el = $("#applybar");
  if (ov.running) {
    el.innerHTML = `<div class="applybar"><span class="dot running"></span><span>${t("Run in progress …")}</span><span class="spacer"></span><a class="btn sm" href="#/runs">${t("View")}</a></div>`;
    return;
  }
  if (!ov.pending) { el.innerHTML = ""; return; }
  el.innerHTML = `<div class="applybar"><span class="dot warn"></span><span>${t("Rules changed – not active in CrowdSec yet.")}</span>
    <span class="muted small mono" id="preview">${t("Computing preview …")}</span><span class="spacer"></span>
    <button class="btn" data-run="plan">${t("Preview")}</button>${ov.last_apply?.status === "blocked"
      ? `<button class="btn danger" data-confirm-run>${t("Apply anyway")}</button>`
      : `<button class="btn primary" data-run="apply" ${ov.crowdsec_mode ? "" : "disabled"}>${t("Apply")}</button>`}</div>`;
  $$("[data-run]", el).forEach((b) => (b.onclick = () => startRun(b.dataset.run)));
  $("[data-confirm-run]", el)?.addEventListener("click", () => reviewStopped(ov.last_apply));
  const my = ++previewSeq;
  api("/preview").then((p) => {
    if (my !== previewSeq || !$("#preview")) return;
    if (p.busy) { setTimeout(renderApplyBar, 1500); return; }
    $("#preview").textContent = p.error ? t("Preview unavailable: {e}", { e: t(p.error) })
      : ["ban", "captcha"].map((k) => `${act(k)} +${fmtNum(p[k].add)} −${fmtNum(p[k].remove)}`).join(" · ");
  }).catch(() => { if ($("#preview")) $("#preview").textContent = ""; });
}

const startRun = guard(async (kind) => {
  if (kind === "apply" && !(await confirmDlg(t("Apply rules"),
    t("Ranges are recomputed and synced with CrowdSec. Existing decisions stay active until it finishes."), t("Apply")))) return;
  await launchRun(kind);
});

// confirm: ID of the stopped run the user accepts – the server only applies a result matching that run
async function launchRun(kind, confirm = null) {
  const prev = ov?.last_apply?.id;
  await api("/runs", { method: "POST", body: confirm ? { kind, confirm } : { kind } });
  toast(kind === "plan" ? t("Computing preview …") : t("Run started"));
  if (location.hash === "#/runs") route(); else location.hash = "#/runs";
  setTimeout(refreshOverview, 300);
  if (kind !== "apply") return;
  const r = await awaitRun(prev);
  if (r?.status === "blocked") reviewStopped(r);
}

// Waits until the apply run started after `prev` has finished
async function awaitRun(prev) {
  for (let i = 0; i < 600; i++) {
    await new Promise((res) => setTimeout(res, 1500));
    const o = await api("/overview").catch(() => null);
    if (o && !o.running && o.last_apply && o.last_apply.id !== prev) return o.last_apply;
  }
  return null;
}

const stopReasons = (r) => r?.summary?.stopped?.length ? r.summary.stopped : [t("The change exceeds the sanity limits.")];

// A stopped run: show why and let the user apply exactly this result in one step
const reviewStopped = guard(async (r) => {
  const s = r.summary || {};
  const add = (s.ban_added || 0) + (s.captcha_added || 0), rm = (s.ban_removed || 0) + (s.captcha_removed || 0);
  const v = await dialog({
    title: t("Run #{id} stopped by the sanity check", { id: r.id }),
    body: `<p>${t("CrowdSec is unchanged. The run would change much more than usual:")}</p>
      <ul>${stopReasons(r).map((x) => `<li>${esc(x)}</li>`).join("")}</ul>
      <p class="mono small">${act("ban")} ${fmtNum(s.ban)} · ${act("captcha")} ${fmtNum(s.captcha)} · <span class="diff-add">+${fmtNum(add)}</span> <span class="diff-del">−${fmtNum(rm)}</span></p>
      <p class="small muted">${t("Expected – for example because you added or removed ASNs or enabled IPv6? Then apply it anyway. If not, review the changes first: a data source may have returned wrong data.")}</p>`,
    actions: [["cancel", t("Not now")], ["review", t("Review changes")], ["ok", t("Apply anyway"), "danger"]],
  });
  if (v === "review") location.hash = `#/runs/${r.id}`;
  if (v === "ok") await launchRun("apply", r.id);
});

function route() {
  const [view = "overview", arg] = location.hash.replace(/^#\/?/, "").split("/");
  const v = VIEWS.includes(view) ? view : "overview";
  $$(".nav a").forEach((a) => (a.dataset.view === v ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current")));
  $("#title").textContent = viewName(v);
  document.title = `${viewName(v)} · asn-blocker`;
  clearTimeout(runPoll);
  const el = $("#view");
  el.innerHTML = `<p class="muted">${t("Loading …")}</p>`;
  ({ overview: viewOverview, asns: viewAsns, attackers: viewAttackers, vpn: viewVpn, exemptions: viewExemptions, runs: viewRuns, audit: viewAudit, settings: viewSettings })[v](el, arg)
    ?.catch?.((e) => (el.innerHTML = `<div class="note danger">${esc(e.message)}</div>`));
}

// --- IP checker ----------------------------------------------------------------------------------------
const checkIp = guard(async (ip) => {
  const r = await api("/check/" + encodeURIComponent(ip));
  const st = r.status ? `<span class="tag ${r.status}">${act(r.status)}</span>` : r.exempt.length ? `<span class="tag ok">${t("Exempt")}</span>` : `<span class="tag">${t("not affected")}</span>`;
  const asns = r.asns.map((a) => `<tr><td class="mono">AS${a.asn}</td><td>${esc(a.name)} <span class="hide-sm">${classTag(a.class)}</span></td><td class="actions">${a.rule ? `<span class="tag ${a.rule}">${act(a.rule)}</span>`
    : `<button class="btn sm" value="ban:${a.asn}">${t("Block")}</button> <button class="btn sm" value="captcha:${a.asn}">${t("Captcha")}</button>`}</td></tr>`).join("");
  const body = `<p>${st}</p>
    ${asns ? `<h3>${t("Origin")}</h3><table><tbody>${asns}</tbody></table>${r.prefix ? `<p class="small muted">${t("Prefix")} ${esc(r.prefix)}</p>` : ""}` : r.global ? "" : `<p class="muted">${t("Not a public address.")}</p>`}
    ${Object.entries(r.ranges).map(([k, v]) => `<p>${t("Covered by {action}:", { action: `<b>${act(k)}</b>` })} <code>${v.map(esc).join(", ")}</code></p>`).join("")}
    ${r.exempt.length ? `<p>${t("Exempt via:")} ${r.exempt.map(esc).join(", ")}</p>` : ""}
    ${r.status && r.vpn_near?.length ? `<div class="note warn small">${t("Probably a VPN exit address: listed {servers} servers are in the same network, and VPN exits often use a neighbouring IP. Select this country for the provider and choose “whole network (/24, /64)”.", { servers: r.vpn_near.map((x) => esc(`${x.name} ${x.country}`)).join(", ") })}
      <a class="btn sm" data-close href="#/vpn/${esc(r.vpn_near[0].provider)}">${t("Open {name}", { name: esc(r.vpn_near[0].name) })}</a></div>` : ""}
    ${r.lookup_error ? `<p class="small muted">${esc(r.lookup_error)}</p>` : ""}
    <p class="small muted">${t("As of the last applied run.")}</p>`;
  const v = await dialog({ title: r.ip, body, actions: [["watch", t("Watch this IP")], ["exempt", t("As exemption")], ["cancel", t("Close"), "primary"]],
    onOpen: (d) => $$("[data-close]", d).forEach((a) => a.addEventListener("click", () => d.close("cancel"))) });
  if (v === "watch") { await api("/watch", { method: "POST", body: { ip: r.ip } }); toast(t("Watched IP added")); refreshOverview(); }
  if (v === "exempt") { await api("/exemptions", { method: "POST", body: { kind: "cidr", value: r.ip } }); toast(t("Exemption saved")); refreshOverview(); }
  const m = /^(ban|captcha):(\d+)$/.exec(v || "");
  if (m) {
    const a = r.asns.find((x) => x.asn === +m[2]);
    if (await addAsnRule({ ...a, via: { ip: r.ip } }, m[1])) { toast(t("AS{asn} added – takes effect with the next run", { asn: a.asn })); refreshOverview(); }
  }
});

// --- Overview ----------------------------------------------------------------------------------------------
// --- Overview: the address-space map is the one signature element; everything else stays quiet ---------------
let atlas = null, atlasData = null;
async function viewOverview(el) {
  const [o, watch] = await Promise.all([api("/overview"), api("/watch")]);
  ov = o;
  const la = o.last_apply;
  el.innerHTML = `<section class="section box atlas" aria-labelledby="atlas-h">
      <div class="atlas-stage" id="atlas-stage" role="img" aria-label="${t("Map of the IPv4 address space, one cell per /16 network; loading")}"></div>
      <div class="atlas-side">
        <span class="eyebrow">${t("IPv4 address space")}</span>
        <h2 id="atlas-h">${t("Loading the map …")}</h2>
        <p id="atlas-p">${t("Every cell is one /16 network, laid out along a Hilbert curve so that neighbouring networks stay together.")}</p>
        <div class="atlas-figures">
          <div><div class="eyebrow">${t("Blocked")}</div><div class="v">${fmtNum(o.applied.ban)}</div><div class="small muted">${t("ranges active")}</div></div>
          <div><div class="eyebrow">${t("Captcha")}</div><div class="v">${fmtNum(o.applied.captcha)}</div><div class="small muted">${t("ranges active")}</div></div>
          <div><div class="eyebrow">${t("Last run")}</div><div class="v small">${la ? `<span class="dot ${la.status}"></span>${runStatus(la.status)}` : "–"}</div><div class="small muted">${la ? ago(la.started_at) + " · " + esc(la.triggered_by) : t("never applied")}</div></div>
          <div><div class="eyebrow">${t("Next run")}</div><div class="v small">${o.next_run ? ago(o.next_run) : "–"}</div><div class="small muted">${o.next_run ? fmtTime(o.next_run) : la ? t("CrowdSec not connected") : t("starts after the first apply")} · ${t("every {h} h", { h: o.interval_hours })}</div></div>
        </div>
        <div class="legend" aria-hidden="true"><span><i class="l-ban"></i>${t("Blocked")}</span><span><i class="l-cap"></i>${t("Captcha")}</span><span><i class="l-free"></i>${t("Not blocked")}</span><span><i class="l-res"></i>${t("Reserved")}</span></div>
      </div>
    </section>
    ${o.attackers_recommended ? `<div class="note warn row hint"><span>${t("{n} networks keep attacking this server – CrowdSec caught several of their IPs this week.", { n: o.attackers_recommended })}</span>
      <span class="spacer"></span><a class="btn sm" href="#/attackers">${t("Review attackers")}</a></div>` : ""}
    <div class="grid2">
      <div class="section"><div class="section-head"><h2>${t("Rules")}</h2></div><div class="box"><table><tbody>
        <tr><td><a href="#/asns">${t("ASNs")}</a></td><td class="num mono">${o.rules.asns}</td></tr>
        <tr><td><a href="#/vpn">${t("Exempt VPN countries")}</a></td><td class="num mono">${o.rules.vpn}</td></tr>
        <tr><td><a href="#/exemptions">${t("Other exemptions")}</a></td><td class="num mono">${o.rules.exemptions}</td></tr>
        <tr><td>${t("ASN name list")}</td><td class="num mono">${o.asn_names ? fmtNum(o.asn_names) : `<span class="muted">${t("loading")}</span>`}</td></tr>
      </tbody></table></div></div>
      <div class="section"><div class="section-head"><h2>${t("Watched IPs")}</h2><a class="small" href="#/exemptions">${t("Manage")}</a></div><div class="box">
        ${watch.length ? `<table><tbody>${watch.map((w) => `<tr><td class="mono">${esc(w.ip)}</td><td>${esc(w.note)}</td><td class="actions">${statusTag(w.last_status)}</td></tr>`).join("")}</tbody></table>`
          : `<div class="empty">${t("Watched IPs are checked after every run and alert you if they would be blocked – e.g. your own mobile IP.")}</div>`}
      </div></div>
    </div>
    ${o.me ? `<p class="small muted">${t("Your IP:")} <code>${esc(o.me.ip)}</code> – ${o.me.status ? act(o.me.status) : t("not affected")}</p>` : ""}`;
  loadAtlas(la?.id ?? 0);
}

async function loadAtlas(key) {
  atlas?.stop(); atlas = null;
  if (atlasData?.key !== key) {
    const [ban, captcha] = await Promise.all([api("/ranges/ban.txt"), api("/ranges/captcha.txt")]);
    atlasData = { key, ban: coverage(ban), captcha: coverage(captcha) };
  }
  const stage = $("#atlas-stage");
  if (!stage) return;  // navigated away meanwhile
  const { ban, captcha } = atlasData;
  const share = (n) => (n / 2 ** 32 * 100).toLocaleString(locale(), { maximumFractionDigits: n / 2 ** 32 < 0.001 ? 3 : 1 });
  $("#atlas-h").textContent = ban.addresses || captcha.addresses
    ? t("{p} % of IPv4 blocked", { p: share(ban.addresses) }) : t("Nothing blocked yet");
  $("#atlas-p").textContent = ban.addresses || captcha.addresses
    ? t("{b} addresses blocked and {c} behind a captcha. Every cell is one /16 network, laid out along a Hilbert curve so that neighbouring networks stay together.",
      { b: fmtAddr(ban.addresses), c: fmtAddr(captcha.addresses) }) + (ban.v6 + captcha.v6 ? " " + t("IPv6 ranges ({n}) are not shown.", { n: fmtNum(ban.v6 + captcha.v6) }) : "")
    : t("Add ASN rules and apply them – blocked networks then light up on this map of the IPv4 address space.");
  stage.setAttribute("aria-label", t("Map of the IPv4 address space: {p} % blocked, {c} % behind a captcha.", { p: share(ban.addresses), c: share(captcha.addresses) }));
  atlas = mountAtlas(stage, atlasData, { ban: t("Block"), captcha: t("Captcha"), free: t("not blocked"), reserved: t("reserved") });
}
const statusTag = (s) => (!s ? `<span class="muted small">${t("not checked yet")}</span>` : s === "ban" || s === "captcha" ? `<span class="tag ${s}">${act(s)}</span>` : `<span class="tag ok">${t("clear")}</span>`);

// --- Attackers: networks behind CrowdSec's own detections, with a recommendation per ASN -------------------------
let attackerDays = 7;
async function viewAttackers(el) {
  const r = await api(`/attackers?days=${attackerDays}`);
  const recTag = (x) => x.kind === "recommend" ? `<span class="tag ${x.action}">${t("Recommended:")} ${act(x.action)}</span>`
    : x.kind === "active" ? `<span class="tag ${x.action}">${act(x.action)}</span>`
    : x.kind === "protected" ? `<span class="tag">${t("protected")}</span>` : `<span class="tag">${t("watch")}</span>`;
  const actions = (row) => row.recommendation.kind === "active" || row.recommendation.kind === "protected" ? ""
    : `<button class="btn sm ${row.recommendation.kind === "recommend" && row.recommendation.action === "ban" ? "danger" : ""}" data-add="ban:${row.asn}">${t("Block")}</button>
       <button class="btn sm" data-add="captcha:${row.asn}">${t("Captcha")}</button>`;
  const since = r.history_since ? new Date(r.history_since + "T00:00:00Z").toLocaleDateString(locale(), { dateStyle: "medium" }) : null;
  el.innerHTML = `<div class="section"><div class="section-head"><div>
      <p class="small muted">${t("Networks whose IPs CrowdSec's own detections caught on this server – community blocklists and manual decisions are not counted. A recommendation appears once a hosting network shows {n} or more attacking IPs; consumer networks are never recommended.", { n: 5 })}</p></div>
      <div class="row"><div class="seg" role="group" aria-label="${t("Period")}">${[7, 30, 90].map((d) => `<button type="button" data-days="${d}" aria-pressed="${d === attackerDays}">${t("{d} days", { d })}</button>`).join("")}</div>
      <button class="btn" id="att-refresh">${t("Update")}</button></div></div>
    ${r.error ? `<div class="note danger">${t("Could not read CrowdSec's alerts:")} ${esc(r.error)}</div>` : ""}
    <p class="small muted">${r.updated ? t("Updated {when}", { when: ago(r.updated) }) : t("Not collected yet")}${since ? " · " + t("history since {d} (CrowdSec itself keeps alerts about a week; asn-blocker keeps a summary for 180 days)", { d: since }) : ""}</p>
    <div class="box table-wrap">${r.rows.length ? `<table><thead><tr><th>ASN</th><th>${t("Name")}</th><th class="num">${t("Attacking IPs")}</th><th class="num hide-sm">${t("Alerts")}</th>
      <th class="hide-sm">${t("Mostly")}</th><th class="hide-sm">${t("Last seen")}</th><th>${t("Recommendation")}</th><th><span class="sr-only">${t("Actions")}</span></th></tr></thead><tbody>
      ${r.rows.map((x) => `<tr><td class="mono">AS${x.asn}</td><td>${esc(x.name) || "–"} ${x.cc ? `<span class="muted small">${esc(x.cc)}</span>` : ""} <span class="hide-sm">${classTag(x.class)}</span></td>
        <td class="num"><button class="btn ghost sm mono" data-ips="${x.asn}" aria-label="${t("Show the {n} IPs of AS{asn}", { n: x.ips, asn: x.asn })}">${fmtNum(x.ips)}</button></td>
        <td class="num mono hide-sm">${fmtNum(x.alerts)}</td>
        <td class="small mono hide-sm">${x.scenarios.map((sc) => esc(sc.name.split("/").pop())).join(", ")}</td>
        <td class="small hide-sm" title="${fmtTime(x.last_seen)}">${ago(x.last_seen)}</td>
        <td>${recTag(x.recommendation)}<div class="small muted">${esc(t(x.recommendation.reason))}</div></td>
        <td class="actions">${actions(x)}</td></tr>`).join("")}</tbody></table>`
      : `<div class="empty">${r.updated ? t("No local detections in this period.") : t("The first collection runs shortly after CrowdSec is connected – or click “Update”.")}</div>`}</div></div>`;
  $$("[data-days]", el).forEach((b) => (b.onclick = () => { attackerDays = +b.dataset.days; route(); }));
  $("#att-refresh").onclick = guard(async () => {
    const res = await api("/attackers/refresh", { method: "POST" });
    toast(t("{n} new alerts", { n: res.new_alerts })); route();
  });
  $$("[data-add]", el).forEach((b) => (b.onclick = guard(async () => {
    const [action, asn] = b.dataset.add.split(":"), row = r.rows.find((x) => x.asn === +asn);
    if (await addAsnRule({ asn: row.asn, name: row.name, class: row.class }, action)) {
      toast(t("AS{asn} added – takes effect with the next run", { asn: row.asn })); refreshOverview(); route();
    }
  })));
  $$("[data-ips]", el).forEach((b) => (b.onclick = guard(async () => {
    const asn = +b.dataset.ips, row = r.rows.find((x) => x.asn === asn), ips = await api(`/attackers/${asn}?days=${attackerDays}`);
    await dialog({ title: t("AS{asn} – attacking IPs", { asn }),
      body: `<p class="small">${esc(row.name)} · ${t("last {d} days", { d: attackerDays })}</p><div class="table-wrap"><table><thead><tr><th>IP</th><th class="num">${t("Alerts")}</th><th>${t("Scenarios")}</th><th>${t("Last seen")}</th></tr></thead><tbody>
        ${ips.map((i) => `<tr><td class="mono">${esc(i.ip)}</td><td class="num mono">${fmtNum(i.alerts)}</td><td class="small mono">${i.scenarios.map((sc) => esc(sc.split("/").pop())).join(", ")}</td><td class="small">${ago(i.last_seen)}</td></tr>`).join("")}</tbody></table></div>`,
      actions: [["cancel", t("Close"), "primary"]] });
  })));
}

// --- ASNs ------------------------------------------------------------------------------------------------------
// One rule from a search hit or an IP check; consumer ISPs ("eyeball" networks) need a confirmation.
async function addAsnRule(a, action) {
  if (/eyeball/i.test(a.class || "") && !(await confirmDlg(t("Consumer network"), t("AS{asn} {name} is classified as an eyeball network (consumer ISP). Blocking it hits real visitors. Add anyway?", { asn: a.asn, name: esc(a.name) }), t("Add"), "danger"))) return false;
  return putRules("/asns", [{ asn: a.asn, name: a.name || "", action, note: a.via ? t("from IP {ip}", { ip: a.via.ip }) : "" }]);
}

// Saves rules; if they would block the network this browser is connected from, asks for an explicit confirmation.
async function putRules(path, body, method = "PUT") {
  try {
    await api(path, { method, body });
    return true;
  } catch (e) {
    if (e.status !== 409 || e.detail?.code !== "own_asn") throw e;
    const asns = e.detail.asns.map((a) => `AS${a}`).join(", ");
    const ok = await confirmDlg(t("Block your own network?"),
      t("{asns} is the network you are connected from right now ({ip}). Blocking it can lock you out of this page and other services – only continue if that is intended, e.g. for a hotel or office network.",
        { asns: `<b>${esc(asns)}</b>`, ip: `<code>${esc(e.detail.ip)}</code>` }), t("Block anyway"), "danger");
    if (!ok) return false;
    await api(path + "?confirm_own=1", { method, body });
    return true;
  }
}

async function viewAsns(el) {
  el.innerHTML = `<div class="section"><div class="search" id="search">
      <input type="search" id="q" placeholder="${t("Search ASN – number, name or an IP, e.g. hetzner, AS16509, 8.8.8.8")}" autocomplete="off" aria-label="${t("Search ASN")}" aria-controls="suggest">
      <div class="suggest box" id="suggest" hidden></div></div></div>
    <div class="section"><div class="section-head"><div><h2>${t("Rules")}</h2><p class="small muted">${t("New rules take effect after “Apply”.")}</p></div>
      <div class="row"><input type="search" id="filter" placeholder="${t("Filter")}" aria-label="${t("Filter rules")}"><button class="btn" id="suggest-btn">${t("Suggestions")}</button><button class="btn" id="paste">${t("Paste list")}</button></div></div>
      <div class="bulk row" id="bulk" hidden><span id="bulk-count"></span><span class="spacer"></span>
        <button class="btn sm" data-bulk="ban">${t("Block")}</button><button class="btn sm" data-bulk="captcha">${t("Captcha")}</button>
        <button class="btn sm danger" data-bulk="delete">${t("Remove")}</button><button class="btn sm ghost" data-bulk="clear">${t("Clear selection")}</button></div>
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
    $("#bulk-count").textContent = t("{n} selected", { n: selected.size });
    const all = $("#sel-all");
    if (all) { const vis = visible(); all.checked = vis.length > 0 && vis.every((r) => selected.has(r.asn)); all.indeterminate = !all.checked && vis.some((r) => selected.has(r.asn)); }
  };
  const draw = () => {
    const list = visible();
    $("#rules").innerHTML = rules.length ? `<table><thead><tr><th class="sel"><input type="checkbox" id="sel-all" aria-label="${t("Select all")}"></th><th>ASN</th><th>${t("Name")}</th><th class="hide-sm">${t("Type")}</th><th class="num hide-sm">${t("Prefixes")}</th><th class="num hide-sm">${t("IPv4 addresses")}</th><th>${t("Action")}</th><th>${t("Note")}</th><th><span class="sr-only">${t("Remove")}</span></th></tr></thead><tbody>
      ${list.map((r) => `<tr data-asn="${r.asn}"><td class="sel"><input type="checkbox" data-sel ${selected.has(r.asn) ? "checked" : ""} aria-label="${t("Select AS{asn}", { asn: r.asn })}"></td><td class="mono">AS${r.asn}</td><td>${esc(r.name)}${r.cc ? ` <span class="muted small">${esc(r.cc)}</span>` : ""}</td>
        <td class="hide-sm">${classTag(r.class)}</td>
        <td class="num mono hide-sm">${r.stats ? fmtNum(r.stats.v4) + (r.stats.v6 ? ` <span class="muted">+${r.stats.v6}</span>` : "") : `<span class="muted">…</span>`}</td>
        <td class="num mono hide-sm">${r.stats ? fmtAddr(r.stats.addresses) : `<span class="muted">…</span>`}</td>
        <td>${segAction(r.action)}</td>
        <td><input class="inline" data-note value="${esc(r.note)}" placeholder="—" aria-label="${t("Note for AS{asn}", { asn: r.asn })}"></td>
        <td class="actions"><button class="btn ghost sm danger" data-del aria-label="${t("Remove AS{asn}", { asn: r.asn })}">${t("Remove")}</button></td></tr>`).join("")}
      </tbody></table>` : `<div class="empty">${t("No ASNs yet. Search above, paste an existing list, or start with the suggestions.")} <button class="btn sm" id="suggest-empty">${t("Show suggestions")}</button></div>`;
    $("#suggest-empty")?.addEventListener("click", () => $("#suggest-btn").click());
    $("#sel-all")?.addEventListener("change", (e) => { for (const r of visible()) e.target.checked ? selected.add(r.asn) : selected.delete(r.asn); draw(); });
    $$("#rules tr[data-asn]").forEach((tr) => {
      const r = rules.find((x) => x.asn == tr.dataset.asn);
      $("[data-sel]", tr).onchange = (e) => { e.target.checked ? selected.add(r.asn) : selected.delete(r.asn); syncBulk(); };
      $$(".seg button", tr).forEach((b) => (b.onclick = guard(async () => { await save([{ ...r, action: b.dataset.a }]); })));
      $("[data-note]", tr).onchange = guard(async (e) => { await save([{ ...r, note: e.target.value }]); toast(t("Note saved")); });
      $("[data-del]", tr).onclick = guard(async () => {
        if (!(await confirmDlg(t("Remove rule"), t("Remove AS{asn} {name}? Its ranges are released on the next apply.", { asn: r.asn, name: esc(r.name) }), t("Remove"), "danger"))) return;
        await api("/asns/" + r.asn, { method: "DELETE" }); await reload();
      });
    });
    syncBulk();
  };
  const reload = async () => { rules = await api("/asns"); draw(); refreshOverview(); };
  const save = async (rs) => { if (await putRules("/asns", rs.map((r) => ({ asn: r.asn, name: r.name, action: r.action, note: r.note })))) await reload(); };
  draw();
  $("#filter").oninput = draw;
  $$("[data-bulk]").forEach((b) => (b.onclick = guard(async () => {
    const pick = rules.filter((r) => selected.has(r.asn));
    if (b.dataset.bulk === "clear") { selected.clear(); draw(); return; }
    if (b.dataset.bulk === "delete") {
      if (!(await confirmDlg(t("Remove rules"), t("Remove {n} ASN rules? Their ranges are released on the next apply.", { n: pick.length }), t("Remove"), "danger"))) return;
      await api("/asns/delete", { method: "POST", body: { asns: pick.map((r) => r.asn) } });
      selected.clear(); await reload(); toast(t("{n} rules removed", { n: pick.length })); return;
    }
    await save(pick.map((r) => ({ ...r, action: b.dataset.bulk })));
    toast(t("{n} rules changed", { n: pick.length }));
  })));
  if (rules.some((r) => !r.stats)) api("/asns/stats", { method: "POST" }).then(reload).catch(() => {});

  // Search with debounce
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
    if (res.length === 1 && res[0].asn === null) {
      const v = res[0].via;
      sug.innerHTML = `<div class="empty">${t("{ip} is not announced by any network right now, so there is no ASN to block.", { ip: `<code>${esc(v.ip)}</code>` })}${v.holder ? `<br>${t("Registered to: {holder}", { holder: esc(v.holder) })}` : ""}</div>`;
      sug.hidden = false;
      return;
    }
    sug.innerHTML = res.length ? res.map((r, i) => `<div class="item" data-i="${i}"><span class="mono">AS${r.asn}</span><span>${esc(r.name)} ${r.cc ? `<span class="muted small">${esc(r.cc)}</span>` : ""}${r.via ? `<br><span class="muted small">${t("IP {ip} is in {prefix}", { ip: esc(r.via.ip), prefix: esc(r.via.prefix || "?") })}</span>` : ""}</span>
        <span class="hide-sm">${classTag(r.class)}</span>
        <span class="row">${r.rule ? `<span class="tag ${r.rule}">${act(r.rule)}</span>` : `<button class="btn sm" data-a="ban">${t("Block")}</button><button class="btn sm" data-a="captcha">${t("Captcha")}</button>`}</span></div>`).join("")
      : `<div class="empty">${t("No ASN found.")}</div>`;
    sug.hidden = false;
    $$(".item", sug).forEach((it) => $$("[data-a]", it).forEach((b) => (b.onclick = guard(async () => {
      const r = res[it.dataset.i];
      if (!(await addAsnRule(r, b.dataset.a))) return;
      await reload();
      toast(t("AS{asn} added", { asn: r.asn }));
      search();
    }))));
  }

  // Paste a list: one ASN per line, optional comment
  $("#paste").onclick = guard(async () => {
    const v = await dialog({ title: t("Paste list"), body: `<p class="small muted">${t("One ASN per line, optionally with a comment:")} <code>16509   # Amazon AWS</code>. ${t("Commented-out lines are skipped.")}</p>
      <label class="field"><span class="sr-only">${t("ASN list")}</span><textarea id="paste-text" placeholder="15169    # Google&#10;AS8075 Microsoft"></textarea></label>
      <label class="field"><span>${t("Action")}</span><select id="paste-action"><option value="ban">${t("Block")}</option><option value="captcha">${t("Captcha")}</option></select></label>`,
      actions: [["cancel", t("Cancel")], ["ok", t("Preview"), "primary"]] });
    if (v !== "ok") return;
    const preview = await api("/asns/parse", { method: "POST", body: { text: $("#paste-text").value, action: $("#paste-action").value } });
    if (!preview.length) return toast(t("No ASNs recognised"), true);
    await reviewImport(preview);
  });

  // Review a list of rules before importing it (paste and suggestions)
  async function reviewImport(preview, { title, note = "", chooseAction = false } = {}) {
    const exist = new Set(rules.map((r) => r.asn));
    const ok = await dialog({ title: title || t("Import {n} ASNs", { n: preview.length }), body: `${note}
      ${chooseAction ? `<label class="field"><span>${t("Action")}</span><select id="sugg-action"><option value="ban">${t("Block")}</option><option value="captcha">${t("Captcha")}</option></select></label>` : ""}
      <table><tbody>${preview.map((p) => `<tr><td class="mono">AS${p.asn}</td><td>${esc(p.name)}</td><td class="small muted">${esc(p.note)}</td><td>${exist.has(p.asn) ? `<span class="tag">${t("replaced")}</span>` : ""}</td></tr>`).join("")}</tbody></table>`,
      actions: [["cancel", t("Cancel")], ["ok", t("Import"), "primary"]],
      onOpen: chooseAction ? () => { $("#sugg-action").value = preview[0]?.action || "ban"; } : undefined });
    if (ok !== "ok") return;
    if (chooseAction) { const a = $("#sugg-action").value; preview = preview.map((p) => ({ ...p, action: a })); }
    if (!(await putRules("/asns", preview))) return;
    toast(t("{n} ASNs imported", { n: preview.length }));
    await reload();
    api("/asns/stats", { method: "POST" }).then(reload).catch(() => {});
  }

  // Curated starting points
  $("#suggest-btn").onclick = guard(async () => {
    const sg = await api("/asns/suggestions");
    const card = (l) => {
      const fresh = l.asns.filter((a) => !a.present && !a.protected).length;
      return `<div class="box pad sugg"><div class="row"><h3>${esc(t(l.title))}</h3><span class="spacer"></span>
        <button class="btn sm" value="${esc(l.id)}" ${fresh ? "" : "disabled"}>${fresh ? t("Review {n} ASNs", { n: fresh }) : t("All added")}</button></div>
        <p class="small">${esc(t(l.description))}</p><div class="note warn small">${esc(t(l.warning))}</div>
        <p class="small muted mono">${l.asns.map((a) => `AS${a.asn} ${esc(a.note)}`).join(" · ")}</p></div>`;
    };
    const spam = `<div class="box pad sugg"><div class="row"><h3>Spamhaus ASN-DROP</h3><span class="spacer"></span>
      <button class="btn sm" value="spamhaus" ${sg.spamhaus ? "disabled" : ""}>${sg.spamhaus ? t("Active") : t("Block automatically")}</button></div>
      <p class="small">${t("Networks run entirely by cybercriminals, maintained by Spamhaus and refreshed on every run. A safe first step.")}</p></div>`;
    const v = await dialog({ title: t("Suggested lists"), body: `<p class="small muted">${t("Not sure where to start? Pick a list – you review every ASN before anything is added.")}</p>${spam}${sg.lists.map(card).join("")}`,
      actions: [["cancel", t("Close")]] });
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
    await reviewImport(preview, { title: t(l.title), chooseAction: true,
      note: `<div class="note warn small">${esc(t(l.warning))}</div>${skipped.length ? `<p class="small muted">${t("Skipped because protected: {list}", { list: esc(skipped.map((a) => `AS${a.asn}`).join(", ")) })}</p>` : ""}` });
  });
}
const segAction = (a) => `<div class="seg" role="group" aria-label="${t("Action")}">${["ban", "captcha"].map((x) => `<button type="button" class="${x}" data-a="${x}" aria-pressed="${a === x}">${act(x)}</button>`).join("")}</div>`;
const classTag = (c) => (!c || c === "Unknown" ? "" : `<span class="tag" title="${t("Classification by bgp.tools")}">${esc(c)}</span>`);

// --- VPN -------------------------------------------------------------------------------------------------------
async function viewVpn(el, sel) {
  const provs = await api("/vpn/providers");
  const p = provs.find((x) => x.id === sel) || provs[0];
  el.innerHTML = `<p class="muted lead-p">${t("Server IPs of the selected countries are carved out of all blocks so users of these VPN locations get through.")}</p>
    <div class="split"><nav class="box plist" aria-label="${t("VPN providers")}">${provs.map((x) => `<a href="#/vpn/${x.id}" ${x.id === p.id ? `aria-current="true"` : ""}><span>${esc(x.name)}</span><span class="mono muted small">${x.countries.length || ""}</span></a>`).join("")}</nav>
    <div><div class="box pad"><div class="section-head"><div><h2>${esc(p.name)}</h2><p class="small muted">${esc(p.note)}</p></div></div>
      <div class="row small"><span id="mode-label">${t("Exempt as")}</span><div class="seg" id="mode" role="group" aria-labelledby="mode-label">
        <button type="button" data-m="exact" aria-pressed="${p.mode === "exact"}">${t("exact server IPs")}</button>
        <button type="button" data-m="net" aria-pressed="${p.mode === "net"}">${t("whole network (/24, /64)")}</button></div></div>
      <div class="note warn small" id="netwarn" ${p.mode === "net" ? "" : "hidden"}>${t("VPN servers usually sit at hosting providers. A whole /24 also exempts other servers there – possibly exactly the ones you want to block.")}</div>
      ${p.exit_asn ? `<div class="note small">${t("{name} users often connect from an exit IP next to the listed server IP – choose “whole network” so the /24 is exempted. Other exits are in {asn}.", { name: esc(p.name), asn: `<code>AS${p.exit_asn}</code>` })} <button class="btn sm" id="exitasn">${t("Add AS{asn} as exempt ASN", { asn: p.exit_asn })}</button></div>` : ""}
    </div>
    <div class="box"><div class="row pad-sm" id="ctools"><input type="search" id="cf" placeholder="${t("Filter countries")}" aria-label="${t("Filter countries")}"><span class="spacer"></span>
      <button class="btn sm ghost" id="none">${t("None")}</button><span class="muted small" id="selcount" aria-live="polite"></span><button class="btn primary" id="save">${t("Save")}</button></div>
      <div class="countries" id="ctry"><span class="muted">${t("Loading server list …")}</span></div></div></div></div>`;
  let mode = p.mode;
  const chosen = new Set(p.countries);
  $$("#mode button").forEach((b) => (b.onclick = () => { mode = b.dataset.m; $$("#mode button").forEach((x) => x.setAttribute("aria-pressed", x === b)); $("#netwarn").hidden = mode !== "net"; }));
  $("#exitasn")?.addEventListener("click", guard(async () => { await api("/exemptions", { method: "POST", body: { kind: "asn", value: String(p.exit_asn), note: t("{name} exit IPs", { name: p.name }) } }); toast(t("AS{asn} saved as exemption", { asn: p.exit_asn })); refreshOverview(); }));
  let countries = [];
  try { countries = await api(`/vpn/${p.id}/countries`); } catch (e) { $("#ctry").innerHTML = `<div class="note danger">${esc(e.message)}</div>`; }
  const count = () => ($("#selcount").textContent = t("{n} selected", { n: chosen.size }));
  const draw = () => {
    if (!countries.length) { count(); return; }
    const f = $("#cf").value.toLowerCase();
    const list = countries.filter((c) => !f || c.name.toLowerCase().includes(f) || c.code.toLowerCase() === f);
    const groups = CONTINENTS.map((k) => [k, list.filter((c) => (c.continent || "") === k).sort((a, b) => a.name.localeCompare(b.name, locale()))]).filter(([, cs]) => cs.length);
    $("#ctry").innerHTML = groups.map(([k, cs]) => {
      const n = cs.filter((c) => chosen.has(c.code)).length;
      return `<fieldset class="continent"><legend><span>${continentName(k)}</span><span class="muted small">${n ? t("{n} of {m}", { n, m: cs.length }) : cs.length}</span>
          <button type="button" class="btn ghost sm" data-all="${k}">${n === cs.length ? t("none") : t("all")}</button></legend>
        <div class="cgrid">${cs.map((c) => `<label><input type="checkbox" value="${esc(c.code)}" ${chosen.has(c.code) ? "checked" : ""}><span>${esc(c.name)}</span><span class="cc">${esc(c.code)} · ${c.servers}</span></label>`).join("")}</div></fieldset>`;
    }).join("") || `<span class="muted">${t("No match")}</span>`;
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
    toast(t("{name}: {n} countries saved", { name: p.name, n: chosen.size }));
    refreshOverview();
  });
}

// --- Exemptions & watched IPs ----------------------------------------------------------------------------------------
async function viewExemptions(el) {
  const [ex, watch, prot] = await Promise.all([api("/exemptions"), api("/watch"), api("/protect")]);
  const asns = ex.filter((e) => e.kind === "asn"), cidrs = ex.filter((e) => e.kind === "cidr");
  const table = (rows, cols, kind) => rows.length ? `<table><tbody>${rows.map((r) => `<tr>${cols(r)}<td class="actions"><button class="btn ghost sm danger" data-del-${kind}="${esc(r.value ?? r.ip)}" aria-label="${t("Remove {v}", { v: esc(r.value ?? r.ip) })}">${t("Remove")}</button></td></tr>`).join("")}</tbody></table>` : "";
  const sessRows = prot.sessions.map((s) => `<tr><td class="mono">${esc(s.ip)}</td><td>${esc(s.user)}@${esc(s.line)}</td>
      <td>${s.asns.map((a) => `<span class="mono">AS${a.asn}</span> ${esc(a.name)} ${a.protected ? `<span class="tag ok">${t("protected")}</span>` : ""}`).join("<br>") || "–"}</td>
      <td>${statusTag(s.status || "clear")}</td>
      <td class="actions">${s.asns.every((a) => a.protected) && s.asns.length ? "" : `<button class="btn sm" data-protect="${esc(s.ip)}">${t("Protect IP and ASN")}</button>`}</td></tr>`).join("");
  const protRows = prot.protected.map((r) => `<tr><td>${r.kind === "asn" ? "ASN" : "IP"}</td><td class="mono">${r.kind === "asn" ? "AS" : ""}${esc(r.value)}</td>
      <td>${esc(r.name || "")}</td><td class="muted">${esc(r.note)}</td>
      <td class="actions"><button class="btn ghost sm danger" data-unprotect="${r.kind}/${esc(r.value)}" aria-label="${t("Remove {v}", { v: esc(r.value) })}">${t("Remove")}</button></td></tr>`).join("");
  el.innerHTML = `
    <div class="section"><div class="section-head"><div><h2>${t("Self-protection")}</h2>
        <p class="small muted">${t("Protected IPs and ASNs are never blocked – not via Spamhaus and not after confirming a sanity check. Active SSH sessions on the host are protected automatically.")}</p></div>
        ${prot.client_ip ? `<button class="btn" data-protect="${esc(prot.client_ip)}">${t("Protect my browser IP {ip}", { ip: esc(prot.client_ip) })}</button>` : ""}</div>
      <div class="box">
        <div class="pad-sm row"><h3 class="inline-h">${t("Active SSH sessions")}</h3>
          ${prot.utmp === "ok" ? `<span class="tag ok">${t("detected")}</span>` : `<span class="tag captcha">${t("not available")}</span>`}</div>
        ${prot.utmp !== "ok" ? `<div class="note warn small">${t("To protect SSH sessions automatically, mount the host's session registry read-only:")} <code>- /run/systemd/sessions:/host/sessions:ro</code> ${t("(older systems without systemd-logind:")} <code>- /var/run/utmp:/host/utmp:ro</code>). ${t("Or run this in your SSH session:")} <code>docker exec -e SSH_CLIENT asn-blocker python -m app.cli protect</code></div>`
          : sessRows ? `<table><tbody>${sessRows}</tbody></table>` : `<div class="empty">${t("No remote SSH session active.")}</div>`}
        <div class="pad-sm"><h3 class="inline-h">${t("Permanently protected")}</h3></div>
        ${protRows ? `<table><tbody>${protRows}</tbody></table>` : `<div class="empty">${t("Nothing protected yet. Protect at least the ASN of your internet connection.")}</div>`}
        <form class="row pad-sm" id="add-protect"><input type="text" name="v" class="mono" placeholder="${t("IP address")}" required aria-label="IP"><label class="check-inline"><input type="checkbox" name="asn" checked> ${t("protect whole ASN")}</label><button class="btn">${t("Protect")}</button></form>
      </div></div>
    <div class="section"><div class="section-head"><div><h2>${t("Exempt ASNs")}</h2><p class="small muted">${t("Prefixes of these ASNs are never blocked, e.g. VPN providers’ exit networks.")}</p></div></div>
      <div class="box">${table(asns, (r) => `<td class="mono">AS${esc(r.value)}</td><td>${esc(r.name)}</td><td class="muted">${esc(r.note)}</td>`, "asn")}
      <form class="row pad-sm" id="add-asn"><input type="text" name="v" class="mono" placeholder="AS207137" required aria-label="ASN"><input type="text" name="n" placeholder="${t("Note")}" aria-label="${t("Note")}"><button class="btn">${t("Add")}</button></form></div></div>
    <div class="section"><div class="section-head"><div><h2>${t("IPs and networks")}</h2><p class="small muted">${t("Single addresses or CIDRs, IPv4 and IPv6.")}</p></div></div>
      <div class="box">${table(cidrs, (r) => `<td class="mono">${esc(r.value)}</td><td class="muted">${esc(r.note)}</td>`, "cidr")}
      <form class="row pad-sm" id="add-cidr"><input type="text" name="v" class="mono" placeholder="${t("203.0.113.7 or 198.51.100.0/24")}" required aria-label="${t("IP or CIDR")}"><input type="text" name="n" placeholder="${t("Note")}" aria-label="${t("Note")}"><button class="btn">${t("Add")}</button></form></div></div>
    <div class="section"><div class="section-head"><div><h2>${t("Watched IPs")}</h2><p class="small muted">${t("Checked on every run. If one would be affected, it shows in the run log and you get notified. They are not exemptions.")}</p></div></div>
      <div class="box">${table(watch, (r) => `<td class="mono">${esc(r.ip)}</td><td class="muted">${esc(r.note)}</td><td>${statusTag(r.last_status)}</td>`, "watch")}
      <form class="row pad-sm" id="add-watch"><input type="text" name="v" class="mono" placeholder="${t("IP address")}" required aria-label="IP"><input type="text" name="n" placeholder="${t("Note, e.g. phone")}" aria-label="${t("Note")}"><button class="btn">${t("Add")}</button></form></div></div>`;
  const re = () => { refreshOverview(); viewExemptions(el); };
  const doProtect = async (ip, withAsn = true) => {
    const r = await api("/protect", { method: "POST", body: { ip, with_asn: withAsn } });
    toast(r.asns.length ? t("{ip} and {asns} protected", { ip, asns: r.asns.map((a) => "AS" + a).join(", ") }) : t("{ip} protected", { ip }));
    re();
  };
  $$("[data-protect]").forEach((b) => (b.onclick = guard(() => doProtect(b.dataset.protect))));
  $("#add-protect").onsubmit = guard(async (e) => { e.preventDefault(); await doProtect(e.target.v.value.trim(), e.target.asn.checked); });
  $$("[data-unprotect]").forEach((b) => (b.onclick = guard(async () => {
    if (!(await confirmDlg(t("Remove protection"), t("{v} can then be blocked again. Continue?", { v: esc(b.dataset.unprotect.split("/")[1]) }), t("Remove"), "danger"))) return;
    await api(`/protect/${b.dataset.unprotect}`, { method: "DELETE" }); re();
  })));
  $("#add-asn").onsubmit = guard(async (e) => { e.preventDefault(); await api("/exemptions", { method: "POST", body: { kind: "asn", value: e.target.v.value.trim(), note: e.target.n.value } }); re(); });
  $("#add-cidr").onsubmit = guard(async (e) => { e.preventDefault(); await api("/exemptions", { method: "POST", body: { kind: "cidr", value: e.target.v.value.trim(), note: e.target.n.value } }); re(); });
  $("#add-watch").onsubmit = guard(async (e) => { e.preventDefault(); await api("/watch", { method: "POST", body: { ip: e.target.v.value.trim(), note: e.target.n.value } }); re(); });
  $$("[data-del-asn]").forEach((b) => (b.onclick = guard(async () => { await api(`/exemptions/asn/${encodeURIComponent(b.dataset.delAsn)}`, { method: "DELETE" }); re(); })));
  $$("[data-del-cidr]").forEach((b) => (b.onclick = guard(async () => { await api(`/exemptions/cidr/${b.dataset.delCidr}`, { method: "DELETE" }); re(); })));
  $$("[data-del-watch]").forEach((b) => (b.onclick = guard(async () => { await api(`/watch/${encodeURIComponent(b.dataset.delWatch)}`, { method: "DELETE" }); re(); })));
}

// --- Runs ----------------------------------------------------------------------------------------------------------
const kindName = (k) => (k === "plan" ? t("Preview") : t("Apply"));
async function viewRuns(el, id) {
  const runs = await api("/runs");
  const sel = id ? Number(id) : runs[0]?.id;
  el.innerHTML = `<div class="section"><div class="section-head"><div><p class="small muted">${t("A run recomputes the ranges and syncs them with CrowdSec. “Preview” changes nothing.")}</p></div>
      <div class="row"><button class="btn" data-run="plan">${t("Preview")}</button><button class="btn primary" data-run="apply">${t("Apply now")}</button></div></div>
    <div class="box table-wrap">${runs.length ? `<table><thead><tr><th>#</th><th>${t("Type")}</th><th>${t("Status")}</th><th>${t("Started")}</th><th class="hide-sm">${t("By")}</th><th class="num">Ban</th><th class="num">Captcha</th><th class="num hide-sm">${t("Changes")}</th></tr></thead><tbody>
      ${runs.map((r) => { const s = r.summary || {}; const ch = (s.ban_added || 0) + (s.captcha_added || 0), rm = (s.ban_removed || 0) + (s.captcha_removed || 0);
        return `<tr data-id="${r.id}" ${r.id === sel ? `aria-current="true"` : ""}><td class="mono"><a href="#/runs/${r.id}">${r.id}</a></td><td>${kindName(r.kind)}</td>
        <td><span class="dot ${r.status}"></span>${runStatus(r.status)}</td><td title="${fmtTime(r.started_at)}">${ago(r.started_at)}</td><td class="hide-sm">${esc(r.triggered_by)}</td>
        <td class="num mono">${s.ban ?? "–"}</td><td class="num mono">${s.captcha ?? "–"}</td>
        <td class="num mono hide-sm">${r.summary ? `<span class="diff-add">+${ch}</span> <span class="diff-del">−${rm}</span>` : ""}</td></tr>`; }).join("")}
      </tbody></table>` : `<div class="empty">${t("No runs yet.")}</div>`}</div></div>
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
    ${r.changes.length >= 200 ? `<p class="small muted">${t("First 200 of {n} changes.", { n: r.changes.length >= 500 ? "500+" : r.changes.length })}</p>` : ""}` : `<p class="muted small">${t("No range changes.")}</p>`;
  $("#detail").innerHTML = `<div class="section"><div class="section-head"><h2>${t("Run")} #${r.id} · ${kindName(r.kind)} · ${runStatus(r.status)}</h2>
      ${r.status === "blocked" && r.id === ov?.last_apply?.id ? `<button class="btn danger" id="force">${t("Apply anyway")}</button>` : ""}
      ${r.kind === "plan" && r.status === "ok" ? `<button class="btn primary" id="apply-now">${t("Apply this state")}</button>` : ""}</div>
    ${r.status === "blocked" ? `<div class="note warn">${t("Stopped by the sanity check – CrowdSec is unchanged:")}<ul>${stopReasons(r).map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>` : ""}
    ${s.watch_hits?.length ? `<div class="note danger">${t("Watched IPs affected:")} <code>${s.watch_hits.map(esc).join(", ")}</code></div>` : ""}
    <div class="grid2"><div><h3>${t("Changes")}</h3>${changes}</div><div><h3>${t("Log")}</h3><pre class="log" tabindex="0">${esc(r.log)}</pre></div></div></div>`;
  $("#force")?.addEventListener("click", () => reviewStopped(r));
  $("#apply-now")?.addEventListener("click", () => startRun("apply"));
  return r;
}

// --- Audit log -------------------------------------------------------------------------------------------------------
const auditName = (a) => ({ "asn.put": t("ASN rule saved"), "asn.delete": t("ASN rule removed"), "vpn.put": t("VPN exemptions changed"),
  "exemption.add": t("Exemption added"), "exemption.delete": t("Exemption removed"), "watch.add": t("Watched IP added"),
  "watch.delete": t("Watched IP removed"), "settings.put": t("Settings changed"), "notify.put": t("Notifications changed"), "crowdsec.put": t("CrowdSec connection changed"),
  "crowdsec.cleanup": t("Old decisions removed"), "run.apply": t("Run started"), login: t("Signed in"), "setup.auth": t("Initial setup"),
  "account.password": t("Password changed"), import: t("Configuration imported"),
  "protect.add": t("Self-protection added"), "protect.delete": t("Self-protection removed"),
  "proxy.trust": t("Proxy trusted"), "proxy.names_learned": t("Proxy container name learned") }[a] ?? a);
async function viewAudit(el) {
  const rows = await api("/audit");
  el.innerHTML = `<div class="box table-wrap">${rows.length ? `<table><thead><tr><th>${t("Time")}</th><th>${t("User")}</th><th>${t("Action")}</th><th>${t("Details")}</th></tr></thead><tbody>
    ${rows.map((r) => `<tr><td class="mono small">${fmtTime(r.ts)}</td><td>${esc(r.user)}</td><td>${esc(auditName(r.action))}</td><td class="mono small muted">${esc(auditDetail(r.detail))}</td></tr>`).join("")}</tbody></table>` : `<div class="empty">${t("No entries yet.")}</div>`}</div>`;
}
function auditDetail(d) {
  if (!d) return "";
  try { const o = JSON.parse(d); return Array.isArray(o) ? o.map((x) => x.asn ? `AS${x.asn} ${x.action}` : JSON.stringify(x)).join(", ").slice(0, 200) : Object.entries(o).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(",") : v}`).join(" ").slice(0, 200); } catch { return d; }
}

// --- Settings -------------------------------------------------------------------------------------------------------
async function viewSettings(el) {
  const s = await api("/settings");
  el.innerHTML = `
  <div class="section"><div class="section-head"><div><h2>${t("CrowdSec connection")}</h2><p class="small muted">${t("Recommended: Local API. No Docker socket needed.")}</p></div>${s.crowdsec_mode ? `<span class="tag ok">${t("connected ({mode})", { mode: s.crowdsec_mode === "lapi" ? "LAPI" : "Docker" })}</span>` : `<span class="tag captcha">${t("not connected")}</span>`}</div>
   <form class="box pad" id="cs">
    <label class="field"><span>${t("Mode")}</span><select name="mode"><option value="lapi">${t("Local API (recommended)")}</option><option value="docker">${t("Docker socket (legacy)")}</option></select></label>
    <div data-cs="lapi">
      <p class="small">${t("Run once in the CrowdSec container and enter the printed password below:")}</p>
      <pre class="cmd">docker exec crowdsec cscli machines add asn-blocker --auto -f -</pre>
      <label class="field"><span>${t("LAPI URL")}</span><input type="url" name="url" class="mono" value="${esc(s.lapi_url)}"><small>${t("Both containers must share a Docker network.")}</small></label>
      <label class="field"><span>${t("Machine ID")}</span><input type="text" name="mid" class="mono" value="${esc(s.lapi_machine_id || "asn-blocker")}"></label>
      <label class="field"><span>${t("Password")}</span><input type="password" name="pw" class="mono" autocomplete="off" placeholder="${s.lapi_password_set ? t("saved – leave empty to keep (required again if URL or machine ID change)") : ""}"></label>
    </div>
    <div data-cs="docker" hidden><div class="note danger small">${t("This requires mounting /var/run/docker.sock. Whoever takes over the UI then has root on the host.")}</div>
      <label class="field"><span>${t("Container name")}</span><input type="text" name="container" class="mono" value="${esc(s.docker_container)}"></label></div>
    <button class="btn primary">${t("Test connection and save")}</button></form></div>

  <div class="section"><div class="section-head"><h2>${t("Schedule and safety")}</h2></div><form class="box pad" id="general">
    <div class="grid2"><label class="field"><span>${t("Update every (hours)")}</span><input type="number" name="interval_hours" min="6" max="336" value="${s.interval_hours}"></label>
    <label class="field"><span>${t("Decision lifetime (hours)")}</span><input type="number" name="decision_hours" min="24" value="${s.decision_hours}">
      <small>${t("Decisions are renewed before they expire. If asn-blocker stops, they expire after this time.")}</small></label></div>
    <div class="grid2"><label class="field"><span>${t("Sanity limit (%)")}</span><input type="number" name="sanity_percent" min="5" max="100" value="${s.sanity_percent}">
      <small>${t("If the number of ranges changes more than this, a run stops and waits for confirmation.")}</small></label>
    <label class="field"><span>${t("Spamhaus ASN-DROP")}</span><select name="spamhaus_asndrop"><option value="">${t("don’t use")}</option><option value="ban">${t("block automatically")}</option><option value="captcha">${t("captcha automatically")}</option></select>
      <small>${t("Public list of known abuse networks, refreshed on every run.")}</small></label></div>
    <label class="check"><input type="checkbox" name="include_ipv6" ${s.include_ipv6 ? "checked" : ""}><span>${t("Also block IPv6 prefixes")}</span></label>
    <h3>${t("Access")}</h3>
    <div class="grid2"><label class="field"><span>${t("Trusted proxies")}</span><input type="text" name="trusted_proxies" class="mono" value="${esc((s.trusted_proxies || []).join(", "))}">
      <small>${s.auth_mode === "proxy" ? t("Container names, IPs or CIDRs. X-Forwarded-For and the user header are only accepted from here.") : t("Container names, IPs or CIDRs. X-Forwarded-For is only accepted from here.")}</small></label>
    <label class="field"><span>${t("User header")}</span><input type="text" name="auth_user_header" class="mono" value="${esc(s.auth_user_header)}" ${s.auth_mode === "proxy" ? "" : "disabled"}></label></div>
    <button class="btn primary">${t("Save")}</button></form></div>

  <div class="section"><div class="section-head"><div><h2>${t("Notifications")}</h2><p class="small muted">${t("Sent when a run fails or is stopped, and when a watched IP is affected.")}</p></div>
    ${s.notify_url ? `<span class="tag ok">${t("active")}</span>` : `<span class="tag">${t("off")}</span>`}</div>
  <form class="box pad" id="notify">
    <div class="note danger small" id="nerr" role="alert" hidden></div>
    <div class="grid2"><label class="field"><span>URL</span><input type="url" name="notify_url" class="mono" value="${esc(s.notify_url)}" placeholder="https://ntfy.example.com/asn-blocker">
      <small>${t("ntfy: server and topic. Gotify: …/message. Webhook: any URL that accepts JSON. Empty = off.")}</small></label>
    <label class="field"><span>${t("Format")}</span><select name="notify_format"><option value="ntfy">ntfy</option><option value="gotify">Gotify</option><option value="webhook">${t("Webhook (JSON)")}</option></select></label></div>
    <div class="grid2"><label class="field"><span>${t("Access token (optional)")}</span><input type="password" name="notify_token" class="mono" autocomplete="off" placeholder="${s.notify_token_set ? t("saved – leave empty to keep") : "tk_…"}">
      <small>${t("ntfy access token or Gotify app token. Sent as a header, never shown again. Required again if the server changes.")}</small></label>
    ${s.notify_token_set ? `<label class="check mid"><input type="checkbox" name="notify_token_clear"><span>${t("Remove saved token")}</span></label>` : "<span></span>"}</div>
    <div class="row"><button type="button" class="btn" id="ntest">${t("Send test")}</button>
      <button class="btn primary" id="nsave" aria-disabled="true">${t("Save")}</button>
      <span class="small muted" id="nhint">${t("Send a successful test first, then save.")}</span></div></form></div>

  ${s.auth_mode === "local" ? `<div class="section"><div class="section-head"><h2>${t("Change password")}</h2></div><form class="box pad" id="pw">
    <div class="grid2"><label class="field"><span>${t("Current password")}</span><input type="password" name="cur" autocomplete="current-password" required></label>
    <label class="field"><span>${t("New password")}</span><input type="password" name="new" minlength="12" autocomplete="new-password" required></label></div>
    <button class="btn">${t("Change")}</button></form></div>` : ""}

  <div class="section"><div class="section-head"><h2>${t("Maintenance")}</h2></div><div class="box pad">
    <div class="row"><a class="btn" href="/api/export" download="asn-blocker.json">${t("Export configuration")}</a>
      <label class="btn">${t("Import configuration")}<input type="file" id="imp" accept="application/json" class="sr-only"></label>
      <a class="btn" href="/api/ranges/ban.txt">${t("Active ban ranges")}</a><a class="btn" href="/api/ranges/captcha.txt">${t("Active captcha ranges")}</a></div>
    <h3 class="mt">${t("Remove decisions of other tools")}</h3>
    <p class="small muted">${t("Remove decisions that other tools or scripts added via cscli, by their reason. CrowdSec's own detections and blocklists are never touched.")}</p>
    <form class="row" id="cleanup"><input type="text" name="reason" class="mono" required minlength="3" placeholder="${t("Reason, e.g. my-old-blocklist")}" aria-label="${t("Reason")}"><button class="btn danger">${t("Remove")}</button></form>
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
  g.onsubmit = guard(async (e) => {
    e.preventDefault();
    await api("/settings", { method: "PUT", body: {
      interval_hours: +g.interval_hours.value, decision_hours: +g.decision_hours.value, sanity_percent: +g.sanity_percent.value,
      include_ipv6: g.include_ipv6.checked, spamhaus_asndrop: g.spamhaus_asndrop.value || null,
      trusted_proxies: g.trusted_proxies.value.split(",").map((x) => x.trim()).filter(Boolean), auth_user_header: g.auth_user_header.value.trim() } });
    toast(t("Saved")); refreshOverview(); viewSettings(el);
  });
  const n = $("#notify");
  n.notify_format.value = s.notify_format;
  const ncfg = () => ({ notify_url: n.notify_url.value.trim(), notify_format: n.notify_format.value,
    notify_token: n.notify_token_clear?.checked ? "" : n.notify_token.value.trim() || null, public_url: location.origin });
  // Saving needs a successful test with exactly the current values (switching notifications off needs none)
  let tested = false;
  const nstate = () => {
    const off = !n.notify_url.value.trim();
    $("#nsave").setAttribute("aria-disabled", String(!(tested || off)));
    $("#nhint").textContent = off ? t("Saving with an empty URL turns notifications off.") : tested ? t("Test delivered – you can save now.") : t("Send a successful test first, then save.");
  };
  const nerr = (msg) => { $("#nerr").textContent = msg || ""; $("#nerr").hidden = !msg; };
  n.addEventListener("input", () => { tested = false; nerr(""); nstate(); });
  nstate();
  $("#ntest").onclick = async () => {
    nerr("");
    try { await api("/notify/test", { method: "POST", body: ncfg() }); tested = true; toast(t("Test notification delivered")); }
    catch (e) { tested = false; nerr(t("Test failed: {e}", { e: e.message })); }
    nstate();
  };
  n.onsubmit = async (e) => {
    e.preventDefault();
    if ($("#nsave").getAttribute("aria-disabled") === "true") { nerr(t("Not saved: send a successful test with these settings first.")); return; }
    try { await api("/notify", { method: "PUT", body: ncfg() }); toast(t("Saved")); viewSettings(el); }
    catch (err) { nerr(err.message); }
  };
  $("#pw")?.addEventListener("submit", guard(async (e) => {
    e.preventDefault();
    await api("/account/password", { method: "PUT", body: { current: e.target.cur.value, new: e.target.new.value } });
    toast(t("Password changed – please sign in again")); boot();
  }));
  $("#imp").onchange = guard(async (e) => {
    const data = JSON.parse(await e.target.files[0].text());
    const count = (x) => (Array.isArray(x) ? x.length : 0);
    if (!(await confirmDlg(t("Import configuration"), t("{a} ASN rules, {e} exemptions and {v} VPN countries will be added or overwritten.", { a: count(data.asns), e: count(data.exemptions), v: count(data.vpn) }), t("Import")))) return;
    if (!(await putRules("/import", data, "POST"))) return;
    toast(t("Imported")); refreshOverview();
  });
  $("#cleanup").onsubmit = guard(async (e) => {
    e.preventDefault();
    const reason = e.target.reason.value.trim();
    if (!(await confirmDlg(t("Remove old decisions"), t("All decisions with reason {r} that were added via cscli will be deleted from CrowdSec.", { r: `<code>${esc(reason)}</code>` }), t("Remove"), "danger"))) return;
    const r = await api("/crowdsec/cleanup", { method: "POST", body: { reason } });
    toast(t("{n} decisions removed", { n: r.deleted }));
  });
}

boot();
