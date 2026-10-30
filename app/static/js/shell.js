// The signed-in shell: navigation, header (command palette, IP check), notices, the current view and the apply bar.
import { checkIp, reviewStopped, startRun } from "./actions.js";
import { connectLive, refreshOverview, stopLive, ThemeSwitch } from "./app-state.js";
import { Icon } from "./icons.js";
import { ago, api, fmtNum, html, IS_MAC, render, setState, stopReasons, t, tx, useEffect, useRef, useState, useStore } from "./lib.js";
import { openPalette } from "./palette.js";
import { guard, toast } from "./ui.js";
import { groupName, NAV_GROUPS, TABS, VIEW_COMPONENTS, VIEWS, viewName } from "./views/index.js";

function parseRoute() {
  const [view = "overview", arg] = location.hash.replace(/^#\/?/, "").split("/");
  return { view: VIEWS.includes(view) ? view : "overview", arg };
}

function useCounts() {
  const ov = useStore((s) => s.ov);
  return ov ? { asns: ov.rules.asns, vpn: ov.rules.vpn, exemptions: ov.rules.exemptions + ov.rules.watch, attackers: ov.attackers_recommended } : {};
}

// Grouped navigation with icons; the same component serves the sidebar and the phone's "More" sheet
function Nav({ onPick }) {
  const route = useStore((s) => s.route), counts = useCounts();
  return html`<nav class="nav" aria-label=${t("Main navigation")}>${NAV_GROUPS.map((g) => html`<div class="nav-group">
    <div class="nav-h eyebrow" aria-hidden="true">${g.name()}</div>
    ${g.views.map((id) => html`<a href=${"#/" + id} data-view=${id} aria-current=${route.view === id ? "page" : undefined} onClick=${onPick}>
      <${Icon} name=${id} /><span class="nav-l">${viewName(id)}</span>${counts[id] ? html`<span class="count" data-count=${id}>${counts[id]}</span>` : null}</a>`)}</div>`)}</nav>`;
}

// Connection and schedule at a glance, at the top of the sidebar
function StatusCard() {
  const ov = useStore((s) => s.ov);
  if (!ov) return html`<div class="status-card" aria-hidden="true"></div>`;
  const run = ov.running, ok = ov.crowdsec_mode, failed = ov.last_apply?.status === "failed";
  const dot = run ? "running" : !ok ? "warn" : failed ? "failed" : "ok";
  return html`<a class="status-card" href=${ok ? "#/runs" : "#/settings"}>
    <span class=${"dot " + dot}></span><span class="sc-t">${run ? t("Run in progress") : !ok ? t("CrowdSec not connected") : failed ? t("Last run failed") : t("Connected to CrowdSec")}</span>
    <span class="sc-s">${ov.next_run && !run ? t("Next run {when}", { when: ago(ov.next_run) }) : run ? t("Follow it under Runs") : ok ? t("No run scheduled") : t("Set it up under Settings")}</span></a>`;
}

function Account({ signOut }) {
  const session = useStore((s) => s.session);
  return html`<div class="account"><span class="avatar" aria-hidden="true">${(session.user || "?").slice(0, 1).toUpperCase()}</span>
    <span class="acc-n"><span class="acc-u">${session.user}</span><span class="acc-v mono">v${session.version}</span></span>
    ${session.auth_mode === "local" ? html`<button type="button" class="icon-btn" id="logout" aria-label=${t("Sign out")} title=${t("Sign out")} onClick=${() => signOut()}><${Icon} name="signout" /></button>` : null}</div>`;
}

// Phone: four tabs and "More" – a sheet with the whole navigation, the theme and the account
function TabBar({ signOut }) {
  const route = useStore((s) => s.route), counts = useCounts();
  const more = !TABS.includes(route.view);
  return html`<nav class="tabbar" aria-label=${t("Quick navigation")}>${TABS.map((id) => html`<a href=${"#/" + id} aria-current=${route.view === id ? "page" : undefined}>
      <span class="tb-i"><${Icon} name=${id} size=${20} />${id === "attackers" && counts.attackers ? html`<span class="tb-badge" aria-hidden="true"></span>` : null}</span><span>${viewName(id)}</span></a>`)}
    <button type="button" class=${more ? "on" : ""} id="more-open" aria-haspopup="dialog" aria-current=${more ? "page" : undefined} onClick=${() => openMore(signOut)}>
      <span class="tb-i"><${Icon} name="more" size=${20} /></span><span>${more ? viewName(route.view) : t("More")}</span></button></nav>`;
}

function openMore(signOut) {
  let dlg = document.getElementById("more");
  if (!dlg) {
    dlg = document.createElement("dialog");
    dlg.id = "more";
    dlg.className = "sheet";
    dlg.setAttribute("aria-label", t("Menu"));
    document.body.append(dlg);
    dlg.addEventListener("click", (e) => { if (e.target === dlg) dlg.close(); });
    dlg.addEventListener("close", () => { if (!dlg.open) render(null, dlg); });
  }
  const close = () => dlg.close();
  render(null, dlg);
  render(html`<div class="sheet-grip" aria-hidden="true"></div><div class="sheet-head"><${StatusCard} />
      <button type="button" class="icon-btn" aria-label=${t("Close")} onClick=${close}><${Icon} name="close" /></button></div>
    <${Nav} onPick=${close} /><div class="sheet-foot"><${ThemeSwitch} /><${Account} signOut=${() => { close(); signOut(); }} /></div>`, dlg);
  dlg.showModal();
}

function Banners() {
  const ov = useStore((s) => s.ov);
  if (!ov) return null;
  const la = ov.last_apply, b = [];
  const exemptMe = guard(async () => {
    await api("/exemptions", { method: "POST", body: { kind: "cidr", value: ov.me.ip, note: t("own IP") } });
    toast(t("Your IP was saved as an exemption. Apply to make it effective."));
    refreshOverview();
  });
  if (!ov.crowdsec_mode) b.push(html`<div class="banner warn"><span class="dot warn"></span><span>${t("CrowdSec is not connected yet.")}</span><a class="btn sm" href="#/settings">${t("Set up")}</a></div>`);
  if (ov.me?.status) b.push(html`<div class="banner danger" role="alert"><span class="dot ban"></span>
    <span>${tx("Your IP {ip} is currently affected by {action}. You risk locking yourself out.", { ip: html`<code>${ov.me.ip}</code>`, action: html`<b>${ov.me.status === "ban" ? t("Block") : t("Captcha")}</b>` })}</span>
    <button class="btn sm" onClick=${exemptMe}>${t("Add as exemption")}</button></div>`);
  if (ov.untrusted_proxy) b.push(html`<div class="banner warn"><span class="dot warn"></span><span>${tx("Requests arrive through proxy {ip}, which is not a trusted proxy. Sign-in throttling then applies to everyone behind it together.", { ip: html`<code>${ov.untrusted_proxy}</code>` })}</span><a class="btn sm" href="#/settings">${t("Settings")}</a></div>`);
  if (ov.broad_proxies?.length) b.push(html`<div class="banner warn"><span class="dot warn"></span><span>${tx("Trusted proxies {nets} cover more than one address. Every host in them can claim any client IP or username – trust only the proxy's own IP.", { nets: html`<code>${ov.broad_proxies.join(", ")}</code>` })}</span><a class="btn sm" href="#/settings">${t("Settings")}</a></div>`);
  if (la?.status === "failed") b.push(html`<div class="banner danger"><span class="dot failed"></span><span>${t("Last run failed ({when}).", { when: ago(la.started_at) })}</span><a class="btn sm" href=${"#/runs/" + la.id}>${t("Details")}</a></div>`);
  if (la?.status === "blocked") b.push(html`<div class="banner warn"><span class="dot blocked"></span><span>${t("The last run was stopped by the sanity check – CrowdSec is unchanged.")} ${stopReasons(la).join(" · ")}</span>
    <a class="btn sm" href=${"#/runs/" + la.id}>${t("Review changes")}</a><button class="btn sm danger" onClick=${() => reviewStopped(la)}>${t("Apply anyway")}</button></div>`);
  return b;
}

const PHASES = { sources: () => t("Collecting data"), plan: () => t("Comparing with CrowdSec"), push: () => t("Writing to CrowdSec"), verify: () => t("Checking") };
const ORDER = Object.keys(PHASES);
function runProgress(run) {
  if (!run) return t("Run in progress …");
  const p = PHASES[run.phase]?.() ?? t("Run in progress …");
  return run.progress != null && run.phase === "push" ? `${p} · ${Math.round(run.progress * 100)} %` : `${p} …`;
}
// One segment per phase: done ones full, the current one by its progress (pushing) or half
function Phases({ run }) {
  const at = ORDER.indexOf(run?.phase);
  return html`<span class="phases" aria-hidden="true">${ORDER.map((ph, i) => html`<i style=${{ "--p": i < at ? 1 : i > at ? 0 : run.phase === "push" && run.progress != null ? run.progress : 0.5 }}></i>`)}</span>`;
}

// Apply bar: a run in progress, or the expected change (+/- ranges) while rules are not applied yet
function ApplyBar() {
  const ov = useStore((s) => s.ov), run = useStore((s) => s.live?.run), view = useStore((s) => s.route.view);
  const [preview, setPreview] = useState(null);
  const rev = ov?.rev, pending = ov?.pending && !ov?.running;
  useEffect(() => {
    if (!pending) return undefined;
    let alive = true, timer;
    setPreview(null);
    const load = () => api("/preview").then((p) => {
      if (!alive) return;
      if (p.busy) { timer = setTimeout(load, 1500); return; }
      setPreview(p.error ? t("Preview unavailable: {e}", { e: t(p.error) }) : p);
    }).catch(() => alive && setPreview(""));
    load();
    return () => { alive = false; clearTimeout(timer); };
  }, [pending, rev]);
  if (!ov) return null;
  if (ov.running) {  // on the runs page itself a link to it would lead nowhere
    return html`<div class="applybar running"><span class="ab-state"><span class="dot running"></span></span>
      <span class="ab-text"><span class="ab-t">${runProgress(run)}</span><${Phases} run=${run} /></span><span class="spacer"></span>
      ${view === "runs" ? null : html`<a class="btn sm" href="#/runs">${t("View")}</a>`}</div>`;
  }
  if (!ov.pending) return null;
  const diff = preview && typeof preview === "object"
    ? html`<span class="ab-diff" id="preview">${["ban", "captcha"].map((k) => html`<span class=${"chip " + k}>${k === "ban" ? t("Block") : t("Captcha")}
        <b>+${fmtNum(preview[k].add)}</b><b>−${fmtNum(preview[k].remove)}</b></span>`)}</span>`
    : html`<span class="ab-s" id="preview">${preview ?? t("Computing preview …")}</span>`;
  return html`<div class="applybar"><span class="ab-state"><span class="dot warn"></span></span>
    <span class="ab-text"><span class="ab-t">${t("Rules changed")}<span class="hide-sm"> – ${t("not active in CrowdSec yet.")}</span></span>${diff}</span><span class="spacer"></span>
    <span class="ab-actions"><button class="btn" data-run="plan" aria-label=${t("Preview")} onClick=${() => startRun("plan")}><${Icon} name="preview" /><span>${t("Preview")}</span></button>
    ${ov.last_apply?.status === "blocked"
      ? html`<button class="btn danger" data-confirm-run onClick=${() => reviewStopped(ov.last_apply)}>${t("Apply anyway")}</button>`
      : html`<button class="btn primary" data-run="apply" disabled=${!ov.crowdsec_mode} onClick=${() => startRun("apply")}><${Icon} name="apply" /><span>${t("Apply")}</span></button>`}</span></div>`;
}

function View() {
  const route = useStore((s) => s.route);
  const Comp = VIEW_COMPONENTS[route.view];
  // The key gives every page (and every run) its own component: a new page fades in, a live update of the same
  // page changes only what changed
  return html`<${Comp} key=${route.view + "/" + (route.view === "vpn" ? route.arg || "" : "")} arg=${route.arg} />`;
}

export function Shell({ signOut }) {
  const route = useStore((s) => s.route);
  const ip = useRef(null);
  useEffect(() => {
    const onHash = () => setState({ route: parseRoute() });
    window.addEventListener("hashchange", onHash);
    const onKey = (e) => { if ((e.metaKey || e.ctrlKey) && !e.altKey && e.key.toLowerCase() === "k") { e.preventDefault(); openPalette(signOut); } };
    document.addEventListener("keydown", onKey);
    onHash();
    refreshOverview();
    connectLive();
    return () => { window.removeEventListener("hashchange", onHash); document.removeEventListener("keydown", onKey); stopLive(); };
  }, []);
  useEffect(() => { document.title = `${viewName(route.view)} · asn-blocker`; }, [route.view]);
  const submitIp = (e) => { e.preventDefault(); const v = ip.current.value.trim(); if (v) checkIp(v); };
  return html`<div class="shell">
      <aside class="side"><a class="brand" href="#/overview"><img src="/static/icon.svg" alt="" /><span>asn-blocker</span></a>
        <${StatusCard} /><${Nav} />
        <div class="side-foot"><${ThemeSwitch} /><${Account} signOut=${signOut} /></div>
      </aside>
      <div class="main"><div id="banners" role="region" aria-label=${t("Notices")}><${Banners} /></div>
        <header class="top"><img class="top-mark" src="/static/icon.svg" alt="" />
          <div class="top-t"><span class="eyebrow" aria-hidden="true">${groupName(route.view)}</span><h1 id="title">${viewName(route.view)}</h1></div>
          <button type="button" class="cmdk-btn" id="cmdk-open" aria-keyshortcuts=${IS_MAC ? "Meta+K" : "Control+K"} aria-label=${t("Search or jump to …")} onClick=${() => openPalette(signOut)}>
            <${Icon} name="search" /><span class="lbl">${t("Search or jump to …")}</span><kbd>${IS_MAC ? "⌘" : "Ctrl"}</kbd><kbd>K</kbd></button>
          <form class="ipcheck" id="ipcheck" role="search" onSubmit=${submitIp}><${Icon} name="ip" /><input ref=${ip} type="search" name="ip" placeholder=${t("Check IP …")} aria-label=${t("Check IP")} autocomplete="off" /></form></header>
        <main class="content" id="view"><${View} /></main></div></div>
    <div id="applybar" role="region" aria-label=${t("Changes")} aria-live="polite"><${ApplyBar} /></div>
    <${TabBar} signOut=${signOut} />`;
}
