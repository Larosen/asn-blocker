// The signed-in shell: navigation, header (command palette, IP check), notices, the current view and the apply bar.
import { checkIp, reviewStopped, startRun } from "./actions.js";
import { connectLive, refreshOverview, stopLive, ThemeSwitch } from "./app-state.js";
import { ago, api, fmtNum, html, IS_MAC, setState, stopReasons, t, tx, useEffect, useRef, useState, useStore } from "./lib.js";
import { openPalette } from "./palette.js";
import { guard, toast } from "./ui.js";
import { VIEW_COMPONENTS, VIEWS, viewName } from "./views/index.js";

function parseRoute() {
  const [view = "overview", arg] = location.hash.replace(/^#\/?/, "").split("/");
  return { view: VIEWS.includes(view) ? view : "overview", arg };
}

function Nav() {
  const ov = useStore((s) => s.ov), route = useStore((s) => s.route);
  const counts = ov ? { asns: ov.rules.asns, vpn: ov.rules.vpn, exemptions: ov.rules.exemptions + ov.rules.watch } : {};
  return html`<nav class="nav" aria-label=${t("Main navigation")}>${VIEWS.map((id) => html`<a href=${"#/" + id} data-view=${id}
    aria-current=${route.view === id ? "page" : undefined}>${viewName(id)}<span class="count" data-count=${id}>${counts[id] || ""}</span></a>`)}</nav>`;
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
function runProgress(run) {
  if (!run) return t("Run in progress …");
  const p = PHASES[run.phase]?.() ?? t("Run in progress …");
  return run.progress != null && run.phase === "push" ? `${p} · ${Math.round(run.progress * 100)} %` : `${p} …`;
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
      setPreview(p.error ? t("Preview unavailable: {e}", { e: t(p.error) })
        : ["ban", "captcha"].map((k) => `${k === "ban" ? t("Block") : t("Captcha")} +${fmtNum(p[k].add)} −${fmtNum(p[k].remove)}`).join(" · "));
    }).catch(() => alive && setPreview(""));
    load();
    return () => { alive = false; clearTimeout(timer); };
  }, [pending, rev]);
  if (!ov) return null;
  if (ov.running) {  // on the runs page itself a link to it would lead nowhere
    return html`<div class="applybar"><span class="dot running"></span><span>${runProgress(run)}</span><span class="spacer"></span>
      ${view === "runs" ? null : html`<a class="btn sm" href="#/runs">${t("View")}</a>`}</div>`;
  }
  if (!ov.pending) return null;
  return html`<div class="applybar"><span class="dot warn"></span><span>${t("Rules changed – not active in CrowdSec yet.")}</span>
    <span class="muted small mono" id="preview">${preview ?? t("Computing preview …")}</span><span class="spacer"></span>
    <button class="btn" data-run="plan" onClick=${() => startRun("plan")}>${t("Preview")}</button>
    ${ov.last_apply?.status === "blocked"
      ? html`<button class="btn danger" data-confirm-run onClick=${() => reviewStopped(ov.last_apply)}>${t("Apply anyway")}</button>`
      : html`<button class="btn primary" data-run="apply" disabled=${!ov.crowdsec_mode} onClick=${() => startRun("apply")}>${t("Apply")}</button>`}</div>`;
}

function View() {
  const route = useStore((s) => s.route);
  const Comp = VIEW_COMPONENTS[route.view];
  // The key gives every page (and every run) its own component: a new page fades in, a live update of the same
  // page changes only what changed
  return html`<${Comp} key=${route.view + "/" + (route.view === "vpn" ? route.arg || "" : "")} arg=${route.arg} />`;
}

export function Shell({ signOut }) {
  const session = useStore((s) => s.session), route = useStore((s) => s.route);
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
      <aside class="side"><div class="brand"><img src="/static/icon.svg" alt="" /><span>asn-blocker</span></div>
        <${Nav} />
        <div class="side-foot"><span>${session.user}</span>${session.auth_mode === "local" ? html`<a href="#" id="logout" onClick=${(e) => { e.preventDefault(); signOut(); }}>${t("Sign out")}</a>` : null}<${ThemeSwitch} /><span>v${session.version}</span></div>
      </aside>
      <div class="main"><div id="banners" role="region" aria-label=${t("Notices")}><${Banners} /></div>
        <header class="top"><h1 id="title">${viewName(route.view)}</h1>
          <button type="button" class="cmdk-btn" id="cmdk-open" aria-keyshortcuts=${IS_MAC ? "Meta+K" : "Control+K"} onClick=${() => openPalette(signOut)}>
            <span class="lbl">${t("Search or jump to …")}</span><kbd>${IS_MAC ? "⌘" : "Ctrl"}</kbd><kbd>K</kbd></button>
          <form class="ipcheck" id="ipcheck" role="search" onSubmit=${submitIp}><input ref=${ip} type="search" name="ip" placeholder=${t("Check IP …")} aria-label=${t("Check IP")} autocomplete="off" /></form></header>
        <main class="content" id="view"><${View} /></main></div></div>
    <div id="applybar" role="region" aria-label=${t("Changes")} aria-live="polite"><${ApplyBar} /></div>`;
}
