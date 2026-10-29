// Runs: history, the selected run's changes and log. A run in progress is followed through the live updates.
import { reviewStopped, startRun } from "../actions.js";
import { liveOk } from "../app-state.js";
import { ago, api, fmtTime, html, kindName, runStatus, stopReasons, t, useEffect, useLayoutEffect, useLoad, useRef, useStore } from "../lib.js";
import { StatusTag } from "../ui.js";

function Log({ text }) {
  const pre = useRef(null), atEnd = useRef(true);
  // a live update keeps the log where the reader left it – at the end if they were at the end
  const onScroll = () => { const p = pre.current; atEnd.current = p.scrollTop + p.clientHeight >= p.scrollHeight - 4; };
  useLayoutEffect(() => { if (atEnd.current && pre.current) pre.current.scrollTop = pre.current.scrollHeight; }, [text]);
  return html`<pre class="log" tabindex="0" ref=${pre} onScroll=${onScroll}>${text}</pre>`;
}

function Detail({ r, lastApplyId }) {
  const s = r.summary || {};
  return html`<div class="section"><div class="section-head"><h2>${t("Run")} #${r.id} · ${kindName(r.kind)} · ${runStatus(r.status)}</h2>
      ${r.status === "blocked" && r.id === lastApplyId ? html`<button class="btn danger" id="force" onClick=${() => reviewStopped(r)}>${t("Apply anyway")}</button>` : null}
      ${r.kind === "plan" && r.status === "ok" ? html`<button class="btn primary" id="apply-now" onClick=${() => startRun("apply")}>${t("Apply this state")}</button>` : null}</div>
    ${r.status === "blocked" ? html`<div class="note warn">${t("Stopped by the sanity check – CrowdSec is unchanged:")}<ul>${stopReasons(r).map((x) => html`<li>${x}</li>`)}</ul></div>` : null}
    ${s.watch_hits?.length ? html`<div class="note danger">${t("Watched IPs affected:")} <code>${s.watch_hits.join(", ")}</code></div>` : null}
    <div class="grid2"><div><h3>${t("Changes")}</h3>
      ${r.changes.length ? html`<div class="box table-wrap"><table><tbody>${r.changes.slice(0, 200).map((c) => html`<tr><td class=${"mono " + (c.op === "+" ? "diff-add" : "diff-del")}>${c.op}</td>
          <td><${StatusTag} s=${c.type} /></td><td class="mono">${c.value}</td></tr>`)}</tbody></table></div>
        ${r.changes.length >= 200 ? html`<p class="small muted">${t("First 200 of {n} changes.", { n: r.changes.length >= 500 ? "500+" : r.changes.length })}</p>` : null}`
      : html`<p class="muted small">${t("No range changes.")}</p>`}</div>
      <div><h3>${t("Log")}</h3><${Log} text=${r.log} /></div></div></div>`;
}

export function Runs({ arg }) {
  const live = useStore((s) => s.live), lastApplyId = useStore((s) => s.ov?.last_apply?.id);
  const [runs, reloadRuns] = useLoad(() => api("/runs"));
  const sel = arg ? Number(arg) : runs?.[0]?.id;
  const [r, reloadRun] = useLoad(() => (sel ? api("/runs/" + sel) : Promise.resolve(null)), [sel]);
  const running = runs?.some((x) => x.status === "running") || r?.status === "running";
  // follow a run: through the live updates (at most once a second), or by polling while the stream is down
  const throttle = useRef(0), viaLive = liveOk();
  useEffect(() => {
    if (!running && !live?.running) return undefined;
    const wait = viaLive ? Math.max(0, 700 - (Date.now() - throttle.current)) : 1500;
    const timer = setTimeout(() => { throttle.current = Date.now(); reloadRuns(); reloadRun(); }, wait);
    return () => clearTimeout(timer);
  }, [live?.version, running, viaLive ? null : runs, viaLive ? null : r]);  // with the stream: only on news
  if (!runs) return html`<p class="muted">${t("Loading …")}</p>`;
  return html`<div class="section"><div class="section-head"><div><p class="small muted">${t("A run recomputes the ranges and syncs them with CrowdSec. “Preview” changes nothing.")}</p></div>
      <div class="row"><button class="btn" data-run="plan" onClick=${() => startRun("plan")}>${t("Preview")}</button><button class="btn primary" data-run="apply" onClick=${() => startRun("apply")}>${t("Apply now")}</button></div></div>
    <div class="box table-wrap">${runs.length ? html`<table><thead><tr><th>#</th><th>${t("Type")}</th><th>${t("Status")}</th><th>${t("Started")}</th><th class="hide-sm">${t("By")}</th>
        <th class="num">Ban</th><th class="num">Captcha</th><th class="num hide-sm">${t("Changes")}</th></tr></thead><tbody>
      ${runs.map((x) => {
        const s = x.summary || {}, ch = (s.ban_added || 0) + (s.captcha_added || 0), rm = (s.ban_removed || 0) + (s.captcha_removed || 0);
        return html`<tr key=${x.id} data-id=${x.id} aria-current=${x.id === sel ? "true" : undefined}><td class="mono"><a href=${"#/runs/" + x.id}>${x.id}</a></td><td>${kindName(x.kind)}</td>
          <td><span class=${"dot " + x.status}></span>${runStatus(x.status)}</td><td title=${fmtTime(x.started_at)}>${ago(x.started_at)}</td><td class="hide-sm">${x.triggered_by}</td>
          <td class="num mono">${s.ban ?? "–"}</td><td class="num mono">${s.captcha ?? "–"}</td>
          <td class="num mono hide-sm">${x.summary ? html`<span class="diff-add">+${ch}</span> <span class="diff-del">−${rm}</span>` : null}</td></tr>`;
      })}</tbody></table>` : html`<div class="empty">${t("No runs yet.")}</div>`}</div></div>
    <div id="detail">${r ? html`<${Detail} r=${r} lastApplyId=${lastApplyId} />` : null}</div>`;
}
