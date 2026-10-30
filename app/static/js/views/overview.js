// Overview: the address-space map is the one signature element; everything else stays quiet.
import { coverage, mountAtlas } from "../../atlas.js";
import { onThemeChange } from "../app-state.js";
import { Icon } from "../icons.js";
import { act, ago, api, fmtAddr, fmtNum, fmtTime, html, locale, runStatus, t, tx, useEffect, useLoad, useRef, useState, useStore } from "../lib.js";
import { StatusTag } from "../ui.js";

let atlasCache = null;  // the ranges only change with an applied run

function Atlas({ runKey, children }) {
  const stage = useRef(null);
  const [data, setData] = useState(atlasCache?.key === runKey ? atlasCache : null);
  useEffect(() => {
    if (data?.key === runKey) return undefined;
    let alive = true;
    Promise.all([api("/ranges/ban.txt"), api("/ranges/captcha.txt")]).then(([ban, captcha]) => {
      atlasCache = { key: runKey, ban: coverage(ban), captcha: coverage(captcha) };
      if (alive) setData(atlasCache);
    }).catch(() => {});
    return () => { alive = false; };
  }, [runKey]);
  useEffect(() => {
    if (!data || !stage.current) return undefined;
    const atlas = mountAtlas(stage.current, data, { ban: t("Block"), captcha: t("Captcha"), free: t("not blocked"), reserved: t("reserved") });
    const off = onThemeChange(() => atlas.redraw());
    return () => { off(); atlas.stop(); stage.current?.replaceChildren(); };
  }, [data]);
  const share = (n) => (n / 2 ** 32 * 100).toLocaleString(locale(), { maximumFractionDigits: n / 2 ** 32 < 0.001 ? 3 : 1 });
  const any = data && (data.ban.addresses || data.captcha.addresses);
  // the frame carries where the curve starts (top left) and ends (top right); the stage itself is cleared and filled by the map
  return html`<div class="atlas-frame"><div class="atlas-stage" id="atlas-stage" ref=${stage} role="img"
      aria-label=${data ? t("Map of the IPv4 address space: {p} % blocked, {c} % behind a captcha.", { p: share(data.ban.addresses), c: share(data.captcha.addresses) })
        : t("Map of the IPv4 address space, one cell per /16 network; loading")}></div>
      <span class="tick tl mono" aria-hidden="true">0.0.0.0</span><span class="tick tr mono" aria-hidden="true">255.255.255.255</span></div>
    <div class="atlas-side"><${AtlasText} data=${data} any=${any} share=${share} />${children}</div>`;
}

function AtlasText({ data, any, share }) {
  return html`<span class="eyebrow">${t("IPv4 address space")}</span>
    <h2 id="atlas-h" class="hero-h">${!data ? t("Loading the map …") : any
      ? tx("{p} of IPv4 blocked", { p: html`<span class="hero-n">${share(data.ban.addresses)}<span class="hero-u"> %</span></span>` }) : t("Nothing blocked yet")}</h2>
    <p id="atlas-p">${!data ? t("Every cell is one /16 network, laid out along a Hilbert curve so that neighbouring networks stay together.")
      : any ? t("{b} addresses blocked and {c} behind a captcha. Every cell is one /16 network, laid out along a Hilbert curve so that neighbouring networks stay together.",
        { b: fmtAddr(data.ban.addresses), c: fmtAddr(data.captcha.addresses) }) + (data.ban.v6 + data.captcha.v6 ? " " + t("IPv6 ranges ({n}) are not shown.", { n: fmtNum(data.ban.v6 + data.captcha.v6) }) : "")
      : t("Add ASN rules and apply them – blocked networks then light up on this map of the IPv4 address space.")}</p>`;
}

export function Overview() {
  const ov = useStore((s) => s.ov);
  const [watch] = useLoad(() => api("/watch"), [ov?.rev, ov?.last_apply?.id]);
  if (!ov || !watch) return html`<p class="muted">${t("Loading …")}</p>`;
  const la = ov.last_apply;
  return html`<section class="section box atlas hero" aria-labelledby="atlas-h">
      <${Atlas} runKey=${la?.id ?? 0}>
        <dl class="readout">
          <div><dt>${t("Blocked")}</dt><dd>${fmtNum(ov.applied.ban)}</dd><dd class="sub">${t("ranges active")}</dd></div>
          <div><dt>${t("Captcha")}</dt><dd>${fmtNum(ov.applied.captcha)}</dd><dd class="sub">${t("ranges active")}</dd></div>
          <div><dt>${t("Last run")}</dt><dd class="txt">${la ? html`<span class=${"dot " + la.status}></span>${runStatus(la.status)}` : "–"}</dd>
            <dd class="sub">${la ? ago(la.started_at) + " · " + la.triggered_by : t("never applied")}</dd></div>
          <div><dt>${t("Next run")}</dt><dd class="txt">${ov.next_run ? ago(ov.next_run) : "–"}</dd>
            <dd class="sub">${ov.next_run ? fmtTime(ov.next_run) : la ? t("CrowdSec not connected") : t("starts after the first apply")} · ${t("every {h} h", { h: ov.interval_hours })}</dd></div>
        </dl>
        <div class="legend" aria-hidden="true"><span><i class="l-ban"></i>${t("Blocked")}</span><span><i class="l-cap"></i>${t("Captcha")}</span><span><i class="l-free"></i>${t("Not blocked")}</span><span><i class="l-res"></i>${t("Reserved")}</span></div>
      <//>
    </section>
    ${ov.attackers_recommended ? html`<div class="note warn row hint"><span>${ov.attackers_recommended === 1 ? t("One network keeps attacking this server – CrowdSec caught several of its IPs this week.")
      : t("{n} networks keep attacking this server – CrowdSec caught several of their IPs this week.", { n: ov.attackers_recommended })}</span>
      <span class="spacer"></span><a class="btn sm" href="#/attackers">${t("Review attackers")}</a></div>` : null}
    <div class="grid2">
      <div class="section"><div class="section-head"><h2>${t("Rules")}</h2></div><div class="box links">
        ${[["asns", t("ASNs"), ov.rules.asns], ["vpn", t("Exempt VPN countries"), ov.rules.vpn], ["exemptions", t("Other exemptions"), ov.rules.exemptions]].map(([v, l, n]) => html`
          <a class="link-row" href=${"#/" + v}><${Icon} name=${v} /><span>${l}</span><span class="num mono">${n}</span><span class="go"><${Icon} name="arrow" size=${14} /></span></a>`)}
        <div class="link-row static"><${Icon} name="audit" /><span>${t("ASN name list")}</span><span class="num mono">${ov.asn_names ? fmtNum(ov.asn_names) : html`<span class="muted">${t("loading")}</span>`}</span><span class="go"></span></div>
      </div></div>
      <div class="section"><div class="section-head"><h2>${t("Watched IPs")}</h2><a class="small" href="#/exemptions">${t("Manage")}</a></div><div class="box">
        ${watch.length ? html`<div class="table-wrap"><table><tbody>${watch.map((w) => html`<tr><td class="mono">${w.ip}</td><td class="hide-sm">${w.note}</td><td class="actions"><${StatusTag} s=${w.last_status} /></td></tr>`)}</tbody></table></div>`
          : html`<div class="empty">${t("Watched IPs are checked after every run and alert you if they would be blocked – e.g. your own mobile IP.")}</div>`}
      </div></div>
    </div>
    ${ov.me ? html`<p class="small muted">${t("Your IP:")} <code>${ov.me.ip}</code> – ${ov.me.status ? act(ov.me.status) : t("not affected")}</p>` : null}`;
}

