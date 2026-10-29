// Overview: the address-space map is the one signature element; everything else stays quiet.
import { coverage, mountAtlas } from "../../atlas.js";
import { onThemeChange } from "../app-state.js";
import { act, ago, api, fmtAddr, fmtNum, fmtTime, html, locale, runStatus, t, useEffect, useLoad, useRef, useState, useStore } from "../lib.js";
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
  return html`<div class="atlas-stage" id="atlas-stage" ref=${stage} role="img"
      aria-label=${data ? t("Map of the IPv4 address space: {p} % blocked, {c} % behind a captcha.", { p: share(data.ban.addresses), c: share(data.captcha.addresses) })
        : t("Map of the IPv4 address space, one cell per /16 network; loading")}></div>
    <div class="atlas-side"><${AtlasText} data=${data} any=${any} share=${share} />${children}</div>`;
}

function AtlasText({ data, any, share }) {
  return html`<span class="eyebrow">${t("IPv4 address space")}</span>
    <h2 id="atlas-h">${!data ? t("Loading the map …") : any ? t("{p} % of IPv4 blocked", { p: share(data.ban.addresses) }) : t("Nothing blocked yet")}</h2>
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
  return html`<section class="section box atlas" aria-labelledby="atlas-h">
      <${Atlas} runKey=${la?.id ?? 0}>
        <div class="atlas-figures">
          <div><div class="eyebrow">${t("Blocked")}</div><div class="v">${fmtNum(ov.applied.ban)}</div><div class="small muted">${t("ranges active")}</div></div>
          <div><div class="eyebrow">${t("Captcha")}</div><div class="v">${fmtNum(ov.applied.captcha)}</div><div class="small muted">${t("ranges active")}</div></div>
          <div><div class="eyebrow">${t("Last run")}</div><div class="v small">${la ? html`<span class=${"dot " + la.status}></span>${runStatus(la.status)}` : "–"}</div>
            <div class="small muted">${la ? ago(la.started_at) + " · " + la.triggered_by : t("never applied")}</div></div>
          <div><div class="eyebrow">${t("Next run")}</div><div class="v small">${ov.next_run ? ago(ov.next_run) : "–"}</div>
            <div class="small muted">${ov.next_run ? fmtTime(ov.next_run) : la ? t("CrowdSec not connected") : t("starts after the first apply")} · ${t("every {h} h", { h: ov.interval_hours })}</div></div>
        </div>
        <div class="legend" aria-hidden="true"><span><i class="l-ban"></i>${t("Blocked")}</span><span><i class="l-cap"></i>${t("Captcha")}</span><span><i class="l-free"></i>${t("Not blocked")}</span><span><i class="l-res"></i>${t("Reserved")}</span></div>
      <//>
    </section>
    ${ov.attackers_recommended ? html`<div class="note warn row hint"><span>${t("{n} networks keep attacking this server – CrowdSec caught several of their IPs this week.", { n: ov.attackers_recommended })}</span>
      <span class="spacer"></span><a class="btn sm" href="#/attackers">${t("Review attackers")}</a></div>` : null}
    <div class="grid2">
      <div class="section"><div class="section-head"><h2>${t("Rules")}</h2></div><div class="box"><table><tbody>
        <tr><td><a href="#/asns">${t("ASNs")}</a></td><td class="num mono">${ov.rules.asns}</td></tr>
        <tr><td><a href="#/vpn">${t("Exempt VPN countries")}</a></td><td class="num mono">${ov.rules.vpn}</td></tr>
        <tr><td><a href="#/exemptions">${t("Other exemptions")}</a></td><td class="num mono">${ov.rules.exemptions}</td></tr>
        <tr><td>${t("ASN name list")}</td><td class="num mono">${ov.asn_names ? fmtNum(ov.asn_names) : html`<span class="muted">${t("loading")}</span>`}</td></tr>
      </tbody></table></div></div>
      <div class="section"><div class="section-head"><h2>${t("Watched IPs")}</h2><a class="small" href="#/exemptions">${t("Manage")}</a></div><div class="box">
        ${watch.length ? html`<div class="table-wrap"><table><tbody>${watch.map((w) => html`<tr><td class="mono">${w.ip}</td><td class="hide-sm">${w.note}</td><td class="actions"><${StatusTag} s=${w.last_status} /></td></tr>`)}</tbody></table></div>`
          : html`<div class="empty">${t("Watched IPs are checked after every run and alert you if they would be blocked – e.g. your own mobile IP.")}</div>`}
      </div></div>
    </div>
    ${ov.me ? html`<p class="small muted">${t("Your IP:")} <code>${ov.me.ip}</code> – ${ov.me.status ? act(ov.me.status) : t("not affected")}</p>` : null}`;
}

