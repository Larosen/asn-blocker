// Actions used from several places: rules, runs and the IP check.
import { refreshOverview } from "./app-state.js";
import { act, api, fmtNum, getState, html, now, stopReasons, t, tx } from "./lib.js";
import { ClassTag, closeDialog, confirmDlg, dialog, EffectTag, guard, toast } from "./ui.js";

// --- Rules -----------------------------------------------------------------------------------------------------
// Saves rules; if they would block the network this browser is connected from, asks for an explicit confirmation.
export async function putRules(path, body, method = "PUT") {
  try {
    await api(path, { method, body });
    return true;
  } catch (e) {
    if (e.status !== 409 || e.detail?.code !== "own_asn") throw e;
    const asns = e.detail.asns.map((a) => `AS${a}`).join(", ");
    const ok = await confirmDlg(t("Block your own network?"),
      tx("{asns} is the network you are connected from right now ({ip}). Blocking it can lock you out of this page and other services – only continue if that is intended, e.g. for a hotel or office network.",
        { asns: html`<b>${asns}</b>`, ip: html`<code>${e.detail.ip}</code>` }), t("Block anyway"), "danger");
    if (!ok) return false;
    await api(path + "?confirm_own=1", { method, body });
    return true;
  }
}

// One rule from a search hit or an IP check; consumer ISPs ("eyeball" networks) need a confirmation.
export async function addAsnRule(a, action, extra = {}) {
  if (/eyeball/i.test(a.class || "") && !(await confirmDlg(t("Consumer network"),
    t("AS{asn} {name} is classified as an eyeball network (consumer ISP). Blocking it hits real visitors. Add anyway?", { asn: a.asn, name: a.name }), t("Add"), "danger"))) return false;
  return putRules("/asns", [{ asn: a.asn, name: a.name || "", action, note: a.via ? t("from IP {ip}", { ip: a.via.ip }) : "", ...extra }]);
}

// --- Runs ------------------------------------------------------------------------------------------------------
export const startRun = guard(async (kind) => {
  if (kind === "apply" && !(await confirmDlg(t("Apply rules"),
    t("Ranges are recomputed and synced with CrowdSec. Existing decisions stay active until it finishes."), t("Apply")))) return;
  await launchRun(kind);
});

// confirm: ID of the stopped run the user accepts – the server only applies a result matching that run
export async function launchRun(kind, confirm = null) {
  const prev = getState().ov?.last_apply?.id;
  await api("/runs", { method: "POST", body: confirm ? { kind, confirm } : { kind } });
  toast(kind === "plan" ? t("Computing preview …") : t("Run started"));
  if (location.hash !== "#/runs") location.hash = "#/runs";
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

// A stopped run: show why and let the user apply exactly this result in one step
export const reviewStopped = guard(async (r) => {
  const s = r.summary || {};
  const add = (s.ban_added || 0) + (s.captcha_added || 0), rm = (s.ban_removed || 0) + (s.captcha_removed || 0);
  const v = await dialog({
    title: t("Run #{id} stopped by the sanity check", { id: r.id }),
    body: html`<p>${t("CrowdSec is unchanged. The run would change much more than usual:")}</p>
      <ul>${stopReasons(r).map((x) => html`<li>${x}</li>`)}</ul>
      <p class="mono small">${act("ban")} ${fmtNum(s.ban)} · ${act("captcha")} ${fmtNum(s.captcha)} · <span class="diff-add">+${fmtNum(add)}</span> <span class="diff-del">−${fmtNum(rm)}</span></p>
      <p class="small muted">${t("Expected – for example because you added or removed ASNs or enabled IPv6? Then apply it anyway. If not, review the changes first: a data source may have returned wrong data.")}</p>`,
    actions: [["cancel", t("Not now")], ["review", t("Review changes")], ["ok", t("Apply anyway"), "danger"]],
  });
  if (v === "review") location.hash = `#/runs/${r.id}`;
  if (v === "ok") await launchRun("apply", r.id);
});

// --- IP check --------------------------------------------------------------------------------------------------
function PolicyLabel({ m }) {
  const [provider, cc] = m.value.split(":");
  const what = m.source === "asn" ? `AS${m.value}${m.name ? " " + m.name : ""}`
    : m.source === "vpn" ? t("VPN {provider} {country}", { provider, country: cc })
    : m.source === "list" ? m.name || m.value : html`<span class="mono">${m.value}</span>`;
  return html`${what}${m.locked ? html` <span class="muted small">· ${t("self-protection")}</span>` : null}${m.note ? html` <span class="muted small">· ${m.note}</span>` : null}`;
}

// Why an IP gets what it gets: every rule that covers it, the one that decides, and whether that is applied yet
export function Explain({ e, applied }) {
  const outcome = e.decision === "allow" ? null : e.decision;
  const rows = [
    ...e.implicit.map((x) => html`<tr><td><${EffectTag} e="allow" /></td><td>${t(x)}</td><td></td></tr>`),
    ...e.matches.map((m) => html`<tr class=${m.wins ? "wins" : ""}><td><${EffectTag} e=${m.effect} /></td>
      <td><${PolicyLabel} m=${m} /><div class="small muted mono">${m.via}</div></td>
      <td class="small">${m.wins ? html`<b>${t("decides")}</b>` : null}</td></tr>`),
  ];
  return html`<h3>${t("Why")}</h3>
    ${rows.length ? html`<div class="table-wrap"><table><tbody>${rows}</tbody></table></div>` : html`<p class="small muted">${t("No rule covers this address.")}</p>`}
    ${e.capped ? html`<p class="small">${t("Its network is protected against bans, so the block becomes a captcha.")}</p>` : null}
    ${(outcome ?? null) !== (applied ?? null) ? html`<div class="note warn small">${tx("With the current rules: {result} – not applied yet.",
      { result: html`<b>${outcome ? act(outcome) : t("not blocked")}</b>` })}</div>` : null}
    ${e.problems.length ? html`<p class="small muted">${e.problems.join(" · ")}</p>` : null}`;
}

export const checkIp = guard(async (ip) => {
  const r = await api("/check/" + encodeURIComponent(ip));
  const st = r.status ? html`<span class=${"tag " + r.status}>${act(r.status)}</span>`
    : r.exempt.length ? html`<span class="tag ok">${t("Exempt")}</span>` : html`<span class="tag">${t("not affected")}</span>`;
  const body = html`<p>${st}</p>
    ${r.asns.length ? html`<h3>${t("Origin")}</h3><table><tbody>${r.asns.map((a) => html`<tr><td class="mono">AS${a.asn}</td>
        <td>${a.name} <span class="hide-sm"><${ClassTag} c=${a.class} /></span></td>
        <td class="actions">${a.rule ? html`<span class=${"tag " + a.rule}>${act(a.rule)}</span>`
          : html`<button class="btn sm" value=${"ban:" + a.asn}>${t("Block")}</button> <button class="btn sm" value=${"captcha:" + a.asn}>${t("Captcha")}</button>`}</td></tr>`)}</tbody></table>
      ${r.prefix ? html`<p class="small muted">${t("Prefix")} ${r.prefix}</p>` : null}`
      : r.global ? null : html`<p class="muted">${t("Not a public address.")}</p>`}
    ${Object.entries(r.ranges).map(([k, v]) => html`<p>${tx("Covered by {action}:", { action: html`<b>${act(k)}</b>` })} <code>${v.join(", ")}</code></p>`)}
    ${r.exempt.length ? html`<p>${t("Exempt via:")} ${r.exempt.join(", ")}</p>` : null}
    ${r.status && r.vpn_near?.length ? html`<div class="note warn small">${t("Probably a VPN exit address: listed {servers} servers are in the same network, and VPN exits often use a neighbouring IP. Select this country for the provider and choose “whole network (/24, /64)”.",
        { servers: r.vpn_near.map((x) => `${x.name} ${x.country}`).join(", ") })}
      <a class="btn sm" href=${"#/vpn/" + r.vpn_near[0].provider} onClick=${() => closeDialog()}>${t("Open {name}", { name: r.vpn_near[0].name })}</a></div>` : null}
    ${r.lookup_error ? html`<p class="small muted">${r.lookup_error}</p>` : null}
    <p class="small muted">${t("As of the last applied run.")}</p>
    ${r.explain ? html`<${Explain} e=${r.explain} applied=${r.status} />` : null}`;
  const v = await dialog({ title: r.ip, body, actions: [["watch", t("Watch this IP")], ["exempt", t("As exemption")], ["cancel", t("Close"), "primary"]] });
  if (v === "watch") { await api("/watch", { method: "POST", body: { ip: r.ip } }); toast(t("Watched IP added")); refreshOverview(); }
  if (v === "exempt") { await api("/exemptions", { method: "POST", body: { kind: "cidr", value: r.ip } }); toast(t("Exemption saved")); refreshOverview(); }
  const m = /^(ban|captcha):(\d+)$/.exec(v || "");
  if (m) {
    const a = r.asns.find((x) => x.asn === +m[2]);
    if (await addAsnRule({ ...a, via: { ip: r.ip } }, m[1])) { toast(t("AS{asn} added – takes effect with the next run", { asn: a.asn })); refreshOverview(); }
  }
});

export const expiresIn = (days) => (days ? now() + +days * 86400 : null);
