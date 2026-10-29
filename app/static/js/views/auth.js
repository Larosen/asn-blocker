// Before sign-in: initial setup, the password login, and the explanation when the reverse proxy is not trusted.
import { ThemeSwitch } from "../app-state.js";
import { api, html, t, tx, useState, useStore } from "../lib.js";
import { guard } from "../ui.js";

export function Setup({ onDone }) {
  const session = useStore((s) => s.session);
  const [mode, setMode] = useState("proxy");
  const submit = guard(async (e) => {
    e.preventDefault();
    const f = e.target;
    await api("/setup/auth", { method: "POST", body: {
      token: f.token.value.trim(), mode, user_header: f.header.value.trim(),
      trusted_proxies: f.trusted.value.split(",").map((s) => s.trim()).filter(Boolean),
      username: f.username.value.trim(), password: f.password.value } });
    location.hash = "#/settings";
    onDone();
  });
  return html`<main class="center"><form class="card" id="setup" onSubmit=${submit}>
    <div class="row"><div class="steps"><span class="on">${t("1 Access")}</span><span aria-hidden="true">›</span><span>${t("2 CrowdSec")}</span></div><span class="spacer"></span><${ThemeSwitch} /></div>
    <h1>${t("Initial setup")}</h1>
    <p class="lead">${t("Choose how the interface is protected.")}</p>
    <label class="field"><span>${t("Setup token")}</span><input type="text" name="token" class="mono" required autocomplete="off" />
      <small>${t("Printed in the container log:")} <code>docker logs asn-blocker</code></small></label>
    <label class="field"><span>${t("Authentication")}</span><select name="mode" value=${mode} onChange=${(e) => setMode(e.target.value)}>
      <option value="proxy">${t("Reverse proxy with SSO (Pangolin, Authelia, Authentik …)")}</option>
      <option value="local">${t("Built-in login with password")}</option></select></label>
    <div data-mode="proxy" hidden=${mode !== "proxy"}>
      <label class="field"><span>${t("Trusted proxies")}</span><input type="text" name="trusted" class="mono" value=${session.peer_name || session.peer_ip || ""} />
        <small>${tx("Container name (recommended – it keeps working when the proxy gets a new IP), IP or CIDR of the reverse proxy, comma separated. This request came from {ip}.",
          { ip: html`<code>${session.peer_ip}</code>${session.peer_name ? html` (<code>${session.peer_name}</code>)` : null}` })}</small></label>
      <label class="field"><span>${t("Header with username")}</span><input type="text" name="header" class="mono" value="Remote-User" />
        <small>${t("The proxy must set this header after a successful SSO login.")}</small></label>
    </div>
    <div data-mode="local" hidden=${mode !== "local"}>
      <label class="field"><span>${t("Username")}</span><input type="text" name="username" value="admin" autocomplete="username" /></label>
      <label class="field"><span>${t("Password")}</span><input type="password" name="password" minlength="12" autocomplete="new-password" /><small>${t("At least 12 characters.")}</small></label>
    </div>
    <button class="btn primary">${t("Continue")}</button>
  </form></main>`;
}

export function Login({ onDone }) {
  const submit = guard(async (e) => {
    e.preventDefault();
    await api("/login", { method: "POST", body: { username: e.target.u.value, password: e.target.p.value } });
    onDone();
  });
  return html`<main class="center"><form class="card" id="login" onSubmit=${submit}>
    <div class="row"><h1>asn-blocker</h1><span class="spacer"></span><${ThemeSwitch} /></div><p class="lead">${t("Sign in")}</p>
    <label class="field"><span>${t("Username")}</span><input type="text" name="u" autocomplete="username" required /></label>
    <label class="field"><span>${t("Password")}</span><input type="password" name="p" autocomplete="current-password" required /></label>
    <button class="btn primary" id="login-btn">${t("Sign in")}</button></form></main>`;
}

export function ProxyDenied() {
  const d = useStore((s) => s.session.denied) || {};
  const who = d.peer_name ? `${d.peer_ip} (${d.peer_name})` : d.peer_ip || "?";
  return html`<main class="center"><div class="card"><h1>${t("No access")}</h1>
    <p class="lead">${t("This instance expects authentication via the reverse proxy (SSO). The request did not come through a trusted proxy or lacked the user header.")}</p>
    <div class="note small"><ul>
      <li>${t("Request from")} <code>${who}</code> – ${d.peer_trusted ? t("trusted proxy") : html`<b>${t("not a trusted proxy")}</b>`}</li>
      <li>${t("User header")}: ${d.user_header_present ? t("present") : html`<b>${t("missing")}</b>`}</li>
      <li>${t("Headers received (names only):")} <code>${(d.headers || []).join(", ")}</code></li></ul></div>
    ${!d.peer_trusted && d.peer_ip ? html`<p class="small">${tx("If {ip} is your reverse proxy (e.g. it got a new IP after its container was recreated), trust it:", { ip: html`<code>${who}</code>` })}<br />
      <code>docker exec asn-blocker python -m app.cli trust-proxy ${d.peer_name || d.peer_ip}</code></p>` : null}
    <p class="muted small">${t("Start over:")} <code>docker exec asn-blocker python -m app.cli reset-auth</code></p></div></main>`;
}
