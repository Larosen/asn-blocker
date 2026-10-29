// asn-blocker UI – components with Preact and htm, no build step, no inline scripts (CSP).
import { applyTheme, stopLive } from "./app-state.js";
import { api, html, render, setState, t, useEffect, useStore, whenSignedOut } from "./lib.js";
import { Shell } from "./shell.js";
import { Toasts } from "./ui.js";
import { Login, ProxyDenied, Setup } from "./views/auth.js";

async function boot() {
  applyTheme();
  const session = await api("/session").catch(() => null);
  setState({ session: session || { unreachable: true } });
}

async function signOut() {
  stopLive();
  await api("/logout", { method: "POST" }).catch(() => {});
  boot();
}

function App() {
  const session = useStore((s) => s.session);
  useEffect(() => {
    whenSignedOut(boot);
    const again = () => boot();
    window.addEventListener("asnb-signed-out", again);
    return () => window.removeEventListener("asnb-signed-out", again);
  }, []);
  if (!session) return html`<div class="boot">${t("Loading …")}</div>`;
  if (session.unreachable) return html`<div class="boot">${t("Server unreachable.")}</div>`;
  if (session.setup_required) return html`<${Setup} onDone=${boot} />`;
  if (!session.user) return session.auth_mode === "local" ? html`<${Login} onDone=${boot} />` : html`<${ProxyDenied} />`;
  return html`<${Shell} key=${session.user} signOut=${signOut} />`;
}

const root = document.getElementById("root");
root.replaceChildren();
root.className = "";
render(html`<${App} />`, root);
render(html`<${Toasts} />`, document.getElementById("toasts"));
boot();
