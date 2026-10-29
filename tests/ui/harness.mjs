// Starts the offline demo server (server.py) and a browser; shared by all UI tests.
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, mkdirSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { chromium } from "playwright";

const here = dirname(fileURLToPath(import.meta.url));
const axeSource = readFileSync(createRequire(import.meta.url).resolve("axe-core/axe.min.js"), "utf8");
export const ARTIFACTS = join(here, "artifacts");
export const VIEWS = ["overview", "asns", "attackers", "vpn/nordvpn", "exemptions", "runs", "audit", "settings"];
export const THEMES = ["light", "dark", "oled"];

const freePort = () => new Promise((resolve) => {
  const s = createServer().listen(0, "127.0.0.1", () => { const { port } = s.address(); s.close(() => resolve(port)); });
});

export async function start({ env = {} } = {}) {
  const port = await freePort(), base = `http://127.0.0.1:${port}`;
  const proc = spawn(process.env.PYTHON || "python3", [join(here, "server.py"), mkdtempSync(join(tmpdir(), "asnb-ui-")), String(port)],
    { stdio: ["ignore", "inherit", "inherit"], env: { ...process.env, ...env } });
  for (let i = 0; ; i++) {
    try { if ((await fetch(base + "/healthz")).ok) break; } catch { /* not up yet */ }
    if (i > 150 || proc.exitCode !== null) throw new Error("demo server did not start");
    await new Promise((r) => setTimeout(r, 100));
  }
  const browser = await chromium.launch();
  const login = await browser.newContext();
  const res = await login.request.post(base + "/api/login", { headers: { "X-Requested-With": "asn-blocker" },
    data: { username: "admin", password: "correct-horse-battery" } });
  if (!res.ok()) throw new Error("login failed: " + res.status());
  const storageState = await login.storageState();
  await login.close();
  mkdirSync(ARTIFACTS, { recursive: true });
  return {
    base, browser,
    // A signed-in page; errors (exceptions, console errors) are collected in page.errors
    async page(opts = {}) {
      const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, storageState, ...opts });
      const p = await ctx.newPage();
      p.errors = [];
      p.on("pageerror", (e) => p.errors.push(e.message));
      p.on("console", (m) => m.type() === "error" && p.errors.push(m.text()));
      return p;
    },
    async api(path, init = {}) {
      const r = await fetch(base + "/api" + path, { ...init, headers: { "X-Requested-With": "asn-blocker", "Content-Type": "application/json",
        Cookie: storageState.cookies.map((c) => `${c.name}=${c.value}`).join("; "), ...(init.headers || {}) } });
      return r.status === 204 ? null : r.json();
    },
    async stop() { await browser.close(); proc.kill(); },
  };
}

// Opens a view the way a user does (hash route) and waits until it has rendered
export async function open(p, base, view, theme) {
  if (theme) { await p.goto(base + "/"); await p.evaluate((t) => localStorage.setItem("asnb-theme", t), theme); }
  await p.goto(`${base}/#/${view}`);
  await p.reload();
  await p.waitForSelector("#view :is(.section, .box, .grid2, .stats, .note, form, table)", { timeout: 15000 });
  await p.waitForTimeout(700); // entrance animations (axe would otherwise measure half-faded colours)
}

export async function axe(p) {
  await p.addScriptTag({ content: axeSource });
  return p.evaluate(async () => (await window.axe.run(document, { runOnly: ["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa", "best-practice"] }))
    .violations.map((v) => `${v.id}: ${v.nodes.slice(0, 3).map((n) => n.target.join(" ")).join(", ")}`));
}
