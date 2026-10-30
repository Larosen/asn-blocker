// The README screenshots, taken from the offline demo server (example data only): npm run screenshots
import { rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { open, start } from "./harness.mjs";

const OUT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "docs", "screenshots");
const h = await start({ env: { ASNB_DEMO_RICH: "1" } });  // realistic network sizes, so the map shows something

async function shot(name, view, { act, width = 1280, height = 800, scale = 1 } = {}) {
  const p = await h.page({ viewport: { width, height }, deviceScaleFactor: scale, colorScheme: "dark" });
  await open(p, h.base, view, "dark");
  if (act) await act(p);
  await p.waitForTimeout(600);  // entrance animations
  await p.screenshot({ path: join(OUT, name + ".png") });
  if (p.errors.length) throw new Error(`${name}: ${p.errors.join("; ")}`);
  await p.context().close();
}

try {
  // the demo leaves one rule change unapplied; apply it so the apply bar does not cover the pictures
  await h.api("/runs", { method: "POST", body: JSON.stringify({ kind: "apply" }) });
  for (let i = 0; i < 50 && (await h.api("/overview")).running; i++) await new Promise((r) => setTimeout(r, 200));
  const page = await h.page();  // a signed-in request context; the range list is plain text, not JSON
  const banned = (await (await page.request.get(h.base + "/api/ranges/ban.txt")).text()).split("\n")[0].split("/")[0].replace(/\.0$/, ".25");
  await page.context().close();

  rmSync(join(OUT, "suggestions.png"), { force: true });
  await shot("overview", "overview");
  await shot("asns-search", "asns", { act: async (p) => { await p.fill("#q", "example"); await p.waitForSelector("#suggest .item"); } });
  await shot("attackers", "attackers");
  await shot("check-ip", "asns", { act: async (p) => {
    await p.fill("#ipcheck input", banned); await p.press("#ipcheck input", "Enter"); await p.waitForSelector("#dlg[open] tr.wins"); } });
  await shot("vpn", "vpn/nordvpn");
  await shot("run", "runs/1");
  await shot("phone", "overview", { width: 390, height: 844, scale: 2 });
} finally {
  await h.stop();
}
