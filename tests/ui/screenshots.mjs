// The README screenshots, taken from the offline demo server (example data only): npm run screenshots
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { open, start } from "./harness.mjs";

const OUT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "docs", "screenshots");
const h = await start();
async function shot(name, view, act) {
  const p = await h.page({ viewport: { width: 1280, height: 800 }, colorScheme: "dark" });
  await open(p, h.base, view, "dark");
  if (act) await act(p);
  await p.waitForTimeout(600);  // entrance animations
  await p.screenshot({ path: join(OUT, name + ".png") });
  if (p.errors.length) throw new Error(`${name}: ${p.errors.join("; ")}`);
  await p.context().close();
}
try {
  await shot("overview", "overview");
  await shot("asns-search", "asns", async (p) => { await p.fill("#q", "example"); await p.waitForSelector("#suggest .item"); });
  await shot("suggestions", "asns", async (p) => { await p.click("button:has-text('Suggestions')"); await p.waitForSelector("#dlg[open]"); });
  await shot("vpn", "vpn/nordvpn");
  await shot("run", "runs/1");
} finally {
  await h.stop();
}
