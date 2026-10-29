// Runs: applying, and the page while a run is in progress
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { devices } from "playwright";
import { open, start } from "./harness.mjs";

let h;
before(async () => { h = await start(); });
after(async () => { await h?.stop(); });

test("apply: the run finishes and the apply bar disappears", async () => {
  const p = await h.page();
  await open(p, h.base, "overview");
  await p.waitForSelector("#applybar [data-run='apply']");
  await p.click("#applybar [data-run='apply']");
  await p.click("#dlg button[value='ok']");
  await p.waitForFunction(() => location.hash === "#/runs");
  await p.waitForFunction(() => !document.querySelector("#applybar .applybar"), null, { timeout: 20000 });
  const runs = await h.api("/runs");
  assert.equal(runs[0].status, "ok");
  assert.deepEqual(p.errors, []);
  await p.context().close();
});

test("while a run is in progress the page stays still and View can be tapped", async () => {
  const p = await h.page({ ...devices["iPhone 13"] });
  await p.route("**/api/overview", async (r) => { const res = await r.fetch(); r.fulfill({ response: res, json: { ...(await res.json()), running: true } }); });
  await p.route("**/api/runs", async (r) => { if (r.request().method() !== "GET") return r.continue();
    const res = await r.fetch(); const j = await res.json(); if (j[0]) j[0].status = "running"; r.fulfill({ response: res, json: j }); });
  for (const view of ["runs", "asns"]) {
    await p.goto(`${h.base}/#/${view}`);
    await p.waitForTimeout(2000);
    await p.evaluate(() => { window.entered = 0; window.shift = 0; window.bar = document.querySelector("#applybar .applybar");
      document.addEventListener("animationstart", (e) => { if (e.animationName !== "pulse") window.entered++; }, true);
      new PerformanceObserver((l) => l.getEntries().forEach((e) => (window.shift += e.value))).observe({ type: "layout-shift" }); });
    await p.waitForTimeout(5000);
    const s = await p.evaluate(() => ({ entered: window.entered, shift: window.shift, same: window.bar === document.querySelector("#applybar .applybar") }));
    assert.deepEqual(s, { entered: 0, shift: 0, same: true }, view);
  }
  assert.equal(await p.locator("#applybar a").count(), 1);
  await p.locator("#applybar a").tap();
  await p.waitForFunction(() => location.hash === "#/runs");
  assert.equal(await p.locator("#applybar a").count(), 0, "no View link on the runs page itself");
  await p.context().close();
});
