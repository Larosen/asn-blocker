// Phone width, user preferences (reduced motion, reduced transparency, more contrast)
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { open, start, VIEWS } from "./harness.mjs";

let h;
before(async () => { h = await start(); });
after(async () => { await h?.stop(); });

test("no horizontal scrolling at 360 px", async () => {
  const p = await h.page({ viewport: { width: 360, height: 780 }, colorScheme: "dark" });
  const overflow = [];
  for (const v of VIEWS) {
    await open(p, h.base, v);
    const o = await p.evaluate(() => [document.documentElement.scrollWidth, document.documentElement.clientWidth]);
    if (o[0] > o[1]) overflow.push(`${v}: ${o[0]}/${o[1]}`);
  }
  assert.deepEqual(overflow, []);
  assert.deepEqual(p.errors, []);
  await p.context().close();
});

test("reduced motion: no entrance animation, the map is drawn at once", async () => {
  const p = await h.page({ reducedMotion: "reduce" });
  await p.goto(h.base + "/#/overview");
  await p.waitForSelector("#atlas-stage canvas");
  await p.waitForTimeout(150);
  const painted = await p.evaluate(() => { const c = document.querySelector("#atlas-stage canvas");
    const d = c.getContext("2d").getImageData(0, c.height - 4, c.width, 2).data; let n = 0; for (let i = 3; i < d.length; i += 4) n += d[i] > 0; return n; });
  assert.ok(painted > 0, "bottom row of the map painted");
  const dur = await p.evaluate(() => parseFloat(getComputedStyle(document.querySelector(".content > *")).animationDuration));
  assert.ok(dur < 0.01, `animation duration ${dur}s`);
  await p.context().close();
});

test("reduced transparency and more contrast", async () => {
  const p = await h.page({ colorScheme: "dark" });
  await open(p, h.base, "overview");
  const cdp = await p.context().newCDPSession(p);
  const before = await p.evaluate(() => getComputedStyle(document.querySelector(".nav a:not([aria-current])")).color);
  await cdp.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-transparency", value: "reduce" }] });
  assert.equal(await p.evaluate(() => getComputedStyle(document.querySelector(".top")).backdropFilter), "none");
  await cdp.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-contrast", value: "more" }] });
  assert.notEqual(await p.evaluate(() => getComputedStyle(document.querySelector(".nav a:not([aria-current])")).color), before);
  await p.context().close();
});
