// Key flows, the way a user clicks through them
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { open, start } from "./harness.mjs";

let h;
before(async () => { h = await start(); });
after(async () => { await h?.stop(); });
const rule = async (asn) => (await h.api("/asns")).find((r) => r.asn === asn);

test("search an ASN and add it as a rule", async () => {
  const p = await h.page();
  await open(p, h.base, "asns");
  await p.fill("#q", "bulletproof");
  await p.click("#suggest .item [data-a='ban']");
  await p.waitForSelector("tr[data-asn='64507']");
  assert.equal((await rule(64507)).action, "ban");
  assert.deepEqual(p.errors, []);
  await p.context().close();
});

test("a rule's lifetime survives a change of its action", async () => {
  const p = await h.page();
  await open(p, h.base, "asns");
  const row = p.locator("tr[data-asn='64501']");
  await row.locator("[data-exp]").selectOption("30");
  await p.waitForTimeout(800);
  const until = (await rule(64501)).expires_at;
  assert.ok(until > Date.now() / 1000 + 29 * 86400);
  await p.locator("tr[data-asn='64501'] .seg button").nth(1).click();
  await p.waitForTimeout(800);
  const r = await rule(64501);
  assert.equal(r.action, "captcha");
  assert.equal(r.expires_at, until);
  await p.locator("tr[data-asn='64501'] [data-exp]").selectOption("");
  await p.waitForTimeout(800);
  assert.equal((await rule(64501)).expires_at, null);
  assert.deepEqual(p.errors, []);
  await p.context().close();
});

test("self-protection: switch a protected ASN between its modes", async () => {
  const p = await h.page();
  await open(p, h.base, "exemptions");
  await p.click("[data-pmode='64504:exempt']");
  await p.waitForTimeout(800);
  let prot = (await h.api("/protect")).protected.find((x) => x.value === "64504");
  assert.equal(prot.mode, "exempt");
  await p.click("[data-pmode='64504:captcha']");
  await p.waitForTimeout(800);
  prot = (await h.api("/protect")).protected.find((x) => x.value === "64504");
  assert.equal(prot.mode, "captcha");
  assert.deepEqual(p.errors, []);
  await p.context().close();
});

test("command palette: navigate and check an IP", async () => {
  const p = await h.page();
  await open(p, h.base, "overview");
  await p.keyboard.press("Control+k");
  await p.keyboard.type("runs");
  await p.keyboard.press("Enter");
  await p.waitForFunction(() => location.hash === "#/runs");
  await p.keyboard.press("Control+k");
  await p.keyboard.type("203.0.113.10");
  await p.waitForSelector("#cmdk .cmdk-item[aria-selected='true']:has-text('Check IP 203.0.113.10')");
  await p.keyboard.press("Enter");
  await p.waitForSelector("#dlg[open]");
  assert.equal(await p.textContent("#dlg-title"), "203.0.113.10");
  assert.deepEqual(p.errors, []);
  await p.context().close();
});

test("settings: routing table status and loading it on demand", async () => {
  const p = await h.page();
  await open(p, h.base, "settings");
  assert.match(await p.textContent("#routing"), /Not loaded – RIPEstat is used/);
  await p.click("#routing-refresh");
  await p.waitForFunction(() => /last attempt failed: demo: no download/.test(document.querySelector("#routing").textContent), null, { timeout: 10000 });
  assert.equal(await p.isDisabled("#routing-refresh"), false);
  assert.deepEqual(p.errors, []);
  await p.context().close();
});

test("IP check explains which rule decides", async () => {
  const p = await h.page();
  await open(p, h.base, "overview");
  const banned = (await (await p.request.get(h.base + "/api/ranges/ban.txt")).text()).split("\n")[0];  // e.g. 11.12.0.0/16
  await p.fill("#ipcheck input", banned.split("/")[0].replace(/\.0$/, ".1"));
  await p.keyboard.press("Enter");
  await p.waitForSelector("#dlg[open]");
  const why = await p.textContent("#dlg");
  assert.match(why, /Why/);
  assert.equal(await p.locator("#dlg tr.wins").count(), 1);
  assert.deepEqual(p.errors, []);
  await p.context().close();
});

test("attackers: switching on automatic rules adds the recommended networks", async () => {
  const p = await h.page();
  await open(p, h.base, "attackers");
  await p.selectOption("#att-auto [name=mode]", "captcha");
  await p.selectOption("#att-auto [name=days]", "7");
  await p.click("#att-auto button");
  const [res] = await Promise.all([p.waitForResponse((r) => r.url().endsWith("/api/attackers/auto")), p.click("#dlg button[value='ok']")]);
  assert.deepEqual(await res.json(), { ok: true, added: 1 });
  const r = await rule(64508);
  assert.equal(r.action, "captcha");
  assert.equal(r.source, "attackers");
  assert.ok(r.expires_at < Date.now() / 1000 + 8 * 86400);
  assert.deepEqual(p.errors, []);
  await p.context().close();
});
