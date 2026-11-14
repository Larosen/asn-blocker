// Feedback: a button shows its running action, a double click is one request, errors stay and can be closed,
// lists show placeholders and a retry, and the page says when it is out of date
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { open, start } from "./harness.mjs";

let h;
before(async () => { h = await start(); });
after(async () => { await h?.stop(); });

test("a button spins while its request runs, and a double click sends one request", async () => {
  const p = await h.page();
  await open(p, h.base, "exemptions");
  let posts = 0;
  await p.route("**/api/exemptions", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    posts++;
    await new Promise((r) => setTimeout(r, 700));
    return route.continue();
  });
  await p.fill("#add-cidr input[name=v]", "203.0.113.7");
  const btn = p.locator("#add-cidr button.btn");
  const before = (await btn.boundingBox()).width;
  await btn.dblclick();
  await p.waitForSelector("#add-cidr button[aria-busy=true].is-busy");
  assert.ok(Math.abs((await btn.boundingBox()).width - before) < 1, "the button keeps its width");
  await p.waitForSelector("#add-cidr button.did-work");
  await p.waitForSelector("#add-cidr button:not([aria-busy])");
  assert.equal(posts, 1);
  assert.deepEqual(p.errors, []);
  await p.context().close();
});

test("an error stays as a message, can be closed, and a lost connection reads plainly", async () => {
  const p = await h.page();
  await open(p, h.base, "exemptions");
  await p.route("**/api/exemptions", (route) => (route.request().method() === "POST" ? route.abort() : route.continue()));
  await p.fill("#add-cidr input[name=v]", "203.0.113.8");
  await p.click("#add-cidr button.btn");
  const toast = p.locator("#toasts .toast.error");
  await toast.waitFor();
  assert.match(await toast.textContent(), /No connection to asn-blocker/);
  assert.equal(await p.locator("#add-cidr button.did-fail").count(), 1);
  await p.waitForTimeout(4000);   // longer than a success message stays
  assert.equal(await toast.count(), 1);
  await p.click("#toasts .toast-x");
  await p.waitForSelector("#toasts .toast", { state: "detached" });
  await p.context().close();
});

test("a list that cannot load offers a retry and shows the result after it", async () => {
  const p = await h.page();
  let fail = true;
  await p.route("**/api/audit", (route) => (fail ? route.fulfill({ status: 502, contentType: "text/html", body: "<html>Bad Gateway</html>" }) : route.continue()));
  await p.goto(h.base + "/#/audit");
  await p.waitForSelector(".load-error");
  const text = await p.locator(".load-error").textContent();
  assert.match(text, /not reachable/);
  assert.doesNotMatch(text, /<|Bad Gateway/);
  fail = false;
  await p.click(".load-error button");
  await p.waitForSelector("#view table, #view .empty");
  assert.equal(await p.locator(".load-error").count(), 0);
  await p.context().close();
});

test("the first load shows placeholders, not an empty page", async () => {
  const p = await h.page();
  await p.route("**/api/audit", async (route) => { await new Promise((r) => setTimeout(r, 800)); return route.continue(); });
  await p.goto(h.base + "/#/audit");
  await p.waitForSelector("#view [aria-busy=true] .skeleton");
  await p.waitForSelector("#view table, #view .empty");
  await p.context().close();
});

test("messages stack up to four and identical ones are not doubled; phone width keeps them reachable", async () => {
  const p = await h.page({ viewport: { width: 390, height: 800 } });
  await open(p, h.base, "overview");
  await p.evaluate(async () => {
    const { toast } = await import("/static/js/ui.js");
    for (const m of ["a", "b", "b", "c", "d", "e"]) toast(m, m === "e" ? "warning" : "info");
  });
  assert.equal(await p.locator("#toasts .toast").count(), 4);
  assert.deepEqual(await p.locator("#toasts .toast-text").allTextContents(), ["b", "c", "d", "e"]);
  const x = await p.locator("#toasts .toast-x").first().boundingBox();
  assert.ok(x.x + x.width <= 390 && x.x >= 0);
  await p.context().close();
});

test("an open page offers a reload when the server runs another version", async () => {
  const p = await h.page();
  await open(p, h.base, "overview");
  await p.waitForTimeout(800);   // the stream is connected
  await p.evaluate(async () => {
    const { setState, getState } = await import("/static/js/lib.js");
    setState({ session: { ...getState().session, version: "0.0.1" } });
  });
  // the next state event carries the real version; force one by changing a rule's revision
  await h.api("/exemptions", { method: "POST", body: JSON.stringify({ kind: "cidr", value: "203.0.113.9", note: "" }) });
  await p.waitForSelector("#banners .banner button:has-text('Reload')", { timeout: 10000 });
  await p.context().close();
});
