// Live updates: a run is followed through the event stream – phases and progress, without polling
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { open, start } from "./harness.mjs";

let h;
before(async () => { h = await start({ env: { ASNB_DEMO_SLOW: "0.4" } }); });
after(async () => { await h?.stop(); });

test("a run shows its phases and progress live, and the page polls nothing meanwhile", async () => {
  await h.api("/settings", { method: "PUT", body: JSON.stringify({ interval_hours: 48, decision_hours: 168, include_ipv6: false, sanity_percent: 100,
    spamhaus_asndrop: "ban", trusted_proxies: [], auth_user_header: "Remote-User" }) });   // more ranges to push
  const p = await h.page();
  await open(p, h.base, "asns");
  await p.waitForTimeout(1000);  // the stream is connected
  const polls = [];
  p.on("request", (r) => { if (/\/api\/(overview|runs)$/.test(new URL(r.url()).pathname) && r.method() === "GET") polls.push(Date.now()); });
  await h.api("/runs", { method: "POST", body: JSON.stringify({ kind: "apply" }) });
  const seen = new Set();
  let running = false;
  for (let i = 0; i < 120; i++) {
    const busy = await p.locator("#applybar .dot.running").count();
    if (busy) { running = true; seen.add((await p.locator("#applybar").textContent()).replace(/\d+ %/, "N %").trim()); }
    else if (running) break;   // the run has ended
    await p.waitForTimeout(200);
  }
  assert.ok([...seen].some((x) => /Writing to CrowdSec · N %/.test(x)), [...seen].join(" | "));
  const runs = await h.api("/runs");
  assert.equal(runs[0].status, "ok");
  // overview is reloaded on the run's start and end (and when rules change), not every two seconds
  assert.ok(polls.length <= 4, `${polls.length} reloads`);
  assert.deepEqual(p.errors, []);
  await p.context().close();
});
