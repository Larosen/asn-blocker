// WCAG 2.2 AA + best practice in every theme and view, and in the command palette
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { axe, open, start, THEMES, VIEWS } from "./harness.mjs";

let h;
before(async () => { h = await start(); });
after(async () => { await h?.stop(); });

for (const theme of THEMES) {
  test(`axe: ${theme}`, async () => {
    const p = await h.page({ bypassCSP: true, colorScheme: theme === "light" ? "light" : "dark" });
    const found = [];
    for (const v of VIEWS) {
      await open(p, h.base, v, theme);
      found.push(...(await axe(p)).map((x) => `${v}: ${x}`));
    }
    await p.keyboard.press("Control+k");
    await p.waitForSelector("#cmdk[open]");
    await p.waitForTimeout(600);
    found.push(...(await axe(p)).map((x) => `palette: ${x}`));
    assert.deepEqual(found, []);
    assert.deepEqual(p.errors, []);
    await p.context().close();
  });
}
