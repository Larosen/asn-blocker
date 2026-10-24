// Map of the IPv4 address space: 256 × 256 cells, one per /16, laid out along a Hilbert curve so that
// neighbouring networks stay neighbours (the classic "map of the internet" layout). Colour shows how much of
// each /16 is blocked or behind a captcha. Plain canvas 2D: no WebGL, no dependencies.

const N = 256;
let curve = null; // block index (/16 in address order) -> [x, y]

function d2xy(d) {
  let x = 0, y = 0;
  for (let s = 1, t = d; s < N; s *= 2, t = Math.floor(t / 4)) {
    const rx = 1 & (t / 2), ry = 1 & (t ^ rx);
    if (!ry) {
      if (rx) { x = s - 1 - x; y = s - 1 - y; }
      [x, y] = [y, x];
    }
    x += s * rx; y += s * ry;
  }
  return [x, y];
}

function xy2d(x, y) {
  let d = 0;
  for (let s = N / 2; s > 0; s = Math.floor(s / 2)) {
    const rx = (x & s) > 0 ? 1 : 0, ry = (y & s) > 0 ? 1 : 0;
    d += s * s * ((3 * rx) ^ ry);
    if (!ry) {
      if (rx) { x = N - 1 - x; y = N - 1 - y; }
      [x, y] = [y, x];
    }
  }
  return d;
}

function layout() {
  if (!curve) {
    curve = new Uint8Array(N * N * 2);
    for (let d = 0; d < N * N; d++) { const [x, y] = d2xy(d); curve[2 * d] = x; curve[2 * d + 1] = y; }
  }
  return curve;
}

// Special-purpose ranges that are never routed on the internet (drawn darker, never blocked): [octet1, octet2, prefix]
const RESERVED = [[0, 0, 8], [10, 0, 8], [100, 64, 10], [127, 0, 8], [169, 254, 16], [172, 16, 12], [192, 168, 16], [198, 18, 15], [224, 0, 3]];

function reservedMask() {
  const m = new Uint8Array(N * N);
  for (const [a, b, p] of RESERVED) {
    const start = a * 256 + b;
    m.fill(1, start, start + 2 ** (16 - p));
  }
  return m;
}

/** Fraction of each /16 covered by the given CIDR lines (IPv6 lines are skipped). */
export function coverage(text) {
  const f = new Float32Array(N * N);
  let addresses = 0, v4 = 0, v6 = 0;
  for (const line of text.split("\n")) {
    if (!line) continue;
    if (line.includes(":")) { v6++; continue; }
    const [ip, plen] = line.split("/");
    const p = Number(plen ?? 32), o = ip.split(".").map(Number);
    if (o.length !== 4 || o.some((x) => !(x >= 0 && x <= 255)) || !(p >= 0 && p <= 32)) continue;
    v4++;
    const start = ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
    addresses += 2 ** (32 - p);
    if (p <= 16) {
      const b = start >>> 16;
      f.fill(1, b, b + 2 ** (16 - p));
    } else {
      const b = start >>> 16;
      f[b] = Math.min(1, f[b] + 2 ** (32 - p) / 65536);
    }
  }
  return { f, addresses, v4, v6 };
}

const reduceMotion = () => matchMedia("(prefers-reduced-motion: reduce)").matches;

/**
 * Draws the map into `stage` (a positioned element). Returns { redraw } for theme changes.
 * data: { ban: coverage(), captcha: coverage() }
 */
export function mountAtlas(stage, data, labels) {
  const cv = document.createElement("canvas");
  const tip = document.createElement("div");
  tip.className = "atlas-tip"; tip.hidden = true; tip.setAttribute("aria-hidden", "true");
  stage.replaceChildren(cv, tip);
  const S = 2; // device pixels per cell (512 × 512 bitmap)
  cv.width = cv.height = N * S;
  const ctx = cv.getContext("2d");
  const pos = layout(), reserved = reservedMask();
  let raf = 0;

  const colors = () => {
    const cs = getComputedStyle(stage);
    const v = (k) => cs.getPropertyValue(k).trim();
    const theme = document.documentElement.dataset.theme;
    const dark = theme ? theme !== "light" : matchMedia("(prefers-color-scheme: dark)").matches;
    return { ban: v("--ban"), cap: v("--cap"), free: v("--bg-2"), res: v("--atlas-res"), glow: dark && theme !== "oled" };
  };

  function cell(c, d) {
    const x = pos[2 * d] * S, y = pos[2 * d + 1] * S;
    if (reserved[d]) { ctx.fillStyle = c.res; ctx.globalAlpha = 1; ctx.fillRect(x, y, S, S); return; }
    const b = data.ban.f[d], k = data.captcha.f[d];
    ctx.globalAlpha = 1; ctx.fillStyle = c.free; ctx.fillRect(x, y, S, S);
    if (b > 0) { ctx.fillStyle = c.ban; ctx.globalAlpha = 0.35 + 0.65 * b; ctx.fillRect(x, y, S, S); }
    else if (k > 0) { ctx.fillStyle = c.cap; ctx.globalAlpha = 0.35 + 0.65 * k; ctx.fillRect(x, y, S, S); }
  }

  function glow(c, alpha) {
    // Light, not shadow: a soft bloom under blocked areas, only in the dark theme
    const off = document.createElement("canvas");
    off.width = off.height = N * S;
    const o = off.getContext("2d");
    for (let d = 0; d < N * N; d++) {
      const b = data.ban.f[d], k = data.captcha.f[d];
      if (!b && !k) continue;
      o.fillStyle = b ? c.ban : c.cap; o.globalAlpha = Math.max(b, k);
      o.fillRect(pos[2 * d] * S, pos[2 * d + 1] * S, S, S);
    }
    ctx.save();
    ctx.globalCompositeOperation = "screen"; ctx.globalAlpha = alpha; ctx.filter = "blur(5px)";
    ctx.drawImage(off, 0, 0);
    ctx.restore();
  }

  function draw(animate) {
    cancelAnimationFrame(raf);
    const c = colors();
    ctx.globalAlpha = 1; ctx.fillStyle = c.res; ctx.fillRect(0, 0, cv.width, cv.height);
    if (!animate) {
      for (let d = 0; d < N * N; d++) cell(c, d);
      if (c.glow) glow(c, 0.32);
      return;
    }
    // Signature reveal: the curve is traced in address order, then the blocked areas light up
    const T = 900, t0 = performance.now();
    let done = 0;
    const step = (now) => {
      const p = Math.min(1, (now - t0) / T);
      const eased = 1 - Math.pow(1 - p, 3);
      const upto = Math.floor(eased * N * N);
      for (let d = done; d < upto; d++) cell(c, d);
      done = upto;
      if (p < 1) { raf = requestAnimationFrame(step); return; }
      for (let d = done; d < N * N; d++) cell(c, d);
      if (c.glow) {
        const g0 = performance.now();
        const snap = ctx.getImageData(0, 0, cv.width, cv.height);
        const bloom = (n) => {
          const q = Math.min(1, (n - g0) / 400);
          ctx.putImageData(snap, 0, 0); glow(c, 0.32 * q);
          if (q < 1) raf = requestAnimationFrame(bloom);
        };
        raf = requestAnimationFrame(bloom);
      }
    };
    raf = requestAnimationFrame(step);
  }

  // Hover details (desktop pointers only)
  if (matchMedia("(hover: hover) and (pointer: fine)").matches) {
    cv.addEventListener("pointermove", (e) => {
      const r = cv.getBoundingClientRect();
      const x = Math.floor(((e.clientX - r.left) / r.width) * N), y = Math.floor(((e.clientY - r.top) / r.height) * N);
      if (x < 0 || y < 0 || x >= N || y >= N) { tip.hidden = true; return; }
      const d = xy2d(x, y);
      const net = `${d >>> 8}.${d & 255}.0.0/16`;
      const b = data.ban.f[d], k = data.captcha.f[d];
      const pct = (v) => `${v >= 0.995 ? 100 : v > 0 && v < 0.01 ? "<1" : Math.round(v * 100)} %`;
      tip.textContent = reserved[d] ? `${net} · ${labels.reserved}`
        : b || k ? `${net} · ${b ? `${labels.ban} ${pct(b)}` : ""}${b && k ? " · " : ""}${k ? `${labels.captcha} ${pct(k)}` : ""}` : `${net} · ${labels.free}`;
      tip.hidden = false;
      const px = e.clientX - r.left, py = e.clientY - r.top;
      tip.style.left = `${Math.min(px + 14, r.width - tip.offsetWidth - 6)}px`;
      tip.style.top = `${py + 16 + tip.offsetHeight > r.height ? py - tip.offsetHeight - 10 : py + 16}px`;
    });
    cv.addEventListener("pointerleave", () => (tip.hidden = true));
  }

  draw(!reduceMotion());
  return { redraw: () => draw(false), stop: () => cancelAnimationFrame(raf) };
}
