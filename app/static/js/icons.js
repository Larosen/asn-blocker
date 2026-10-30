// Line icons on a 24 px grid, drawn for this app (stroke = currentColor, so they follow text colour and theme).
import { html } from "./lib.js";

const P = {  // functions: a vnode must not be rendered in two places at once
  overview: () => html`<rect x="3.5" y="3.5" width="7" height="7" rx="1.5" /><rect x="13.5" y="3.5" width="7" height="4" rx="1.5" /><rect x="13.5" y="10.5" width="7" height="10" rx="1.5" /><rect x="3.5" y="13.5" width="7" height="7" rx="1.5" />`,
  asns: () => html`<circle cx="12" cy="12" r="8.5" /><path d="M3.5 12h17M12 3.5c2.6 2.3 3.8 5.2 3.8 8.5s-1.2 6.2-3.8 8.5M12 3.5C9.4 5.8 8.2 8.7 8.2 12s1.2 6.2 3.8 8.5" />`,
  attackers: () => html`<circle cx="12" cy="12" r="7.5" /><circle cx="12" cy="12" r="2" /><path d="M12 2.5v4M12 17.5v4M2.5 12h4M17.5 12h4" />`,
  vpn: () => html`<rect x="4.5" y="10.5" width="15" height="10" rx="2" /><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3M12 14.5v2" />`,
  exemptions: () => html`<path d="M12 3.2 19 6v5.2c0 4.3-2.9 8-7 9.6-4.1-1.6-7-5.3-7-9.6V6z" /><path d="m9 12 2.2 2.2L15.5 10" />`,
  runs: () => html`<path d="M3 12h3.5l2.5-6.5 4.5 13 2.8-6.5H21" />`,
  audit: () => html`<path d="M9 6.5h11M9 12h11M9 17.5h11M4.5 6.5h.5M4.5 12h.5M4.5 17.5h.5" />`,
  settings: () => html`<path d="M4 7.5h9M17 7.5h3M4 16.5h3M11 16.5h9" /><circle cx="15" cy="7.5" r="2" /><circle cx="9" cy="16.5" r="2" />`,
  search: () => html`<circle cx="11" cy="11" r="6.5" /><path d="m20 20-4.2-4.2" />`,
  close: () => html`<path d="M6.5 6.5l11 11M17.5 6.5l-11 11" />`,
  more: () => html`<path d="M5 12h.5M12 12h.5M19 12h.5" stroke-width="3" />`,
  auto: () => html`<rect x="3.5" y="4.5" width="17" height="11.5" rx="2" /><path d="M8.5 20h7M12 16v4" />`,
  light: () => html`<circle cx="12" cy="12" r="3.8" /><path d="M12 3v1.8M12 19.2V21M3 12h1.8M19.2 12H21M5.6 5.6l1.3 1.3M17.1 17.1l1.3 1.3M5.6 18.4l1.3-1.3M17.1 6.9l1.3-1.3" />`,
  dark: () => html`<path d="M19.5 14.6A7.8 7.8 0 1 1 9.4 4.5a6.2 6.2 0 0 0 10.1 10.1z" />`,
  oled: () => html`<circle cx="12" cy="12" r="8" /><path d="M12 4a8 8 0 0 1 0 16z" fill="currentColor" />`,
  signout: () => html`<path d="M14 4.5h3.5a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H14M10 8l-4 4 4 4M6 12h10" />`,
  apply: () => html`<path d="M7 5.5v13l11-6.5z" />`,
  preview: () => html`<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z" /><circle cx="12" cy="12" r="2.8" />`,
  paste: () => html`<rect x="8.5" y="3" width="7" height="3.5" rx="1" /><path d="M8.5 5H6.5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2" />`,
  spark: () => html`<path d="M12 3.5 13.8 10.2 20.5 12l-6.7 1.8L12 20.5l-1.8-6.7L3.5 12l6.7-1.8z" />`,
  ip: () => html`<circle cx="12" cy="12" r="8.5" /><circle cx="12" cy="12" r="3" /><path d="M12 3.5v3M12 17.5v3" />`,
  arrow: () => html`<path d="M5 12h14M13 6l6 6-6 6" />`,
};

// aria-hidden: an icon never carries meaning on its own – the text or aria-label next to it does
export const Icon = ({ name, size = 16 }) => html`<svg class="icon" width=${size} height=${size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
  stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${P[name]?.()}</svg>`;
