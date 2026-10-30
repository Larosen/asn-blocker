// The pages of the app, in navigation order.
import { t } from "../lib.js";
import { Asns } from "./asns.js";
import { Attackers } from "./attackers.js";
import { Audit } from "./audit.js";
import { Exemptions } from "./exemptions.js";
import { Overview } from "./overview.js";
import { Runs } from "./runs.js";
import { Settings } from "./settings.js";
import { Vpn } from "./vpn.js";

export const VIEWS = ["overview", "asns", "attackers", "vpn", "exemptions", "runs", "audit", "settings"];
export const VIEW_COMPONENTS = { overview: Overview, asns: Asns, attackers: Attackers, vpn: Vpn, exemptions: Exemptions, runs: Runs, audit: Audit, settings: Settings };
export const viewName = (v) => ({ overview: t("Overview"), asns: t("ASNs"), attackers: t("Attackers"), vpn: t("VPN exemptions"), exemptions: t("Exemptions"),
  runs: t("Runs"), audit: t("Log"), settings: t("Settings") }[v]);
// Navigation groups: what is happening, what is decided, how it runs
export const NAV_GROUPS = [
  { name: () => t("Monitor"), views: ["overview", "attackers", "runs", "audit"] },
  { name: () => t("Rules"), views: ["asns", "vpn", "exemptions"] },
  { name: () => t("System"), views: ["settings"] },
];
export const groupName = (v) => NAV_GROUPS.find((g) => g.views.includes(v))?.name() ?? "";
export const TABS = ["overview", "asns", "attackers", "runs"];  // the phone's tab bar; everything else is under "More"
