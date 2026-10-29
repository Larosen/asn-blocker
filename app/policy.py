"""The evaluator: from the active policies to the ranges CrowdSec gets – and, for one IP, which policies apply and which
one wins.

Every policy resolves to networks (an ASN to its announced prefixes, a VPN selection to its server IPs, a list to the
prefixes of its ASNs). Where networks of different policies overlap, the stronger effect wins, per address:

    allow (never blocked)  >  cap (at most captcha)  >  ban  >  captcha

Non-public ranges, active SSH sessions and locked (self-protection) policies always count as allow. Allow and cap
policies of an ASN fail closed: without prefixes the run stops rather than run without the exemption.
"""
import ipaddress
from collections import defaultdict

from . import db, netset, routing, selfprotect, sources
from .store import lists, policies, vpn

# Never blocked, whatever a source says: private, loopback, link-local, CGNAT, documentation, multicast, reserved
NON_PUBLIC = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
    "::/8", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8")]
# Shorter prefixes are never announced by a single real ASN
MIN_PREFIXLEN = {4: 8, 6: 16}
RANK = policies.RANK


def plausible(nets, what, log):
    """No real ASN announces prefixes shorter than MIN_PREFIXLEN – from a broken or poisoned source they would block
    (or, as exemption, unblock) huge parts of the internet."""
    huge = [n for n in nets if n.prefixlen < MIN_PREFIXLEN[n.version]]
    if huge:
        log(f"  WARNING {what}: ignored implausibly large prefixes {', '.join(map(str, huge[:5]))}")
    return [n for n in nets if n.prefixlen >= MIN_PREFIXLEN[n.version]]


def canonical(ip):
    """IPv4-mapped IPv6 (::ffff:a.b.c.d) protects the IPv4 address it stands for."""
    a = ipaddress.ip_address(str(ip).split("/")[0])
    return str(ipaddress.ip_network(a.ipv4_mapped if a.version == 6 and a.ipv4_mapped else a))


def guard_ips():
    """All IPs that must never be blocked: protected IPs + active SSH sessions. {ip_cidr: label}"""
    out = {}
    for p in policies.listing("ip", effects=("allow",), locked=True, active=True):
        out[canonical(p["value"])] = "Self-protection" + (f": {p['note']}" if p["note"] else "")
    sessions, _ = selfprotect.ssh_sessions()
    for s in sessions:
        out.setdefault(canonical(s["ip"]), f"SSH session {s['user']}@{s['line']}")
    return out


def _vpn_networks(provider, cc, widen):
    prov = sources.PROVIDERS.get(provider)
    if not prov:
        raise sources.SourceError(f"Unknown VPN provider {provider}")
    ips = prov.ips(cc)
    if not ips:
        raise sources.SourceError(f"{prov.name} {cc}: no server IPs found")
    out = []
    for ip in ips:
        a = ipaddress.ip_address(ip)
        plen = (24 if a.version == 4 else 64) if widen else a.max_prefixlen
        out.append(ipaddress.ip_network(f"{ip}/{plen}", strict=False))
    return prov, out


def evaluate(log, fresh=True):
    """Returns ({'ban': [cidr], 'captcha': [cidr]}, [(cidr, label)] of everything exempted)."""
    ipv6 = db.get("include_ipv6")
    modes = vpn.modes()
    active = policies.listing(active=True)
    by = defaultdict(list)
    for p in active:
        by[(p["source"], p["effect"], p["locked"])].append(p)

    log("Collecting exemptions")
    exempt = []  # (network, label)
    vpn_sel = defaultdict(list)
    for p in by[("vpn", "allow", False)] + by[("vpn", "allow", True)]:
        provider, _, cc = p["value"].partition(":")
        vpn_sel[provider].append(cc)
    for provider, countries in sorted(vpn_sel.items()):
        prov = sources.PROVIDERS.get(provider)
        if fresh and prov:
            prov.entries(fresh=True)  # same validation and limits as every other read
        widen = modes.get(provider) == "net"
        for cc in sorted(countries):
            prov, nets = _vpn_networks(provider, cc, widen)
            exempt += [(n, f"VPN {prov.name} {cc}") for n in nets]
            log(f"  {prov.name} {cc}: {len(nets)} server IPs" + (" (as network)" if widen else ""))

    ex_asns = sorted(int(p["value"]) for p in by[("asn", "allow", False)])
    for asn, pfx in sources.prefixes_many(ex_asns, use_cache=not fresh).items():
        if not pfx:
            raise sources.SourceError(f"Exempt AS{asn}: no prefixes")
        exempt += [(n, f"Exempt AS{asn}") for n in plausible(netset.parse(pfx), f"exempt AS{asn}", log)]
        log(f"  Exempt AS{asn}: {len(pfx)} prefixes")
    for p in by[("cidr", "allow", False)] + by[("ip", "allow", False)]:
        exempt += [(n, "Manual" + (f": {p['note']}" if p["note"] else "")) for n in netset.parse([p["value"]])]
    for p in by[("cidr", "allow", True)]:
        exempt += [(n, "Self-protection" + (f": {p['note']}" if p["note"] else "")) for n in netset.parse([p["value"]])]

    exempt += [(n, "Non-public range") for n in NON_PUBLIC]
    guard = guard_ips()
    exempt += [(ipaddress.ip_network(ip), label) for ip, label in guard.items()]
    prot_asns = sorted(int(p["value"]) for p in by[("asn", "allow", True)])
    capped_asns = sorted(int(p["value"]) for p in by[("asn", "cap", True)] + by[("asn", "cap", False)])
    capped = []  # networks that may get a captcha but are never banned
    for asn, pfx in sources.prefixes_many(prot_asns + capped_asns, use_cache=not fresh).items():
        if not pfx:  # fail closed like exempt ASNs: better no run than a run without the protection
            raise sources.SourceError(f"Self-protection AS{asn}: no prefixes")
        nets = plausible(netset.parse(pfx), f"protected AS{asn}", log)
        if asn in capped_asns:
            capped += nets
        else:
            exempt += [(n, f"Self-protection AS{asn}") for n in nets]
    log(f"  Self-protection: {len(guard)} IPs, {len(prot_asns)} ASNs never blocked, {len(capped_asns)} ASNs at most captcha")

    st = routing.status()
    log("Collecting ASN ranges – " + (f"local routing table ({st['prefixes']:,} prefixes, "
                                      f"{(__import__('time').time() - st['updated']) / 3600:.0f} h old)" if routing.fresh()
                                      else "from RIPEstat (no current local routing table)"))
    rules = {int(p["value"]): {"name": p["name"], "action": p["effect"]} for p in by[("asn", "ban", False)] + by[("asn", "captcha", False)]}
    drop_effect = lists.spamhaus()
    if drop_effect:
        drop = sources.spamhaus_asndrop(use_cache=not fresh)
        added = 0
        for d in drop:
            if d["asn"] not in rules:
                rules[d["asn"]] = {"name": d["name"], "action": drop_effect, "spamhaus": True}
                added += 1
        log(f"  Spamhaus ASN-DROP: {len(drop)} ASNs, {added} of them additional")
    for asn in set(rules) & set(prot_asns):
        log(f"  AS{asn} is protected (self-protection) – rule ignored")
        del rules[asn]
    for asn in set(rules) & set(capped_asns):
        if rules[asn]["action"] == "ban":
            log(f"  AS{asn} is protected against bans – captcha instead")
            rules[asn] = {**rules[asn], "action": "captcha"}
    raw = {"ban": [], "captcha": []}
    for p in by[("cidr", "ban", False)] + by[("cidr", "captcha", False)]:
        raw[p["effect"]] += netset.parse([p["value"]])
    prefixes = sources.prefixes_many(rules, use_cache=not fresh)
    spamhaus = [0, 0]  # ASNs, prefixes – summarized instead of hundreds of individual lines
    for asn, r in sorted(rules.items()):
        nets = [n for n in netset.parse(prefixes[asn]) if ipv6 or n.version == 4]
        nets = plausible(nets, f"AS{asn}", log)
        raw[r["action"]] += nets
        if r.get("spamhaus"):
            spamhaus[0] += 1
            spamhaus[1] += len(nets)
        else:
            log(f"  AS{asn} {r.get('name') or sources.asn_name(asn)} -> {r['action']}: {len(nets)} prefixes")
    if spamhaus[0]:
        log(f"  Spamhaus ASN-DROP -> {drop_effect}: {spamhaus[0]} ASNs, {spamhaus[1]} prefixes")

    log("Carving out exemptions")
    ex_nets = [n for n, _ in exempt]
    ban = netset.subtract(raw["ban"], ex_nets + capped)
    # bans that fall into networks protected against bans (e.g. through Spamhaus or another ASN's prefix) become captcha
    downgraded = netset.subtract(raw["ban"], ex_nets + ban) if capped else []
    captcha = netset.subtract(raw["captcha"] + downgraded, ex_nets + ban)  # captcha only where not already banned
    if downgraded:
        log(f"  {len(downgraded)} ranges in networks protected against bans: captcha instead of ban")
    log(f"  ban: {len(ban)} ranges, captcha: {len(captcha)} ranges, {len(netset.collapse(ex_nets))} exempt networks")
    # hard final check: no protected IP may end up in a block
    ranges = {"ban": [str(n) for n in ban], "captcha": [str(n) for n in captcha]}
    for ip, label in guard.items():
        hit = status_of(str(ipaddress.ip_network(ip).network_address), ranges)
        if hit:
            raise sources.SourceError(f"Self-protection violated: {ip} ({label}) would be hit by {hit} – run aborted")
    return ranges, [(str(n), label) for n, label in exempt]


def status_of(ip, ranges):
    """'ban' | 'captcha' | None for an IP against {type: [cidr]}"""
    for t in ("ban", "captcha"):
        if netset.contains(ranges.get(t, []), ip):
            return t
    return None


# --- Explain ----------------------------------------------------------------------------------------------------

def _covering(nets, a):
    for n in nets:
        try:
            if a in ipaddress.ip_network(n, strict=False):
                return str(n)
        except ValueError:
            continue
    return None


def explain(ip):
    """Every active policy that covers the IP, and the decision: what the IP gets once the rules are applied.
    Uses cached or local data only where possible; an ASN that cannot be resolved is reported, not guessed."""
    a = ipaddress.ip_address(ip)
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    ipv6 = db.get("include_ipv6")
    matches, problems = [], []
    try:
        origin = sources.ip_info(str(a)) if a.is_global else {"asns": [], "prefix": ""}
    except sources.SourceError as e:
        origin, problems = {"asns": [], "prefix": ""}, [str(e)]
    for p in policies.listing(active=True):
        via = None
        try:
            if p["source"] in ("cidr", "ip"):
                via = _covering([p["value"]], a)
            elif p["source"] == "asn":
                via = _covering(sources.asn_prefixes(int(p["value"])), a)
            elif p["source"] == "vpn":
                provider, _, cc = p["value"].partition(":")
                _, nets = _vpn_networks(provider, cc, vpn.modes().get(provider) == "net")
                via = _covering(nets, a)
            elif p["source"] == "list":  # the IP's own network is on the list
                drop = {d["asn"] for d in sources.spamhaus_asndrop()}
                hit = sorted(set(origin["asns"]) & drop)
                via = f"AS{hit[0]} on the list" if hit else None
        except (sources.SourceError, ValueError) as e:
            problems.append(f"{p['source']} {p['value']}: {e}")
        if via and p["effect"] in ("ban", "captcha") and a.version == 6 and not ipv6 and p["source"] != "cidr":
            via = None  # IPv6 prefixes of ASNs are only blocked with the IPv6 setting
        if via:
            matches.append({**p, "via": via})
    implicit = []
    if any(a in n for n in NON_PUBLIC) or not a.is_global:
        implicit.append("Non-public range")
    for g, label in guard_ips().items():
        if a in ipaddress.ip_network(g) and label.startswith("SSH session"):
            implicit.append(label)

    effects = {m["effect"] for m in matches}
    if implicit or "allow" in effects:
        decision = "allow"
    elif "ban" in effects:
        decision = "captcha" if "cap" in effects else "ban"
    elif "captcha" in effects:
        decision = "captcha"
    else:
        decision = None
    if decision == "allow":
        winner = next((m for m in sorted(matches, key=lambda m: (m["effect"] != "allow", not m["locked"]))), None)
    elif decision:
        winner = max((m for m in matches if m["effect"] in ("ban", "captcha")), key=lambda m: RANK[m["effect"]])
    else:
        winner = None
    for m in matches:
        m["wins"] = winner is not None and m["id"] == winner["id"]
    matches.sort(key=lambda m: (-RANK[m["effect"]], not m["locked"]))
    return {"decision": decision, "implicit": implicit, "matches": matches, "problems": problems,
            "capped": decision == "captcha" and "ban" in effects and "cap" in effects}
