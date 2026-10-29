"""Maintenance:
  docker exec asn-blocker python -m app.cli reset-auth      reset sign-in (prints a new setup token)
  docker exec asn-blocker python -m app.cli check-sources   check all external data sources live
  docker exec asn-blocker python -m app.cli trust-proxy NAME  trust a reverse proxy by container name, IP or CIDR
  docker exec asn-blocker python -m app.cli untrust-proxy NAME  remove a trusted proxy entry
  docker exec -e SSH_CLIENT asn-blocker python -m app.cli protect [IP] [--asn | --asn-exempt]
      permanently protect the IP of the current SSH connection (or the given IP) from blocks;
      --asn also protects its network against bans (captcha stays possible), --asn-exempt never blocks it
  docker exec asn-blocker python -m app.cli protect --list  show protected IPs/ASNs and SSH sessions
"""
import ipaddress
import os
import sys
import time

from . import auth, db, routing, selfprotect, sources
from .store import rules as rule_store


def check_sources() -> bool:
    """Queries every source through the same functions as a real run and sanity-checks the result."""
    results = []

    def check(name, fn):
        t0 = time.monotonic()
        try:
            detail = fn()
            results.append((True, name, detail, time.monotonic() - t0))
        except Exception as e:  # noqa: BLE001 - evaluate each source on its own
            results.append((False, name, f"{type(e).__name__}: {e}", time.monotonic() - t0))

    def expect(cond, msg):
        if not cond:
            raise AssertionError(msg)

    def ripe_prefixes():  # the fallback, asked directly
        p = sorted(x["prefix"] for x in sources._ripe("announced-prefixes", "AS24940")["prefixes"])
        v4 = [x for x in p if ":" not in x]
        expect(len(v4) > 10 and all(ipaddress.ip_network(x) for x in p), f"AS24940: only {len(p)} prefixes")
        return f"AS24940 Hetzner: {len(v4)} IPv4 and {len(p) - len(v4)} IPv6 prefixes"

    def ripe_ipinfo():
        r = sources._ripe("network-info", "1.1.1.1", 20)
        r = {"asns": [int(a) for a in r.get("asns") or []], "prefix": r.get("prefix")}
        expect(13335 in r["asns"], f"1.1.1.1 -> {r}")
        return f"1.1.1.1 -> AS{r['asns'][0]}, {r['prefix']}"

    def ripe_search():
        r = sources.search_asn("hetzner") if not sources.asn_info(24940)["name"] else []
        if not r:  # local list present -> check RIPE search directly
            data = sources.http_get(f"{sources.RIPE}/searchcomplete/data.json", {"resource": "hetzner", "sourceapp": sources.RIPE_APP}, 20)
            r = [s for c in data["data"]["categories"] if c["category"] == "ASNs" for s in c["suggestions"]]
        expect(len(r) > 0, "no results")
        return f"Search 'hetzner': {len(r)} results"

    def bgptools():
        n = sources.refresh_asn_names()
        hit = sources.search_asn("hetzner")
        expect(any(h["asn"] == 24940 for h in hit), f"AS24940 not found: {hit[:3]}")
        cls = sources.asn_info(24940)["class"]
        return f"{n} ASNs loaded, AS24940 found (type: {cls or '-'})"

    def spamhaus():
        d = sources.spamhaus_asndrop(use_cache=False)
        expect(len(d) > 50 and all(isinstance(x["asn"], int) for x in d), f"only {len(d)} entries")
        return f"{len(d)} ASNs, e.g. AS{d[0]['asn']} {d[0]['name']}"

    def routing_table():
        n = routing.refresh()  # loads it, exactly as the daily update does
        p = routing.prefixes(24940) or []
        expect(len(p) > 10, f"AS24940: only {len(p)} prefixes")
        hit = routing.lookup("1.1.1.1")
        expect(13335 in hit["asns"], f"1.1.1.1 -> {hit}")
        return f"{n:,} prefixes loaded; AS24940: {len(p)} prefixes; 1.1.1.1 -> AS13335 ({hit['prefix']})"

    check("bgp.tools routing table", routing_table)
    check("RIPEstat announced-prefixes", ripe_prefixes)
    check("RIPEstat network-info", ripe_ipinfo)
    check("RIPEstat searchcomplete", ripe_search)
    check("bgp.tools asns.csv", bgptools)
    check("Spamhaus ASN-DROP", spamhaus)

    for prov in sources.PROVIDERS.values():
        def provider(prov=prov):
            countries = prov.countries()
            expect(len(countries) >= 5, f"only {len(countries)} countries")
            missing = [c["code"] for c in countries if not c["continent"]]
            cc = next((c for c in ("DE", "NL", "US") if any(x["code"] == c for x in countries)), countries[0]["code"])
            ips = prov.ips(cc)
            expect(len(ips) > 0, f"{cc}: no IPs")
            expect(all(ipaddress.ip_address(i).is_global for i in ips), f"{cc}: non-public IP")
            servers = sum(c["servers"] for c in countries)
            note = f", no continent: {','.join(missing)}" if missing else ""
            via = f" (via {prov.source})" if getattr(prov, "source", None) else ""
            return f"{len(countries)} countries, {servers} entries; {cc}: {len(ips)} IPs, e.g. {ips[0]}{note}{via}"
        check(f"VPN {prov.name}", provider)

    width = max(len(r[1]) for r in results)
    for ok, name, detail, dt in results:
        print(f"{'OK  ' if ok else 'FAIL'} {name:<{width}}  {dt:5.1f}s  {sources.clean(detail, 200)}")
    failed = [r for r in results if not r[0]]
    print(f"\n{len(results) - len(failed)}/{len(results)} sources OK")
    return not failed


def protect(args) -> bool:
    if "--list" in args:
        sessions, status = selfprotect.ssh_sessions()
        print(f"SSH sessions ({status}):")
        for s in sessions:
            print(f"  {s['ip']:<40} {sources.clean(s['user'], 40)}@{sources.clean(s['line'], 40)}")
        print("Protected:")
        for r in selfprotect.protected():
            mode = {"exempt": "never blocked", "captcha": "at most captcha"}[r["mode"]] if r["kind"] == "asn" else ""
            print(f"  {r['kind']:<4} {r['value']:<40} {mode:<16} {sources.clean(r['note'], 80)}")
        return True
    ips = [a for a in args if not a.startswith("--")]
    ip = ips[0] if ips else (os.environ.get("SSH_CLIENT") or os.environ.get("SSH_CONNECTION") or "").split(" ")[0]
    if not ip:
        print("No IP given and SSH_CLIENT not set.\n"
              "Run from the SSH session with: docker exec -e SSH_CLIENT asn-blocker python -m app.cli protect")
        return False
    try:
        if not ipaddress.ip_address(ip).is_global:
            print(f"{ip} is not a public address (e.g. a VPN, Tailscale or bastion address). Protect the public IP you "
                  "connect from instead: docker exec asn-blocker python -m app.cli protect <public-ip>")
            return False
        mode = "exempt" if "--asn-exempt" in args else "captcha"
        asns = selfprotect.protect_ip(ip, "SSH (CLI)", with_asn="--asn" in args or "--asn-exempt" in args, asn_mode=mode)
    except ValueError:
        print(f"Not a valid IP: {sources.clean(ip, 60)}")
        return False
    except sources.SourceError as e:
        print(f"IP {ip} protected, could not determine ASN: {sources.clean(e)}")
        return False
    changed = rule_store.apply_protection(asns, mode)
    print(f"Protected: {ip}" + "".join(f", AS{a} {sources.clean(sources.asn_name(a), 60)} "
                                       f"({'never blocked' if mode == 'exempt' else 'at most captcha'})" for a in asns))
    if changed:
        print(("Removed block rules: " if mode == "exempt" else "Block rules changed to captcha: ") + ", ".join(f"AS{a}" for a in changed))
    print("Takes effect on the next run – click 'Apply' in the web UI.")
    return True


def trust_proxy(args) -> bool:
    """Adds a reverse proxy (container name, IP or CIDR) whose user header and X-Forwarded-For are accepted."""
    if len(args) != 1:
        print("Usage: python -m app.cli trust-proxy <container name | IP | CIDR>   e.g. trust-proxy gerbil")
        return False
    try:
        entry = auth.normalize_proxy(args[0])
    except ValueError as e:
        print(e)
        return False
    if auth._is_name(entry):
        addrs = auth.resolve_name(entry)
        if not addrs:
            print(f"{entry} does not resolve from inside this container – is the proxy on a shared Docker network?")
            return False
        print(f"{entry} -> {', '.join(sorted(addrs))}")
    with db.tx() as c:
        current = db.get("trusted_proxies") or []
        if entry not in current:
            db.put("trusted_proxies", current + [entry], c)
    db.audit("cli", "proxy.trust", {"entry": entry})
    trusted = db.get("trusted_proxies")
    print("Trusted proxies: " + ", ".join(trusted))
    stale = [e for e in trusted if e != entry and not auth._is_name(e)]
    if stale:
        print(f"If {', '.join(stale)} no longer belongs to your proxy, remove it under Settings → Access: "
              "whatever gets that address next would be trusted.")
    return True


def untrust_proxy(args) -> bool:
    """Removes a trusted proxy entry."""
    if len(args) != 1:
        print("Usage: python -m app.cli untrust-proxy <entry as listed>")
        return False
    try:
        entry = auth.normalize_proxy(args[0])
    except ValueError as e:
        print(e)
        return False
    with db.tx() as c:
        current = db.get("trusted_proxies") or []
        if entry not in current:
            print(f"{entry} is not a trusted proxy. Trusted proxies: {', '.join(current) or '-'}")
            return False
        db.put("trusted_proxies", [e for e in current if e != entry], c)
    db.audit("cli", "proxy.untrust", {"entry": entry})
    print("Trusted proxies: " + (", ".join(db.get("trusted_proxies")) or "-"))
    return True


def main():
    db.init()
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "reset-auth":
        with db.tx() as c:
            db.put("auth_mode", None, c)
            auth.drop_all_sessions(c)
        print(f"Sign-in reset. Open the web UI and complete the setup with this setup token:\n  {auth.new_setup_token()}\n"
              "(Any older setup token is no longer valid.)")
    elif cmd == "untrust-proxy":
        sys.exit(0 if untrust_proxy(sys.argv[2:]) else 1)
    elif cmd == "trust-proxy":
        sys.exit(0 if trust_proxy(sys.argv[2:]) else 1)
    elif cmd == "protect":
        sys.exit(0 if protect(sys.argv[2:]) else 1)
    elif cmd == "check-sources":
        sys.exit(0 if check_sources() else 1)
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
