"""Maintenance:
  docker exec asn-blocker python -m app.cli reset-auth      reset sign-in (prints a new setup token)
  docker exec asn-blocker python -m app.cli check-sources   check all external data sources live
  docker exec -e SSH_CLIENT asn-blocker python -m app.cli protect [IP] [--ip-only]
      permanently protect the IP and ASN of the current SSH connection (or the given IP) from blocks
  docker exec asn-blocker python -m app.cli protect --list  show protected IPs/ASNs and SSH sessions
"""
import ipaddress
import os
import sys
import time

from . import auth, db, selfprotect, sources


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

    def ripe_prefixes():
        p = sources.asn_prefixes(24940, use_cache=False)
        v4 = [x for x in p if ":" not in x]
        expect(len(v4) > 10 and all(ipaddress.ip_network(x) for x in p), f"AS24940: only {len(p)} prefixes")
        return f"AS24940 Hetzner: {len(v4)} IPv4 and {len(p) - len(v4)} IPv6 prefixes"

    def ripe_ipinfo():
        r = sources.ip_info("1.1.1.1")
        expect(13335 in r["asns"], f"1.1.1.1 -> {r}")
        return f"1.1.1.1 -> AS{r['asns'][0]}, {r['prefix']}"

    def ripe_search():
        r = sources.search_asn("hetzner") if not db.q1("SELECT 1 x FROM asn_names LIMIT 1") else []
        if not r:  # local list present -> check RIPE search directly
            data = sources.http_get(f"{sources.RIPE}/searchcomplete/data.json", {"resource": "hetzner", "sourceapp": sources.RIPE_APP}, 20)
            r = [s for c in data["data"]["categories"] if c["category"] == "ASNs" for s in c["suggestions"]]
        expect(len(r) > 0, "no results")
        return f"Search 'hetzner': {len(r)} results"

    def bgptools():
        n = sources.refresh_asn_names()
        hit = sources.search_asn("hetzner")
        expect(any(h["asn"] == 24940 for h in hit), f"AS24940 not found: {hit[:3]}")
        cls = db.q1("SELECT class FROM asn_names WHERE asn=24940")["class"]
        return f"{n} ASNs loaded, AS24940 found (type: {cls or '-'})"

    def spamhaus():
        d = sources.spamhaus_asndrop(use_cache=False)
        expect(len(d) > 50 and all(isinstance(x["asn"], int) for x in d), f"only {len(d)} entries")
        return f"{len(d)} ASNs, e.g. AS{d[0]['asn']} {d[0]['name']}"

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
            return f"{len(countries)} countries, {servers} entries; {cc}: {len(ips)} IPs, e.g. {ips[0]}{note}"
        check(f"VPN {prov.name}", provider)

    width = max(len(r[1]) for r in results)
    for ok, name, detail, dt in results:
        print(f"{'OK  ' if ok else 'FAIL'} {name:<{width}}  {dt:5.1f}s  {detail}")
    failed = [r for r in results if not r[0]]
    print(f"\n{len(results) - len(failed)}/{len(results)} sources OK")
    return not failed


def protect(args) -> bool:
    if "--list" in args:
        sessions, status = selfprotect.ssh_sessions()
        print(f"SSH sessions ({status}):")
        for s in sessions:
            print(f"  {s['ip']:<40} {s['user']}@{s['line']}")
        print("Protected:")
        for r in selfprotect.protected():
            print(f"  {r['kind']:<4} {r['value']:<40} {r['note']}")
        return True
    ips = [a for a in args if not a.startswith("--")]
    ip = ips[0] if ips else (os.environ.get("SSH_CLIENT") or os.environ.get("SSH_CONNECTION") or "").split(" ")[0]
    if not ip:
        print("No IP given and SSH_CLIENT not set.\n"
              "Run from the SSH session with: docker exec -e SSH_CLIENT asn-blocker python -m app.cli protect")
        return False
    try:
        asns = selfprotect.protect_ip(ip, "SSH (CLI)", with_asn="--ip-only" not in args)
    except ValueError:
        print(f"Not a valid IP: {ip}")
        return False
    except sources.SourceError as e:
        print(f"IP {ip} protected, could not determine ASN: {e}")
        return False
    with db.tx() as c:
        removed = [a for a in asns if c.execute("DELETE FROM asn_rules WHERE asn=?", (a,)).rowcount]
    print(f"Protected: {ip}" + "".join(f", AS{a} {sources.asn_name(a)}" for a in asns))
    if removed:
        print("Removed block rules: " + ", ".join(f"AS{a}" for a in removed))
    print("Takes effect on the next run – click 'Apply' in the web UI.")
    return True


def main():
    db.init()
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "reset-auth":
        with db.tx() as c:
            db.put("auth_mode", None, c)
            c.execute("DELETE FROM sessions")
        print(f"Sign-in reset. Open the web UI and complete the setup with this setup token:\n  {auth.new_setup_token()}\n"
              "(Any older setup token is no longer valid.)")
    elif cmd == "protect":
        sys.exit(0 if protect(sys.argv[2:]) else 1)
    elif cmd == "check-sources":
        sys.exit(0 if check_sources() else 1)
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
