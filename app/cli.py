"""Wartung:
  docker exec asn-blocker python -m app.cli reset-auth      Anmeldung zuruecksetzen
  docker exec asn-blocker python -m app.cli check-sources   alle externen Datenquellen live pruefen
"""
import ipaddress
import sys
import time

from . import db, sources


def check_sources() -> bool:
    """Fragt jede Quelle ueber dieselben Funktionen ab wie ein echter Lauf und prueft das Ergebnis auf Plausibilitaet."""
    results = []

    def check(name, fn):
        t0 = time.monotonic()
        try:
            detail = fn()
            results.append((True, name, detail, time.monotonic() - t0))
        except Exception as e:  # noqa: BLE001 - jede Quelle einzeln bewerten
            results.append((False, name, f"{type(e).__name__}: {e}", time.monotonic() - t0))

    def expect(cond, msg):
        if not cond:
            raise AssertionError(msg)

    def ripe_prefixes():
        p = sources.asn_prefixes(24940, use_cache=False)
        v4 = [x for x in p if ":" not in x]
        expect(len(v4) > 10 and all(ipaddress.ip_network(x) for x in p), f"AS24940: nur {len(p)} Prefixe")
        return f"AS24940 Hetzner: {len(v4)} IPv4- und {len(p) - len(v4)} IPv6-Prefixe"

    def ripe_ipinfo():
        r = sources.ip_info("1.1.1.1")
        expect(13335 in r["asns"], f"1.1.1.1 -> {r}")
        return f"1.1.1.1 -> AS{r['asns'][0]}, {r['prefix']}"

    def ripe_search():
        r = sources.search_asn("hetzner") if not db.q1("SELECT 1 x FROM asn_names LIMIT 1") else []
        if not r:  # lokale Liste vorhanden -> RIPE-Suche direkt pruefen
            data = sources.http_get(f"{sources.RIPE}/searchcomplete/data.json", {"resource": "hetzner", "sourceapp": sources.RIPE_APP}, 20)
            r = [s for c in data["data"]["categories"] if c["category"] == "ASNs" for s in c["suggestions"]]
        expect(len(r) > 0, "keine Treffer")
        return f"Suche 'hetzner': {len(r)} Treffer"

    def bgptools():
        n = sources.refresh_asn_names()
        hit = sources.search_asn("hetzner")
        expect(any(h["asn"] == 24940 for h in hit), f"AS24940 nicht gefunden: {hit[:3]}")
        cls = db.q1("SELECT class FROM asn_names WHERE asn=24940")["class"]
        return f"{n} ASNs geladen, AS24940 gefunden (Typ: {cls or '-'})"

    def spamhaus():
        d = sources.spamhaus_asndrop(use_cache=False)
        expect(len(d) > 50 and all(isinstance(x["asn"], int) for x in d), f"nur {len(d)} Einträge")
        return f"{len(d)} ASNs, z. B. AS{d[0]['asn']} {d[0]['name']}"

    check("RIPEstat announced-prefixes", ripe_prefixes)
    check("RIPEstat network-info", ripe_ipinfo)
    check("RIPEstat searchcomplete", ripe_search)
    check("bgp.tools asns.csv", bgptools)
    check("Spamhaus ASN-DROP", spamhaus)

    for prov in sources.PROVIDERS.values():
        def provider(prov=prov):
            countries = prov.countries()
            expect(len(countries) >= 5, f"nur {len(countries)} Länder")
            missing = [c["code"] for c in countries if not c["continent"]]
            cc = next((c for c in ("DE", "NL", "US") if any(x["code"] == c for x in countries)), countries[0]["code"])
            ips = prov.ips(cc)
            expect(len(ips) > 0, f"{cc}: keine IPs")
            expect(all(ipaddress.ip_address(i).is_global for i in ips), f"{cc}: nicht-öffentliche IP")
            servers = sum(c["servers"] for c in countries)
            note = f", ohne Kontinent: {','.join(missing)}" if missing else ""
            return f"{len(countries)} Länder, {servers} Einträge; {cc}: {len(ips)} IPs, z. B. {ips[0]}{note}"
        check(f"VPN {prov.name}", provider)

    width = max(len(r[1]) for r in results)
    for ok, name, detail, dt in results:
        print(f"{'OK  ' if ok else 'FAIL'} {name:<{width}}  {dt:5.1f}s  {detail}")
    failed = [r for r in results if not r[0]]
    print(f"\n{len(results) - len(failed)}/{len(results)} Quellen OK")
    return not failed


def main():
    db.init()
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "reset-auth":
        with db.tx() as c:
            db.put("auth_mode", None, c)
            c.execute("DELETE FROM sessions")
        print("Anmeldung zurückgesetzt. Container neu starten – das neue Setup-Token steht dann im Log.")
    elif cmd == "check-sources":
        sys.exit(0 if check_sources() else 1)
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
