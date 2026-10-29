"""Offline demo server for the UI tests: deterministic data, no network, an in-memory CrowdSec.

    python tests/ui/server.py <data dir> <port>

Signs in as admin / correct-horse-battery. Every external source is replaced by fixed data, so the tests see the same
screens on every run (documentation IPs and private-use ASNs only).
"""
import hashlib
import ipaddress
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
if __name__ == "__main__":
    os.environ["DATA_DIR"] = sys.argv[1]

from app import crowdsec, db, engine, routing, sources  # noqa: E402
from app.store import policies  # noqa: E402
from tests.conftest import FakeBackend  # noqa: E402

PASSWORD = "correct-horse-battery"
NAMES = {  # (name, class, cc)
    64500: ("EXAMPLE-CLOUD", "Content", "US"), 64501: ("EXAMPLE-HOSTING", "Content", "DE"),
    64502: ("EXAMPLE-VPS", "Content", "NL"), 64503: ("EXAMPLE-TRANSIT", "Transit/Access", "GB"),
    64504: ("EXAMPLE-HOME-ISP", "Eyeball", "DE"), 64505: ("EXAMPLE-MOBILE", "Eyeball", "FR"),
    64506: ("EXAMPLE-SCRAPER", "Content", "SG"), 64507: ("EXAMPLE-BULLETPROOF", "Content", "RU"),
    64508: ("EXAMPLE-VPN", "Content", "SE"), 64509: ("EXAMPLE-CDN", "Content", "US"),
}


def fake_prefixes(asn, use_cache=True):
    """A few /16–/22 networks per ASN, spread over the public IPv4 space, plus one IPv6 prefix."""
    h = hashlib.sha256(str(asn).encode()).digest()
    out = []
    for i in range(4 + h[0] % 8):
        a, b = 11 + (h[i + 1] * 7 + i * 13) % 180, h[i + 9]
        if a in (100, 127, 169, 172, 192, 198, 203):
            a += 1
        out.append(f"{a}.{b}.0.0/{16 + h[i + 17] % 7}")
    out.append(f"2001:db8:{asn % 65536:x}::/48")
    return sorted({str(ipaddress.ip_network(p, strict=False)) for p in out})


def fake_ip_info(ip):
    a = ipaddress.ip_address(ip)
    if not a.is_global and not str(a).startswith(("203.0.113.", "198.51.100.")):
        return {"asns": [], "prefix": ""}
    asn = 64500 + int(str(a).split(".")[-1] if a.version == 4 else 0) % 10
    return {"asns": [asn], "prefix": str(ipaddress.ip_network(f"{a}/24", strict=False)) if a.version == 4 else ""}


VPN_ROWS = [("SE", "Sweden", "198.51.100.10"), ("SE", "Sweden", "198.51.100.11"), ("DE", "Germany", "198.51.100.20"),
            ("NL", "Netherlands", "198.51.100.30"), ("US", "United States", "198.51.100.40")]

def install_fakes(patch=setattr):
    """Replaces every network source and CrowdSec. patch: setattr, or pytest's monkeypatch.setattr."""
    patch(sources, "asn_prefixes", fake_prefixes)
    patch(sources, "prefixes_many", lambda asns, use_cache=True: {a: fake_prefixes(a) for a in asns})
    patch(sources, "ip_info", fake_ip_info)
    patch(sources, "ip_holder", lambda ip: "Example Registry")
    patch(sources, "spamhaus_asndrop", lambda use_cache=True: [{"asn": 64507, "name": "EXAMPLE-BULLETPROOF", "cc": "RU"}])
    patch(sources, "refresh_asn_names", lambda: len(NAMES))
    for p in sources.PROVIDERS.values():
        patch(p, "fetch", lambda: list(VPN_ROWS))
        patch(p, "ips", lambda code: [v for cc, _, v in VPN_ROWS if cc == code])
    def fake_routing_refresh(download=None):
        db.put("routes_tried", time.time())
        db.put("routes_error", "demo: no download")
        raise routing.RoutingError("demo: no download")
    patch(routing, "refresh", fake_routing_refresh)
    backend = FakeBackend()
    patch(crowdsec, "backend", lambda: backend)
    return backend


def seed():
    """Settings, rules, exemptions, protection, attacker history and one applied run."""
    from app import auth

    db.init()
    if db.get("auth_mode"):
        return
    now = time.time()
    with db.tx() as c:
        db.put("auth_mode", "local", c)
        db.put("local_user", "admin", c)
        db.put("local_password_hash", auth.hash_password(PASSWORD), c)
        db.put("crowdsec_mode", "lapi", c)
        db.put("lapi_machine_id", "asn-blocker", c)
        db.put("asn_names_updated", now, c)
        c.executemany("INSERT INTO asn_names VALUES(?,?,?,?)", [(a, *v) for a, v in NAMES.items()])
        rules = [(64500, "ban", "scrapers", None), (64501, "ban", "", None), (64502, "captcha", "", now + 30 * 86400),
                 (64503, "captcha", "transit", None), (64506, "ban", "attacking network", now + 90 * 86400)]
        policies.upsert([{"source": "asn", "value": a, "effect": act, "name": NAMES[a][0], "note": note, "expires_at": exp}
                         for a, act, note, exp in rules]
                        + [{"source": "cidr", "value": "203.0.113.0/28", "effect": "allow", "note": "partner"},
                           {"source": "asn", "value": 64509, "effect": "allow", "note": "CDN"}]
                        + [{"source": "vpn", "value": v, "effect": "allow"} for v in ("nordvpn:SE", "nordvpn:DE", "mullvad:NL")]
                        + [{"source": "ip", "value": "198.51.100.42", "effect": "allow", "locked": True, "note": "home"},
                           {"source": "asn", "value": 64504, "effect": "cap", "locked": True, "note": "home ISP"}], c, now)
        c.execute("INSERT INTO watch_ips(ip,note,last_status) VALUES('203.0.113.7','monitoring','clear')")
        for d in range(20):
            day = time.strftime("%Y-%m-%d", time.gmtime(now - d * 86400))
            for i in range(1 + d % 4):
                for asn, n in ((64506, 6), (64501, 3), (64504, 2), (64508, 5)):
                    if i < n:
                        ip = f"{11 + asn % 50}.{d}.{i}.{asn % 200}"
                        c.execute("INSERT OR IGNORE INTO attack_ips VALUES(?,?,?,?,?,?,?)",
                                  (day, ip, asn, NAMES[asn][0], 3 + d % 5, json.dumps(["crowdsecurity/ssh-bf", "crowdsecurity/http-probing"]),
                                   now - d * 86400 - i * 600))
        db.put("attackers_updated", now, c)
        db.bump_rev(c)
    engine.run("apply", "setup")  # a real run against the in-memory CrowdSec: ranges, history, map
    policies.upsert([{"source": "asn", "value": 64501, "effect": "ban", "name": NAMES[64501][0],
                      "note": "edited after the run"}])  # leaves "not applied" changes for the apply bar


if __name__ == "__main__":
    import uvicorn

    install_fakes()
    seed()
    from app import main

    main.engine.scheduler = lambda: None
    uvicorn.run(main.app, host="127.0.0.1", port=int(sys.argv[2]), log_level="warning")
