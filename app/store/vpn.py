"""VPN exemptions: the selected countries per provider, and whether exact server IPs or their /24 (/64) are exempt."""
from collections import defaultdict

from .. import db


def selections():
    """{provider: [country codes]}"""
    out = defaultdict(list)
    for r in db.q("SELECT provider, country FROM vpn_rules ORDER BY provider, country"):
        out[r["provider"]].append(r["country"])
    return dict(out)


def modes():
    return db.get("vpn_modes") or {}


def count():
    return db.q1("SELECT count(*) n FROM vpn_rules")["n"]


def select(provider, countries, mode):
    with db.tx() as c:
        c.execute("DELETE FROM vpn_rules WHERE provider=?", (provider,))
        c.executemany("INSERT INTO vpn_rules VALUES(?,?)", [(provider, cc) for cc in countries])
        db.put("vpn_modes", modes() | {provider: mode}, c)
        db.bump_rev(c)


def add(pairs, provider_modes=None, c=None):
    """Import: adds (provider, country) pairs; provider_modes replaces the modes if given."""
    with db.tx_or(c) as c:
        c.executemany("INSERT OR IGNORE INTO vpn_rules VALUES(?,?)", pairs)
        if provider_modes is not None:
            db.put("vpn_modes", provider_modes, c)
        db.bump_rev(c)


def export():
    return db.q("SELECT provider,country FROM vpn_rules")
