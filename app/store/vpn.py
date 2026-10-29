"""VPN exemptions: the selected countries per provider (allow policies of source 'vpn', value 'provider:CC'), and
whether exact server IPs or their /24 (/64) are exempt (a setting per provider)."""
from collections import defaultdict

from .. import db
from . import policies


def selections():
    """{provider: [country codes]}"""
    out = defaultdict(list)
    for p in policies.listing("vpn", effects=("allow",)):
        provider, _, cc = p["value"].partition(":")
        out[provider].append(cc)
    return {k: sorted(v) for k, v in sorted(out.items())}


def modes():
    return db.get("vpn_modes") or {}


def count():
    return policies.count("vpn", ("allow",))


def select(provider, countries, mode):
    with db.tx() as c:
        for cc in set(selections().get(provider, [])) - set(countries):
            policies.delete("vpn", f"{provider}:{cc}", ("allow",), c=c)
        policies.upsert([{"source": "vpn", "value": f"{provider}:{cc}", "effect": "allow"} for cc in countries
                         if cc not in selections().get(provider, [])], c)
        db.put("vpn_modes", modes() | {provider: mode}, c)
        db.bump_rev(c)


def add(pairs, provider_modes=None, c=None):
    """Import: adds (provider, country) pairs; provider_modes replaces the modes if given."""
    with db.tx_or(c) as c:
        have = {(p, cc) for p, ccs in selections().items() for cc in ccs}
        policies.upsert([{"source": "vpn", "value": f"{p}:{cc}", "effect": "allow"} for p, cc in pairs if (p, cc) not in have], c)
        if provider_modes is not None:
            db.put("vpn_modes", provider_modes, c)
        db.bump_rev(c)


def export():
    return [{"provider": p, "country": cc} for p, ccs in selections().items() for cc in ccs]
