"""ASN rules: Block or Captcha per ASN, optionally with a lifetime – the block policies of source 'asn'."""
import time

from .. import sources
from . import policies

BLOCK = ("ban", "captcha")


def _rule(p):
    return {"asn": int(p["value"]), "name": p["name"], "action": p["effect"], "note": p["note"], "source": p["origin"],
            "updated_at": p["updated"], "expires_at": p["expires_at"]}


def listing():
    """All rules with the ASN's type and country, for the rules table."""
    out = []
    for p in sorted(policies.listing("asn", effects=BLOCK, locked=False), key=lambda p: int(p["value"])):
        info = sources.asn_info(int(p["value"]))
        out.append(_rule(p) | {"class": info["class"] or None, "cc": info["cc"] or None})
    return out


def active(now=None):
    """{asn: rule} – an expired rule no longer counts, even before expire() has removed it."""
    now = time.time() if now is None else now
    return {r["asn"]: r for r in map(_rule, policies.listing("asn", effects=BLOCK, locked=False))
            if r["expires_at"] is None or r["expires_at"] > now}


def actions():
    return {int(p["value"]): p["effect"] for p in policies.listing("asn", effects=BLOCK, locked=False)}


def asns():
    return set(actions())


def count():
    return policies.count("asn", effects=BLOCK, locked=False)


def upsert(rules, now=None, c=None):
    """rules: dicts with asn, name, action, note, expires_at (None = permanent). Replaces existing rules of these ASNs."""
    policies.upsert([{"source": "asn", "value": r["asn"], "effect": r["action"], "name": r.get("name"), "note": r.get("note"),
                      "origin": r.get("source") or "manual", "expires_at": r.get("expires_at")} for r in rules], c, now)


def delete(asns):
    return sum(policies.delete("asn", a, BLOCK, locked=False) for a in asns)


def expire(now=None):
    """Removes rules (and any other policy) whose time is up. Returns the removed ASN rules (asn, name, action)."""
    return [{"asn": int(p["value"]), "name": p["name"], "action": p["effect"]} for p in policies.expire(now)
            if p["source"] == "asn" and p["effect"] in BLOCK]


def apply_protection(asns, mode):
    """'exempt' (never blocked) removes the rules of these ASNs, 'captcha' (at most captcha) turns Block into Captcha.
    Returns the ASNs whose rule changed."""
    if mode == "exempt":
        return [a for a in asns if policies.delete("asn", a, BLOCK, locked=False)]
    return [a for a in asns if policies.set_effect("asn", a, ("ban",), "captcha", locked=False)]


def export():
    rules = map(_rule, policies.listing("asn", effects=BLOCK, locked=False))
    return sorted(({k: r[k] for k in ("asn", "name", "action", "note", "expires_at")} for r in rules), key=lambda r: r["asn"])
