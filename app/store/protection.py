"""Self-protection: IPs that are never blocked, and ASNs that are never blocked ('exempt') or at most get a
captcha ('captcha') – the locked policies."""
from . import policies

ASN_MODES = ("exempt", "captcha")  # never blocked | at most behind a captcha (never banned)
_EFFECT = {"exempt": "allow", "captcha": "cap"}


def listing():
    return [{"kind": p["source"], "value": p["value"], "note": p["note"], "created": p["created"],
             "mode": "captcha" if p["effect"] == "cap" else "exempt"}
            for k in ("asn", "ip") for p in policies.listing(k, locked=True)]


def ips():
    """[(ip, note)]"""
    return [(p["value"], p["note"]) for p in policies.listing("ip", effects=("allow",), locked=True)]


def asns(mode=None):
    """Protected ASNs, optionally only those with the given mode."""
    effects = (_EFFECT[mode],) if mode else ("allow", "cap")
    return {int(p["value"]) for p in policies.listing("asn", effects=effects, locked=True)}


def add(kind, value, note="", mode="exempt"):
    effect = _EFFECT[mode] if kind == "asn" else "allow"
    policies.delete(kind, value, locked=True)  # one protection per IP or ASN, whichever mode
    policies.upsert([{"source": kind, "value": value, "effect": effect, "locked": True, "note": note}])


def set_mode(asn, mode):
    if mode not in ASN_MODES:
        raise ValueError(mode)
    current = policies.listing("asn", str(asn), locked=True)
    if not current:
        return False
    if current[0]["effect"] != _EFFECT[mode]:
        policies.delete("asn", str(asn), locked=True)
        policies.upsert([{"source": "asn", "value": str(asn), "effect": _EFFECT[mode], "locked": True, "note": current[0]["note"]}])
    return True


def delete(kind, value):
    policies.delete(kind, value, locked=True)
