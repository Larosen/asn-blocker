"""Exemptions: networks (CIDR) and whole ASNs that are cut out of every blocked range – unlocked allow policies."""
from . import policies

KINDS = ("asn", "cidr")


def _rows(kind=None):
    return [p for k in ([kind] if kind else KINDS) for p in policies.listing(k, effects=("allow",), locked=False)]


def listing():
    return [{"kind": p["source"], "value": p["value"], "note": p["note"]} for p in _rows()]


def asns():
    return [int(p["value"]) for p in _rows("asn")]


def networks():
    """[(cidr, note)]"""
    return [(p["value"], p["note"]) for p in _rows("cidr")]


def count():
    return sum(policies.count(k, ("allow",), False) for k in KINDS)


def add(rows, c=None):
    """rows: [(kind, value, note)] – value already validated and normalised."""
    policies.upsert([{"source": k, "value": v, "effect": "allow", "note": n} for k, v, n in rows], c)


def delete(kind, value):
    if kind in KINDS:
        policies.delete(kind, value, ("allow",), locked=False)


def export():
    return listing()
