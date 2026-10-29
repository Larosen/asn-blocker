"""Maintained lists of networks as policies of source 'list' – today Spamhaus ASN-DROP."""
from . import policies

SPAMHAUS = "spamhaus-asndrop"


def spamhaus():
    """'ban' | 'captcha' | None (not used)"""
    p = policies.listing("list", SPAMHAUS)
    return p[0]["effect"] if p else None


def set_spamhaus(effect, c=None):
    if effect:
        policies.upsert([{"source": "list", "value": SPAMHAUS, "effect": effect, "name": "Spamhaus ASN-DROP"}], c)
    else:
        policies.delete("list", SPAMHAUS, c=c)
