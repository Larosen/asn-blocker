"""Self-protection: IPs that are never blocked, and ASNs that are never blocked ('exempt') or at most get a
captcha ('captcha')."""
import time

from .. import db

ASN_MODES = ("exempt", "captcha")  # never blocked | at most behind a captcha (never banned)


def listing():
    return db.q("SELECT kind, value, note, created, mode FROM protected ORDER BY kind, value")


def ips():
    """[(ip, note)]"""
    return [(r["value"], r["note"]) for r in db.q("SELECT value, note FROM protected WHERE kind='ip'")]


def asns(mode=None):
    """Protected ASNs, optionally only those with the given mode."""
    rows = db.q("SELECT value, mode FROM protected WHERE kind='asn'")
    return {int(r["value"]) for r in rows if mode is None or r["mode"] == mode}


def add(kind, value, note="", mode="exempt"):
    with db.tx() as c:
        c.execute("INSERT OR REPLACE INTO protected(kind,value,note,created,mode) VALUES(?,?,?,?,?)",
                  (kind, value, note, time.time(), mode if kind == "asn" else "exempt"))
        db.bump_rev(c)


def set_mode(asn, mode):
    if mode not in ASN_MODES:
        raise ValueError(mode)
    with db.tx() as c:
        n = c.execute("UPDATE protected SET mode=? WHERE kind='asn' AND value=?", (mode, str(asn))).rowcount
        if n:
            db.bump_rev(c)
    return bool(n)


def delete(kind, value):
    with db.tx() as c:
        c.execute("DELETE FROM protected WHERE kind=? AND value=?", (kind, value))
        db.bump_rev(c)
