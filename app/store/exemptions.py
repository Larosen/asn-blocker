"""Exemptions: networks (CIDR) and whole ASNs that are cut out of every blocked range."""
from .. import db


def listing():
    return db.q("SELECT * FROM exemptions ORDER BY kind, value")


def asns():
    return [int(r["value"]) for r in db.q("SELECT value FROM exemptions WHERE kind='asn'")]


def networks():
    """[(cidr, note)]"""
    return [(r["value"], r["note"]) for r in db.q("SELECT value, note FROM exemptions WHERE kind='cidr'")]


def count():
    return db.q1("SELECT count(*) n FROM exemptions")["n"]


def add(rows, c=None):
    """rows: [(kind, value, note)] – value already validated and normalised."""
    with db.tx_or(c) as c:
        c.executemany("INSERT OR REPLACE INTO exemptions VALUES(?,?,?)", rows)
        db.bump_rev(c)


def delete(kind, value):
    with db.tx() as c:
        c.execute("DELETE FROM exemptions WHERE kind=? AND value=?", (kind, value))
        db.bump_rev(c)


def export():
    return db.q("SELECT kind,value,note FROM exemptions")
