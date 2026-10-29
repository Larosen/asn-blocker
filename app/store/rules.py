"""ASN rules: Block or Captcha per ASN, optionally with a lifetime."""
import time

from .. import db

COLUMNS = ("asn", "name", "action", "note", "expires_at")


def listing():
    """All rules with the ASN's type and country, for the rules table."""
    return db.q("SELECT a.*, n.class, n.cc FROM asn_rules a LEFT JOIN asn_names n USING(asn) ORDER BY a.asn")


def active(now=None):
    """{asn: rule} – an expired rule no longer counts, even before expire() has removed it."""
    now = time.time() if now is None else now
    return {r["asn"]: r for r in db.q("SELECT * FROM asn_rules WHERE expires_at IS NULL OR expires_at > ?", (now,))}


def actions():
    return {r["asn"]: r["action"] for r in db.q("SELECT asn, action FROM asn_rules")}


def asns():
    return {r["asn"] for r in db.q("SELECT asn FROM asn_rules")}


def count():
    return db.q1("SELECT count(*) n FROM asn_rules")["n"]


def upsert(rules, now=None, c=None):
    """rules: dicts with asn, name, action, note, expires_at (None = permanent). Replaces existing rules of these ASNs."""
    now = time.time() if now is None else now
    with db.tx_or(c) as c:
        c.executemany("INSERT INTO asn_rules(asn,name,action,note,updated_at,expires_at) VALUES(?,?,?,?,?,?) "
                      "ON CONFLICT(asn) DO UPDATE SET name=excluded.name, action=excluded.action, note=excluded.note, "
                      "updated_at=excluded.updated_at, expires_at=excluded.expires_at",
                      [(r["asn"], r.get("name") or "", r["action"], r.get("note") or "", now, r.get("expires_at")) for r in rules])
        db.bump_rev(c)


def delete(asns):
    with db.tx() as c:
        n = sum(c.execute("DELETE FROM asn_rules WHERE asn=?", (a,)).rowcount for a in asns)
        db.bump_rev(c)
    return n


def expire(now=None):
    """Removes rules whose time is up. Returns them (asn, name, action)."""
    now = time.time() if now is None else now
    with db.tx() as c:
        gone = [dict(r) for r in c.execute("SELECT asn, name, action FROM asn_rules WHERE expires_at <= ?", (now,))]
        if gone:
            c.executemany("DELETE FROM asn_rules WHERE asn=?", [(r["asn"],) for r in gone])
            db.bump_rev(c)
    return gone


def apply_protection(asns, mode):
    """'exempt' (never blocked) removes the rules of these ASNs, 'captcha' (at most captcha) turns Block into Captcha.
    Returns the ASNs whose rule changed."""
    with db.tx() as c:
        if mode == "exempt":
            changed = [a for a in asns if c.execute("DELETE FROM asn_rules WHERE asn=?", (a,)).rowcount]
        else:
            changed = [a for a in asns if c.execute("UPDATE asn_rules SET action='captcha' WHERE asn=? AND action='ban'", (a,)).rowcount]
        db.bump_rev(c)
    return changed


def export():
    return db.q("SELECT asn,name,action,note,expires_at FROM asn_rules ORDER BY asn")
