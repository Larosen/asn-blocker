"""All rules in one table. A policy says what a source of networks gets:

  source  asn (an AS number) | cidr (a network) | ip (one address) | vpn ('provider:CC', the servers of a VPN provider
          in a country) | list (a maintained list of networks, e.g. 'spamhaus-asndrop')
  effect  ban | captcha | cap (at most captcha: never banned) | allow (never blocked)
  locked  self-protection: contradicting rules are rejected, and a run fails rather than run without it
  expires_at  optional lifetime; an expired policy no longer counts and is removed by the scheduler

A source has at most one policy per kind (ban/captcha share one, the block policy) and per locked state, so an ASN can
be blocked and partly exempted, or exempted and also protected – as before, but in one model. Precedence when policies
overlap is decided per network by the evaluator (policy.py): allow > cap > ban > captcha.
"""
import time

from .. import db

SOURCES = ("asn", "cidr", "ip", "vpn", "list")
EFFECTS = ("ban", "captcha", "cap", "allow")
RANK = {"allow": 3, "cap": 2, "ban": 1, "captcha": 0}
COLUMNS = "id, source, value, effect, locked, name, note, origin, created, updated, expires_at"


def group(effect):
    """Policies of one source that replace each other: ban and captcha are the same kind (block)."""
    return "block" if effect in ("ban", "captcha") else effect


def _where(source=None, value=None, effects=None, locked=None, active=False):
    sql, args = [], []
    if source is not None:
        sql.append("source=?")
        args.append(source)
    if value is not None:
        sql.append("value=?")
        args.append(str(value))
    if effects is not None:
        sql.append(f"effect IN ({','.join('?' * len(effects))})")
        args += list(effects)
    if locked is not None:
        sql.append("locked=?")
        args.append(int(bool(locked)))
    if active:
        sql.append("(expires_at IS NULL OR expires_at > ?)")
        args.append(time.time())
    return (" WHERE " + " AND ".join(sql)) if sql else "", args


def listing(source=None, value=None, effects=None, locked=None, active=False, order="source, value"):
    where, args = _where(source, value, effects, locked, active)
    order = order if order in ("source, value", "id") else "source, value"
    rows = db.q(f"SELECT {COLUMNS} FROM policies{where} ORDER BY {order}", args)  # noqa: S608 - fixed fragments
    for r in rows:
        r["locked"] = bool(r["locked"])
    return rows


def count(source=None, effects=None, locked=None):
    where, args = _where(source, None, effects, locked)
    return db.q1(f"SELECT count(*) n FROM policies{where}", args)["n"]  # noqa: S608


def upsert(rows, c=None, now=None):
    """rows: dicts with source, value, effect and optionally locked, name, note, origin, expires_at. A policy replaces
    the existing one of the same source, kind and locked state (keeping its creation time)."""
    now = time.time() if now is None else now
    with db.tx_or(c) as c:
        for r in rows:
            if r["source"] not in SOURCES or r["effect"] not in EFFECTS:
                raise ValueError(f"invalid policy {r['source']}/{r['effect']}")
            locked = int(bool(r.get("locked")))
            effects = ("ban", "captcha") if group(r["effect"]) == "block" else (r["effect"],)
            marks = ",".join("?" * len(effects))
            old = c.execute(f"SELECT id, created FROM policies WHERE source=? AND value=? AND locked=? AND effect IN ({marks})",  # noqa: S608
                            (r["source"], str(r["value"]), locked, *effects)).fetchone()
            values = (r["effect"], r.get("name") or "", r.get("note") or "", r.get("origin") or "manual", now, r.get("expires_at"))
            if old:
                c.execute("UPDATE policies SET effect=?, name=?, note=?, origin=?, updated=?, expires_at=? WHERE id=?", (*values, old["id"]))
            else:
                c.execute("INSERT INTO policies(source, value, locked, effect, name, note, origin, updated, expires_at, created) "
                          "VALUES(?,?,?,?,?,?,?,?,?,?)", (r["source"], str(r["value"]), locked, *values, now))
        db.bump_rev(c)


def delete(source, value, effects=None, locked=None, c=None):
    """Removes the matching policies; returns how many."""
    where, args = _where(source, value, effects, locked)
    with db.tx_or(c) as c:
        n = c.execute(f"DELETE FROM policies{where}", args).rowcount  # noqa: S608
        if n:
            db.bump_rev(c)
    return n


def set_effect(source, value, old_effects, effect, locked=None):
    """Changes the effect of matching policies (e.g. ban -> captcha); returns how many changed."""
    where, args = _where(source, value, old_effects, locked)
    with db.tx() as c:
        n = c.execute(f"UPDATE policies SET effect=?, updated=?{where.replace(' WHERE ', ' WHERE ', 1)}",  # noqa: S608
                      [effect, time.time(), *args]).rowcount
        if n:
            db.bump_rev(c)
    return n


def expire(now=None):
    """Removes policies whose time is up. Returns them."""
    now = time.time() if now is None else now
    with db.tx() as c:
        gone = [dict(r) for r in c.execute(f"SELECT {COLUMNS} FROM policies WHERE expires_at <= ?", (now,))]  # noqa: S608
        if gone:
            c.executemany("DELETE FROM policies WHERE id=?", [(r["id"],) for r in gone])
            db.bump_rev(c)
    return gone
