"""Watched IPs: checked after every run, with a notification if one would be affected."""
from .. import db


def listing():
    return db.q("SELECT * FROM watch_ips ORDER BY ip")


def ips():
    return [r["ip"] for r in db.q("SELECT ip FROM watch_ips")]


def count():
    return db.q1("SELECT count(*) n FROM watch_ips")["n"]


def add(rows, c=None):
    """rows: [(ip, note)]"""
    with db.tx_or(c) as c:
        c.executemany("INSERT OR REPLACE INTO watch_ips(ip,note) VALUES(?,?)", rows)


def set_status(status, c=None):
    """status: {ip: 'ban' | 'captcha' | None} from the last applied run."""
    with db.tx_or(c) as c:
        c.executemany("UPDATE watch_ips SET last_status=? WHERE ip=?", [(s or "clear", ip) for ip, s in status.items()])


def delete(ip):
    with db.tx() as c:
        c.execute("DELETE FROM watch_ips WHERE ip=?", (ip,))


def export():
    return db.q("SELECT ip,note FROM watch_ips")
