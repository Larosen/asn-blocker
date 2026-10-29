"""Local copy of the global routing table: which prefixes every ASN announces, and which ASN announces an IP.

One download a day (bgp.tools table.jsonl, ~80 MB, ~1.5 million prefixes) replaces one RIPEstat request per ASN and
per IP: runs take seconds, every ASN comes from the same snapshot, and lookups need no network. If the table is
missing or older than MAX_AGE, sources.py falls back to RIPEstat as before.

The table lives in its own SQLite file (routes.db), built next to it and swapped in with one atomic rename: the main
database stays small, a load never holds its write lock, and readers switch to the new file on their next query.
"""
import ipaddress
import json
import logging
import os
import sqlite3
import threading
import time
from pathlib import Path

from . import db

log = logging.getLogger("asn_blocker.routing")

URL = "https://bgp.tools/table.jsonl"
REFRESH = 24 * 3600        # download once a day …
MAX_AGE = 3 * 86400        # … and stop using a table that could not be refreshed for this long
MAX_BYTES = 256 * 2**20    # the table is ~80 MB today
MIN_PREFIXES = {4: 500_000, 6: 100_000}  # fewer means a truncated or broken download (today ~1.2 M and ~0.3 M)
MIN_PEERS = 5              # prefixes seen by fewer of bgp.tools' peers are leaks or noise
MIN_PREFIXLEN = {4: 8, 6: 16}

_local = threading.local()
_refresh_lock = threading.Lock()


class RoutingError(RuntimeError):
    pass


def path():
    return Path(db.DATA_DIR) / "routes.db"


def status():
    """{updated, prefixes, source, error} – for the UI."""
    return {"updated": db.get("routes_updated"), "prefixes": db.get("routes_count") or 0, "source": URL,
            "error": db.get("routes_error"), "active": fresh(), "refreshing": _refresh_lock.locked()}


def fresh():
    updated = db.get("routes_updated")
    return bool(updated and time.time() - updated < MAX_AGE and db.get("routes_count") and path().exists())


def due():
    updated = db.get("routes_updated") or 0
    tried = db.get("routes_tried") or 0
    return time.time() - updated > REFRESH and time.time() - tried > 3600  # after a failure: retry hourly


def _conn():
    """Read-only connection to the current file; reopened when a refresh has replaced it."""
    p = path()
    try:
        ident = p.stat().st_ino, p.stat().st_mtime_ns
    except OSError:
        return None
    c = getattr(_local, "conn", None)
    if c is None or _local.ident != ident or _local.path != p:
        if c is not None:
            c.close()
        c = sqlite3.connect(f"file:{p}?mode=ro", uri=True, check_same_thread=False)
        _local.conn, _local.ident, _local.path = c, ident, p
    return c


def prefixes(asn):
    """Announced prefixes of an ASN, or None if there is no usable table (then RIPEstat is asked)."""
    c = _conn() if fresh() else None
    if c is None:
        return None
    return sorted(r[0] for r in c.execute("SELECT prefix FROM routes WHERE asn=?", (int(asn),)))


def lookup(ip):
    """{'asns': [...], 'prefix': most specific announced prefix} for an IP, or None without a usable table."""
    c = _conn() if fresh() else None
    if c is None:
        return None
    a = ipaddress.ip_address(ip)
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    cands = [str(ipaddress.ip_network(f"{a}/{n}", strict=False)) for n in range(a.max_prefixlen, MIN_PREFIXLEN[a.version] - 1, -1)]
    rows = c.execute(f"SELECT prefix, asn FROM routes WHERE prefix IN ({','.join('?' * len(cands))})", cands).fetchall()  # noqa: S608
    if not rows:
        return {"asns": [], "prefix": ""}
    best = max(rows, key=lambda r: int(r[0].rsplit("/", 1)[1]))[0]
    return {"asns": sorted({asn for p, asn in rows if p == best}), "prefix": best}


def _rows(source, counts):
    """(prefix, asn) of every plausible line; counts per IP version."""
    with open(source, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                o = json.loads(line)
                net = ipaddress.ip_network(str(o["CIDR"]), strict=True)
                asn, peers = o["ASN"], o.get("Hits", MIN_PEERS)
            except (ValueError, KeyError, TypeError, AttributeError):
                continue
            if type(asn) is not int or not 0 < asn < 2**32 or net.prefixlen < MIN_PREFIXLEN[net.version] \
                    or not net.is_global or (isinstance(peers, int) and peers < MIN_PEERS):
                continue
            counts[net.version] += 1
            yield str(net), asn


def refresh(download=None):
    """Downloads and loads a new table; the old one stays in use until the new one is complete and plausible.
    download(path): writes table.jsonl to path (default: HTTPS from bgp.tools). Returns the number of prefixes."""
    from . import sources

    if not _refresh_lock.acquire(blocking=False):
        raise RoutingError("a refresh is already in progress")
    db.put("routes_tried", time.time())
    raw, new = path().with_suffix(".jsonl.part"), path().with_suffix(".db.new")
    try:
        (download or (lambda p: sources.download(URL, p, timeout=600, max_bytes=MAX_BYTES)))(raw)
        new.unlink(missing_ok=True)
        counts = {4: 0, 6: 0}
        c = sqlite3.connect(new)
        try:
            c.execute("PRAGMA journal_mode=OFF")  # a new file: if anything fails it is simply thrown away
            c.execute("PRAGMA synchronous=OFF")
            c.execute("CREATE TABLE routes (prefix TEXT NOT NULL, asn INTEGER NOT NULL, PRIMARY KEY (prefix, asn)) WITHOUT ROWID")
            c.executemany("INSERT OR IGNORE INTO routes VALUES(?,?)", _rows(raw, counts))
            c.execute("CREATE INDEX routes_asn ON routes(asn)")
            c.commit()
        finally:
            c.close()
        if any(counts[v] < MIN_PREFIXES[v] for v in (4, 6)):
            raise RoutingError(f"implausible routing table ({counts[4]:,} IPv4 and {counts[6]:,} IPv6 prefixes)")
        os.chmod(new, 0o600)
        os.replace(new, path())  # atomic: readers see the old or the new file, never a half-written one
        with db.tx() as tx:
            db.put("routes_updated", time.time(), tx)
            db.put("routes_count", counts[4] + counts[6], tx)
            db.put("routes_error", None, tx)
        log.info("Routing table loaded: %d IPv4 and %d IPv6 prefixes", counts[4], counts[6])
        return counts[4] + counts[6]
    except (RoutingError, sources.SourceError, OSError, sqlite3.Error) as e:
        db.put("routes_error", sources.clean(e, 300))
        raise RoutingError(str(e)) from e
    finally:
        for f in (raw, new):
            f.unlink(missing_ok=True)
        _refresh_lock.release()
