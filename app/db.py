"""SQLite storage: rules, settings, runs, audit, caches. One file in DATA_DIR."""
import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DB_FILE = DATA_DIR / "asn-blocker.db"

# --- Schema and migrations ------------------------------------------------------------------------------
# The schema version is SQLite's user_version. Each migration runs once, in its own transaction, in order.
# Databases from before 0.7.6 have version 0: their tables already exist, so every migration here is idempotent.

BASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS asn_rules (
  asn INTEGER PRIMARY KEY, name TEXT NOT NULL DEFAULT '', action TEXT NOT NULL CHECK (action IN ('ban','captcha')),
  note TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT 'manual', updated_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS vpn_rules (provider TEXT NOT NULL, country TEXT NOT NULL, PRIMARY KEY (provider, country));
CREATE TABLE IF NOT EXISTS exemptions (
  kind TEXT NOT NULL CHECK (kind IN ('asn','cidr')), value TEXT NOT NULL, note TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (kind, value));
-- Self-protection: IPs/ASNs that must never be blocked
CREATE TABLE IF NOT EXISTS protected (kind TEXT NOT NULL CHECK (kind IN ('asn','ip')), value TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '', created REAL NOT NULL DEFAULT 0, PRIMARY KEY (kind, value));
CREATE TABLE IF NOT EXISTS watch_ips (ip TEXT PRIMARY KEY, note TEXT NOT NULL DEFAULT '', last_status TEXT);
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, status TEXT NOT NULL, triggered_by TEXT NOT NULL,
  started_at REAL NOT NULL, finished_at REAL, summary TEXT, log TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS run_changes (run_id INTEGER NOT NULL, op TEXT NOT NULL, type TEXT NOT NULL, value TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS run_changes_run ON run_changes(run_id);
-- last applied target state (for IP checker, downloads, lockout warning)
CREATE TABLE IF NOT EXISTS applied (type TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (type, value));
-- exemptions with their origin from the last run
CREATE TABLE IF NOT EXISTS exempt_index (cidr TEXT NOT NULL, label TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, user TEXT NOT NULL,
  action TEXT NOT NULL, detail TEXT);
CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, value TEXT NOT NULL, fetched_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS asn_names (asn INTEGER PRIMARY KEY, name TEXT NOT NULL, class TEXT, cc TEXT);
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user TEXT NOT NULL, expires REAL NOT NULL);
-- Attackers seen by CrowdSec's own detections, one row per IP and day (CrowdSec itself keeps alerts ~7 days)
CREATE TABLE IF NOT EXISTS attack_ips (day TEXT NOT NULL, ip TEXT NOT NULL, asn INTEGER, as_name TEXT NOT NULL DEFAULT '',
  alerts INTEGER NOT NULL, scenarios TEXT NOT NULL DEFAULT '[]', last_seen REAL NOT NULL, PRIMARY KEY (day, ip));
CREATE INDEX IF NOT EXISTS attack_ips_asn ON attack_ips(asn, day);
"""


def _has_column(c, table, column):
    return column in {r[1] for r in c.execute(f"PRAGMA table_info({table})")}


def _m2_protection_mode(c):
    # mode (ASNs only): 'exempt' = never blocked, 'captcha' = may be behind a captcha but never banned
    if not _has_column(c, "protected", "mode"):
        c.execute("ALTER TABLE protected ADD COLUMN mode TEXT NOT NULL DEFAULT 'exempt' CHECK (mode IN ('exempt','captcha'))")


def _m3_rule_lifetime(c):
    # NULL = permanent; expired rules are removed by the scheduler
    if not _has_column(c, "asn_rules", "expires_at"):
        c.execute("ALTER TABLE asn_rules ADD COLUMN expires_at REAL")


MIGRATIONS = [  # (version, description, SQL script or function(connection))
    (1, "base schema", BASE_SCHEMA),
    (2, "self-protection mode per ASN", _m2_protection_mode),
    (3, "lifetime of ASN rules", _m3_rule_lifetime),
]


def schema_version(c=None):
    return (c or conn()).execute("PRAGMA user_version").fetchone()[0]


def migrate():
    c = conn()
    for version, _, step in MIGRATIONS:
        if version <= schema_version(c):
            continue
        c.execute("BEGIN IMMEDIATE")
        try:
            if version <= schema_version(c):  # another process (e.g. the CLI) migrated meanwhile
                c.execute("ROLLBACK")
                continue
            if isinstance(step, str):  # plain statements separated by ';' (no ';' inside comments or strings)
                for stmt in filter(str.strip, step.split(";")):
                    c.execute(stmt)
            else:
                step(c)
            c.execute(f"PRAGMA user_version = {int(version)}")
            c.execute("COMMIT")
        except BaseException:
            c.execute("ROLLBACK")
            raise


_local = threading.local()
_write_lock = threading.RLock()


def conn() -> sqlite3.Connection:
    c = getattr(_local, "conn", None)
    if c is None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        c = sqlite3.connect(DB_FILE, timeout=30, isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA foreign_keys=ON")
        _local.conn = c
    return c


@contextmanager
def tx():
    """Write transaction; serialized via a process lock."""
    with _write_lock:
        c = conn()
        c.execute("BEGIN IMMEDIATE")
        try:
            yield c
            c.execute("COMMIT")
        except BaseException:
            c.execute("ROLLBACK")
            raise


@contextmanager
def tx_or(c=None):
    """The given transaction, or a new one: lets store functions join a larger transaction (e.g. an import)."""
    if c is not None:
        yield c
    else:
        with tx() as c:
            yield c


def q(sql, args=()):
    return [dict(r) for r in conn().execute(sql, args).fetchall()]


def q1(sql, args=()):
    r = conn().execute(sql, args).fetchone()
    return dict(r) if r else None


def init():
    os.umask(0o077)  # also covers the -wal/-shm files, which contain the same secrets
    with _write_lock:
        migrate()
    try:
        os.chmod(DB_FILE, 0o600)
    except OSError:
        pass
    _migrate_prototype()


def prune():
    """Bounded growth: drop stale cache entries (IP lookups etc.), keep the newest 20,000 audit entries and 180 days
    of attacker history."""
    with tx() as c:
        c.execute("DELETE FROM cache WHERE fetched_at < ?", (time.time() - 7 * 86400,))
        c.execute("DELETE FROM audit_log WHERE id <= (SELECT max(id) FROM audit_log) - 20000")
        c.execute("DELETE FROM attack_ips WHERE day < date('now', '-180 days')")


# --- Settings --------------------------------------------------------------------

DEFAULTS = {
    "auth_mode": None,               # 'proxy' | 'local'
    "auth_user_header": "Remote-User",
    "trusted_proxies": [],           # CIDRs from which proxy headers are accepted
    "local_user": "admin",
    "local_password_hash": None,
    "crowdsec_mode": None,           # 'lapi' | 'docker'
    "lapi_url": "http://crowdsec:8080",
    "lapi_machine_id": "",
    "lapi_password": "",
    "docker_container": "crowdsec",
    "interval_hours": 48,
    "decision_hours": 168,           # 7 days; decisions are renewed before they expire
    "include_ipv6": False,
    "vpn_modes": {},                 # provider -> 'exact' | 'net'
    "sanity_percent": 30,
    "notify_url": "",
    "notify_format": "ntfy",         # 'ntfy' | 'gotify' | 'webhook'
    "notify_token": "",              # optional access token, sent as header (never returned to the browser)
    "public_url": None,              # address of the web UI, for links in notifications
    "spamhaus_asndrop": None,        # None = off, otherwise 'ban' | 'captcha'
    "config_rev": 0,
    "applied_rev": 0,
    "attackers_last_id": 0,          # newest CrowdSec alert already counted
    "attackers_updated": None,       # time of the last successful collection
    "attackers_error": None,         # why the last collection failed, if it did
    "attackers_notified": {},        # ASN -> time of the last "keeps attacking" notification
}


def get(key):
    r = q1("SELECT value FROM settings WHERE key=?", (key,))
    return json.loads(r["value"]) if r else DEFAULTS.get(key)


def put(key, value, c=None):
    (c or conn()).execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                          (key, json.dumps(value)))


def bump_rev(c):
    """Rules changed -> UI shows 'not applied'."""
    put("config_rev", (get("config_rev") or 0) + 1, c)


def audit_log(limit=200):
    return q("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))


def audit(user, action, detail=None):
    with tx() as c:
        c.execute("INSERT INTO audit_log(ts,user,action,detail) VALUES(?,?,?,?)",
                  (time.time(), user, action, json.dumps(detail, ensure_ascii=False) if detail is not None else None))


# --- Cache -----------------------------------------------------------------------------

def cache_get(key, max_age):
    r = q1("SELECT value, fetched_at FROM cache WHERE key=?", (key,))
    if r and time.time() - r["fetched_at"] < max_age:
        return json.loads(r["value"])
    return None


def cache_put(key, value):
    with tx() as c:
        c.execute("INSERT OR REPLACE INTO cache(key,value,fetched_at) VALUES(?,?,?)", (key, json.dumps(value), time.time()))


# --- Migration from the prototype (config.json) ------------------------------------------------

def _migrate_prototype():
    old = DATA_DIR / "config.json"
    if not old.exists() or get("migrated_v1"):
        return
    try:
        cfg = json.loads(old.read_text())
    except ValueError:
        return
    now = time.time()
    with tx() as c:
        for a in cfg.get("asns", []):
            c.execute("INSERT OR IGNORE INTO asn_rules(asn,name,action,note,updated_at) VALUES(?,?,?,?,?)",
                      (a["asn"], a.get("name", ""), a["action"], a.get("note", ""), now))
        for v in cfg.get("vpn_whitelist", []):
            c.execute("INSERT OR IGNORE INTO vpn_rules VALUES(?,?)", (v["provider"], v["country"]))
        for asn in cfg.get("exempt_asns", []):
            c.execute("INSERT OR IGNORE INTO exemptions(kind,value) VALUES('asn',?)", (str(asn),))
        for cidr in cfg.get("manual_exempt", []):
            c.execute("INSERT OR IGNORE INTO exemptions(kind,value) VALUES('cidr',?)", (cidr,))
        put("include_ipv6", bool(cfg.get("include_ipv6")), c)
        if cfg.get("widen_vpn_ips"):
            put("vpn_modes", {p: "net" for p in ("nordvpn", "mullvad", "surfshark")}, c)
        put("migrated_v1", True, c)
        bump_rev(c)
