"""Layering: each table is read and written by exactly one module, everything else goes through it."""
import re
import sqlite3
from pathlib import Path

from app import db

APP = Path(__file__).resolve().parents[1] / "app"
OWNERS = {  # table -> the only module (relative to app/) with SQL for it
    "asn_rules": "store/rules.py", "exemptions": "store/exemptions.py", "vpn_rules": "store/vpn.py",
    "protected": "store/protection.py", "watch_ips": "store/watch.py", "runs": "store/runs.py",
    "run_changes": "store/runs.py", "applied": "store/runs.py", "exempt_index": "store/runs.py",
    "attack_ips": "attackers.py", "routes": "routing.py", "sessions": "auth.py", "settings": "db.py", "cache": "db.py", "audit_log": "db.py",
}
SQL = re.compile(r"\b(?:FROM|INTO|UPDATE|JOIN|TABLE(?: IF NOT EXISTS)?|table_info\()\s*([a-z_]+)", re.I)


def test_each_table_has_one_owner():
    found = {}
    for f in APP.rglob("*.py"):
        rel = f.relative_to(APP).as_posix()
        for table in SQL.findall(f.read_text()):
            if table in OWNERS and rel != OWNERS[table] and rel != "db.py":  # db.py: schema and migrations
                found.setdefault(table, set()).add(rel)
    assert found == {}


def test_fresh_database_is_on_the_latest_schema():
    assert db.schema_version() == db.MIGRATIONS[-1][0]
    db.migrate()  # nothing left to do
    assert db.schema_version() == db.MIGRATIONS[-1][0]


def test_database_from_before_numbered_migrations(tmp_path, monkeypatch):
    """A 0.7.2 database: tables exist, user_version is 0, the newer columns are missing."""
    f = tmp_path / "old.db"
    con = sqlite3.connect(f)
    con.executescript(db.BASE_SCHEMA)
    con.execute("INSERT INTO asn_rules(asn,action,updated_at) VALUES(64500,'ban',0)")
    con.execute("INSERT INTO protected(kind,value) VALUES('asn','64501')")
    con.commit()
    con.close()
    monkeypatch.setattr(db, "DB_FILE", f)
    db._local.__dict__.clear()
    db.init()
    assert db.schema_version() == db.MIGRATIONS[-1][0]
    assert db.q1("SELECT expires_at FROM asn_rules")["expires_at"] is None
    assert db.q1("SELECT mode FROM protected")["mode"] == "exempt"
