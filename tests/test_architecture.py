"""Layering: each table is read and written by exactly one module, everything else goes through it."""
import re
import sqlite3
from pathlib import Path

from app import db
from app.store import protection, rules

APP = Path(__file__).resolve().parents[1] / "app"
OWNERS = {  # table -> the only module (relative to app/) with SQL for it
    "policies": "store/policies.py", "watch_ips": "store/watch.py", "runs": "store/runs.py",
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
    assert rules.listing()[0] | {"updated_at": 0} == {"asn": 64500, "name": "", "action": "ban", "note": "", "source": "manual",
                                                      "updated_at": 0, "expires_at": None, "class": None, "cc": None}
    assert protection.asns("exempt") == {64501}   # protection from before the modes: never blocked
    assert not list(f.parent.glob("old.db.schema-*"))  # version 0: nothing to keep a copy of


def test_migration_to_policies_keeps_every_rule_and_a_backup(tmp_path, monkeypatch):
    """A 0.7.7 database (schema version 3): every kind of rule ends up as a policy, Spamhaus included."""
    f = tmp_path / "v3.db"
    con = sqlite3.connect(f)
    con.executescript(db.BASE_SCHEMA)
    con.execute("ALTER TABLE protected ADD COLUMN mode TEXT NOT NULL DEFAULT 'exempt'")
    con.execute("ALTER TABLE asn_rules ADD COLUMN expires_at REAL")
    con.executescript("""
        INSERT INTO asn_rules(asn,name,action,note,source,updated_at,expires_at) VALUES(64500,'A','ban','n','manual',5,9e9),
          (64501,'B','captcha','','import',6,NULL);
        INSERT INTO exemptions VALUES('asn','64502','cdn'),('cidr','203.0.113.0/24','partner');
        INSERT INTO vpn_rules VALUES('nordvpn','DE'),('mullvad','SE');
        INSERT INTO protected(kind,value,note,created,mode) VALUES('ip','198.51.100.42','home',7,'exempt'),
          ('asn','64503','isp',8,'captcha'),('asn','64502','also exempt',9,'exempt');
        INSERT INTO settings VALUES('spamhaus_asndrop','"captcha"'),('vpn_modes','{"nordvpn": "net"}');
        PRAGMA user_version = 3;""")
    con.commit()
    con.close()
    monkeypatch.setattr(db, "DB_FILE", f)
    db._local.__dict__.clear()
    db.init()
    from app.store import exemptions, lists, vpn
    assert rules.actions() == {64500: "ban", 64501: "captcha"}
    assert rules.listing()[0]["expires_at"] == 9e9 and rules.listing()[1]["source"] == "import"
    assert sorted((e["kind"], e["value"], e["note"]) for e in exemptions.listing()) == \
        [("asn", "64502", "cdn"), ("cidr", "203.0.113.0/24", "partner")]
    assert vpn.selections() == {"mullvad": ["SE"], "nordvpn": ["DE"]} and vpn.modes() == {"nordvpn": "net"}
    assert protection.asns("captcha") == {64503} and protection.asns("exempt") == {64502}   # exempt and protected: both kept
    assert protection.ips() == [("198.51.100.42", "home")]
    assert lists.spamhaus() == "captcha" and db.q1("SELECT 1 x FROM settings WHERE key='spamhaus_asndrop'") is None
    assert (tmp_path / "v3.db.schema-v3.bak").exists()   # the database as it was, in case the update has to be undone
    assert {r["name"] for r in db.q("SELECT name FROM sqlite_master WHERE type='table'")} >= {"policies"} \
        and not {r["name"] for r in db.q("SELECT name FROM sqlite_master WHERE name IN ('asn_rules','exemptions','vpn_rules','protected')")}
