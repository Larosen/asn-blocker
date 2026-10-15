import time

import pytest

from app import crowdsec, db, engine, sources
from tests.conftest import FakeBackend

PREFIXES = {1: ["10.0.0.0/16"], 2: ["10.0.0.0/8", "2001:db8::/32"], 3: ["10.0.7.0/24"]}


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setattr(sources, "asn_prefixes", lambda a, use_cache=True: PREFIXES[a])

    class P(sources.Provider):
        id, name = "nordvpn", "NordVPN"

        def fetch(self):
            return [("DE", "Germany", "10.0.5.9"), ("NO", "Norway", "10.0.6.9")]

    monkeypatch.setitem(sources.PROVIDERS, "nordvpn", P())
    monkeypatch.setattr(sources, "_public_ip", lambda v: v)  # Testnetze sind nicht "global"
    be = FakeBackend()
    monkeypatch.setattr(crowdsec, "backend", lambda: be)
    monkeypatch.setattr(engine.notify, "send", lambda *a, **k: None)
    db.put("crowdsec_mode", "lapi")
    with db.tx() as c:
        c.execute("INSERT INTO asn_rules(asn,name,action,updated_at) VALUES(1,'a','ban',0),(2,'b','captcha',0)")
        c.execute("INSERT INTO vpn_rules VALUES('nordvpn','DE')")
        c.execute("INSERT INTO exemptions(kind,value) VALUES('asn','3'),('cidr','10.1.0.0/16')")
    return be


def last_run():
    return db.q1("SELECT * FROM runs ORDER BY id DESC LIMIT 1")


def applied(t):
    return {r["value"] for r in db.q("SELECT value FROM applied WHERE type=?", (t,))}


def test_apply_carves_exemptions_and_separates_types(env):
    engine.run("apply", "test")
    assert last_run()["status"] == "ok", last_run()["log"]
    ban, cap = applied("ban"), applied("captcha")
    assert "10.0.5.9" not in str(ban)
    assert engine.status_of("10.0.5.9", {"ban": list(ban)}) is None       # VPN exakt ausgenommen
    assert engine.status_of("10.0.5.10", {"ban": list(ban)}) == "ban"     # Nachbar-IP bleibt gesperrt
    assert engine.status_of("10.0.7.1", {"ban": list(ban)}) is None       # Ausnahme-ASN
    assert engine.status_of("10.1.2.3", {"captcha": list(cap)}) is None   # manuelle Ausnahme
    assert engine.status_of("10.0.1.1", {"captcha": list(cap)}) is None   # Captcha nicht unter Ban
    assert engine.status_of("10.200.0.1", {"captcha": list(cap)}) == "captcha"
    assert not any(":" in v for v in ban | cap)                            # IPv6 aus
    assert {d["value"] for d in env.decisions if d["type"] == "ban"} == ban


def test_second_run_is_noop_then_diff(env):
    engine.run("apply", "test")
    env.calls.clear()
    engine.run("apply", "test")
    assert env.calls == [], "unveränderter Stand darf nichts schreiben"
    with db.tx() as c:
        c.execute("DELETE FROM exemptions WHERE kind='asn'")
    db.put("sanity_percent", 100)
    engine.run("apply", "test")
    s = __import__("json").loads(last_run()["summary"])
    assert s["ban_added"] >= 1 and s["ban_removed"] >= 1
    assert engine.status_of("10.0.7.1", {"ban": list(applied("ban"))}) == "ban"


def test_add_happens_before_delete(env):
    engine.run("apply", "test")
    with db.tx() as c:
        c.execute("DELETE FROM vpn_rules")
    db.put("sanity_percent", 100)
    env.calls.clear()
    engine.run("apply", "test")
    kinds = [c[0] for c in env.calls]
    assert kinds.index("add") < kinds.index("delete")


def test_expiring_decisions_are_refreshed(env):
    engine.run("apply", "test")
    for d in env.decisions:
        d["until"] = time.time() + 3600  # laeuft vor dem naechsten Lauf ab
    engine.run("apply", "test")
    assert all(d["until"] > time.time() + 86400 for d in env.decisions)
    assert len(env.decisions) == len(applied("ban")) + len(applied("captcha"))


def test_source_error_leaves_crowdsec_untouched(env, monkeypatch):
    engine.run("apply", "test")
    before = list(env.decisions)

    def boom(a, use_cache=True):
        raise sources.SourceError("RIPE down")

    monkeypatch.setattr(sources, "asn_prefixes", boom)
    engine.run("apply", "test")
    assert last_run()["status"] == "failed"
    assert env.decisions == before


def test_sanity_blocks_large_change(env):
    engine.run("apply", "test")
    before = list(env.decisions)
    with db.tx() as c:
        c.execute("DELETE FROM asn_rules WHERE asn=2")
    engine.run("apply", "test")
    assert last_run()["status"] == "blocked"
    assert env.decisions == before
    engine.run("apply", "test", force=True)
    assert last_run()["status"] == "ok"
    assert applied("captcha") == set()


def test_watch_ip_hit(env):
    with db.tx() as c:
        c.execute("INSERT INTO watch_ips(ip) VALUES('10.0.9.9'),('10.0.5.9')")
    engine.run("apply", "test")
    st = {r["ip"]: r["last_status"] for r in db.q("SELECT * FROM watch_ips")}
    assert st == {"10.0.9.9": "ban", "10.0.5.9": "frei"}


def test_plan_does_not_write(env):
    engine.run("plan", "test")
    assert last_run()["status"] == "ok"
    assert env.decisions == [] and applied("ban") == set()


def test_diff_removes_duplicates():
    cur = [{"id": 1, "value": "a", "until": 9e12}, {"id": 2, "value": "a", "until": 8e12}, {"id": 3, "value": "b", "until": 9e12}]
    add, delete, refresh = engine.diff(["a"], cur, time.time())
    assert add == [] and sorted(delete) == [2, 3] and refresh == 0


def test_go_duration():
    assert crowdsec.go_duration("167h59m58.5s") == pytest.approx(167 * 3600 + 59 * 60 + 58.5)
    assert crowdsec.go_duration("-1s") == -1


def test_unreachable_lapi_raises_crowdsec_error():
    with pytest.raises(crowdsec.CrowdSecError, match="nicht erreichbar"):
        crowdsec.Lapi("http://127.0.0.1:1", "m", "p").test()
