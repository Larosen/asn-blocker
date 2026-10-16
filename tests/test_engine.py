import time

import pytest

from app import crowdsec, db, engine, sources
from tests.conftest import FakeBackend

PREFIXES = {1: ["11.0.0.0/16"], 2: ["11.0.0.0/8", "2a00:1::/32"], 3: ["11.0.7.0/24"]}


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setattr(sources, "asn_prefixes", lambda a, use_cache=True: PREFIXES[a])

    class P(sources.Provider):
        id, name = "nordvpn", "NordVPN"

        def fetch(self):
            return [("DE", "Germany", "11.0.5.9"), ("NO", "Norway", "11.0.6.9")]

    monkeypatch.setitem(sources.PROVIDERS, "nordvpn", P())
    monkeypatch.setattr(sources, "_public_ip", lambda v: v)  # test networks are not "global"
    be = FakeBackend()
    monkeypatch.setattr(crowdsec, "backend", lambda: be)
    monkeypatch.setattr(engine.notify, "send", lambda *a, **k: None)
    db.put("crowdsec_mode", "lapi")
    with db.tx() as c:
        c.execute("INSERT INTO asn_rules(asn,name,action,updated_at) VALUES(1,'a','ban',0),(2,'b','captcha',0)")
        c.execute("INSERT INTO vpn_rules VALUES('nordvpn','DE')")
        c.execute("INSERT INTO exemptions(kind,value) VALUES('asn','3'),('cidr','11.1.0.0/16')")
    return be


def last_run():
    return db.q1("SELECT * FROM runs ORDER BY id DESC LIMIT 1")


def applied(t):
    return {r["value"] for r in db.q("SELECT value FROM applied WHERE type=?", (t,))}


def test_apply_carves_exemptions_and_separates_types(env):
    engine.run("apply", "test")
    assert last_run()["status"] == "ok", last_run()["log"]
    ban, cap = applied("ban"), applied("captcha")
    assert "11.0.5.9" not in str(ban)
    assert engine.status_of("11.0.5.9", {"ban": list(ban)}) is None       # VPN exempted exactly
    assert engine.status_of("11.0.5.10", {"ban": list(ban)}) == "ban"     # neighbouring IP stays blocked
    assert engine.status_of("11.0.7.1", {"ban": list(ban)}) is None       # exempt ASN
    assert engine.status_of("11.1.2.3", {"captcha": list(cap)}) is None   # manual exemption
    assert engine.status_of("11.0.1.1", {"captcha": list(cap)}) is None   # no captcha under ban
    assert engine.status_of("11.200.0.1", {"captcha": list(cap)}) == "captcha"
    assert not any(":" in v for v in ban | cap)                            # IPv6 off
    assert {d["value"] for d in env.decisions if d["type"] == "ban"} == ban


def test_second_run_is_noop_then_diff(env):
    engine.run("apply", "test")
    env.calls.clear()
    engine.run("apply", "test")
    assert env.calls == [], "unchanged state must not write anything"
    with db.tx() as c:
        c.execute("DELETE FROM exemptions WHERE kind='asn'")
    db.put("sanity_percent", 100)
    engine.run("apply", "test")
    s = __import__("json").loads(last_run()["summary"])
    assert s["ban_added"] >= 1 and s["ban_removed"] >= 1
    assert engine.status_of("11.0.7.1", {"ban": list(applied("ban"))}) == "ban"


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
        d["until"] = time.time() + 3600  # expires before the next run
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
        c.execute("INSERT INTO watch_ips(ip) VALUES('11.0.9.9'),('11.0.5.9')")
    engine.run("apply", "test")
    st = {r["ip"]: r["last_status"] for r in db.q("SELECT * FROM watch_ips")}
    assert st == {"11.0.9.9": "ban", "11.0.5.9": "clear"}


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
    with pytest.raises(crowdsec.CrowdSecError, match="not reachable"):
        crowdsec.Lapi("http://127.0.0.1:1", "m", "p").test()


def test_preview_counts_against_applied(env):
    p = engine.preview()
    assert p["ban"]["add"] == p["ban"]["total"] > 0 and p["ban"]["remove"] == 0
    engine.run("apply", "test")
    db.bump_rev(db.conn())
    p = engine.preview()
    assert p["ban"]["add"] == 0 and p["ban"]["remove"] == 0
    before = list(env.decisions)
    with db.tx() as c:
        c.execute("DELETE FROM asn_rules WHERE asn=2")
        db.bump_rev(c)
    p = engine.preview()
    assert p["captcha"]["total"] == 0 and p["captcha"]["remove"] > 0
    assert env.decisions == before  # preview writes nothing to CrowdSec


def test_countries_have_continent(env):
    cs = {c["code"]: c for c in sources.PROVIDERS["nordvpn"].countries()}
    assert cs["DE"]["continent"] == "EU" and cs["NO"]["continent"] == "EU"


def test_json_logging(capsys, monkeypatch):
    import json
    import logging

    from app import logs

    monkeypatch.setenv("LOG_FORMAT", "json")
    logs.setup()
    logging.getLogger("asn_blocker.test").info("hello %s", "world", extra={"run_id": 7})
    line = capsys.readouterr().out.strip().splitlines()[-1]
    data = json.loads(line)
    assert data["msg"] == "hello world" and data["run_id"] == 7 and data["level"] == "info"
    monkeypatch.setenv("LOG_FORMAT", "text")
    logs.setup()


def test_dns_failure_is_reported(monkeypatch):
    class S(sources.Provider):
        id, name = "x", "Surfshark"

        def fetch(self):
            return [("DE", "Germany", "de-fra.prod.example.com")]

    monkeypatch.setattr(sources, "_resolve", lambda h: [])
    with pytest.raises(sources.SourceError, match="DNS resolution"):
        S().ips("DE")


def test_poisoned_source_cannot_block_private_or_huge_ranges(env, monkeypatch):
    poisoned = {**PREFIXES, 1: ["11.0.0.0/16", "0.0.0.0/1", "10.0.0.0/8", "127.0.0.0/8", "192.168.0.0/16", "::/0"]}
    monkeypatch.setattr(sources, "asn_prefixes", lambda a, use_cache=True: poisoned[a])
    engine.run("apply", "test")
    assert last_run()["status"] == "ok", last_run()["log"]
    assert "implausibly large" in last_run()["log"]
    ranges = {t: list(applied(t)) for t in ("ban", "captcha")}
    for ip in ("10.1.2.3", "127.0.0.1", "192.168.1.1", "8.8.8.8"):
        assert engine.status_of(ip, ranges) is None, ip


def test_sanity_caps_address_space_even_on_first_run(env, monkeypatch):
    many = {**PREFIXES, 1: [f"{i}.0.0.0/8" for i in range(11, 60)]}   # 49 /8s ≈ 19 % of IPv4
    monkeypatch.setattr(sources, "asn_prefixes", lambda a, use_cache=True: many[a])
    engine.run("apply", "test")
    assert last_run()["status"] == "blocked" and "IPv4 addresses" in last_run()["log"]
    assert env.decisions == []


def test_sanity_detects_address_space_jump_with_same_range_count(env, monkeypatch):
    engine.run("apply", "test")
    halved = {**PREFIXES, 2: ["11.0.0.0/9", "2a00:1::/32"]}   # same structure, half the address space
    monkeypatch.setattr(sources, "asn_prefixes", lambda a, use_cache=True: halved[a])
    engine.run("apply", "test")
    assert last_run()["status"] == "blocked" and "address space" in last_run()["log"], last_run()["log"]
