import time
from datetime import datetime, timezone

from app import attackers, db, sources
from app.store import exemptions, rules
from tests.conftest import FakeBackend

NOW = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def alert(i, ip, scenario="crowdsecurity/ssh-bf", asn="24940", name="HETZNER-AS", scope="Ip", **kw):
    return {"id": i, "scenario": scenario, "simulated": False, "start_at": NOW, "created_at": NOW,
            "source": {"scope": scope, "value": ip, "ip": ip, "as_number": asn, "as_name": name}} | kw


def names(*rows):
    with db.tx() as c:
        c.executemany("INSERT OR REPLACE INTO asn_names VALUES(?,?,?,?)", rows)


def test_only_local_detections_are_counted():
    be = FakeBackend()
    be.alert_list = [
        alert(1, "5.9.0.1"), alert(2, "5.9.0.2", scenario="crowdsecurity/http-probing"),
        alert(3, "5.9.0.3", scenario="update : +15000/-0 IPs", scope="crowdsecurity/community-blocklist"),  # CAPI
        alert(4, "5.9.0.4", scenario="manual 'ban' from 'localhost'"),          # cscli decisions add
        alert(5, "asn-blocker ban", scope="asn-blocker", scenario="asn-blocker ban"),  # our own
        alert(6, "5.9.0.6", simulated=True),
        alert(7, "10.0.0.1"),                                                   # private
    ]
    assert attackers.collect(be) == 2
    assert {r["ip"] for r in db.q("SELECT ip FROM attack_ips")} == {"5.9.0.1", "5.9.0.2"}
    assert be.calls == [("alerts", 168)]  # first collection: one week back


def test_collection_is_incremental():
    be = FakeBackend()
    be.alert_list = [alert(1, "5.9.0.1"), alert(2, "5.9.0.1")]
    assert attackers.collect(be) == 2
    assert attackers.collect(be) == 0  # same alerts again: nothing counted twice
    be.alert_list.append(alert(3, "5.9.0.1", scenario="crowdsecurity/http-bad-user-agent"))
    assert attackers.collect(be) == 1
    r = db.q1("SELECT alerts, scenarios FROM attack_ips")
    assert r["alerts"] == 3 and "crowdsecurity/http-bad-user-agent" in r["scenarios"]
    assert be.calls[-1][1] == 2  # later collections only look back a few hours


def test_missing_asn_is_looked_up(monkeypatch):
    calls = []
    monkeypatch.setattr(sources, "ip_info", lambda ip: calls.append(ip) or {"asns": [14061], "prefix": "1.2.0.0/16"})
    be = FakeBackend()
    be.alert_list = [alert(1, "8.8.4.4", asn="", name=""), alert(2, "8.8.4.4", asn="", name="")]
    attackers.collect(be)
    assert calls == ["8.8.4.4"] and db.q1("SELECT asn FROM attack_ips")["asn"] == 14061


def test_recommendations(monkeypatch):
    monkeypatch.setattr(attackers, "_fetch_sizes", lambda: None)
    names((24940, "HETZNER-AS", "Content", "DE"), (3320, "DTAG", "Eyeball", "DE"), (16509, "AMAZON-02", "Content", "US"),
          (14061, "DIGITALOCEAN", "Content", "US"), (51167, "CONTABO", "Content", "DE"), (12876, "SCALEWAY", "Content", "FR"))
    db.cache_put("asnsize:16509", 2 ** 26)
    be = FakeBackend()
    i = 0
    for asn, n in ((24940, 6), (3320, 9), (16509, 7), (14061, 2), (51167, 5), (12876, 5)):
        for k in range(n):
            i += 1
            be.alert_list.append(alert(i, f"{100 + asn % 50}.{k}.0.1", asn=str(asn)))
    rules.upsert([{"asn": 51167, "name": "CONTABO", "action": "ban"}])
    exemptions.add([("asn", "12876", "")])
    attackers.collect(be)
    rep = attackers.report(7)
    rec = {r["asn"]: r["recommendation"] for r in rep["rows"]}
    assert rec[24940]["kind"] == "recommend" and rec[24940]["action"] == "ban"
    assert "6 attacking IPs in 7 days, mostly ssh-bf" in rec[24940]["reason"]
    assert rec[3320]["kind"] == "watch" and "Consumer network" in rec[3320]["reason"]  # never for eyeball networks
    assert rec[16509]["action"] == "captcha"                                             # large cloud
    assert rec[14061]["kind"] == "watch"                                                 # too few attackers yet
    assert rec[51167]["kind"] == "active" and rec[12876]["kind"] == "protected"
    assert rep["recommended"] == 2
    assert [r["asn"] for r in rep["rows"]][:2] == [3320, 16509]                          # most attackers first
    ips = attackers.ips_of(24940)
    assert len(ips) == 6 and ips[0]["scenarios"] == ["crowdsecurity/ssh-bf"]


def test_history_window():
    with db.tx() as c:
        c.execute("INSERT INTO attack_ips VALUES(date('now','-20 days'),'5.9.0.1',24940,'HETZNER',3,'[\"a/b\"]',?)", (time.time(),))
        c.execute("INSERT INTO attack_ips VALUES(date('now'),'5.9.0.2',24940,'HETZNER',1,'[\"a/b\"]',?)", (time.time(),))
    assert attackers.report(7)["rows"][0]["ips"] == 1
    assert attackers.report(30)["rows"][0]["ips"] == 2
    db.prune()
    assert db.q1("SELECT count(*) n FROM attack_ips")["n"] == 2


def test_lookups_stop_at_the_time_budget_and_continue_later(monkeypatch):
    monkeypatch.setattr(sources, "ip_info", lambda ip: {"asns": [14061], "prefix": ""})
    monkeypatch.setattr(attackers, "LOOKUP_BUDGET", -1)  # no time left
    be = FakeBackend()
    be.alert_list = [alert(1, "8.8.4.4", asn="", name="")]
    attackers.collect(be)
    assert db.q1("SELECT asn FROM attack_ips")["asn"] is None
    monkeypatch.setattr(attackers, "LOOKUP_BUDGET", 20)
    attackers.collect(be)  # no new alerts, but the missing ASN is filled in
    assert db.q1("SELECT asn FROM attack_ips")["asn"] == 14061


def attacked(monkeypatch, *networks):
    """Collects alerts for (asn, name, class, attacking IPs) with automatic rules switched off, so tests decide when."""
    monkeypatch.setattr(attackers, "_fetch_sizes", lambda: None)
    attackers.take_added()  # left over from other tests
    names(*((asn, name, cls, "DE") for asn, name, cls, _ in networks))
    be, i = FakeBackend(), 0
    for asn, _, _, n in networks:
        for k in range(n):
            i += 1
            be.alert_list.append(alert(i, f"{100 + asn % 50}.{k}.0.1", asn=str(asn)))
    attackers.collect(be)


def test_automatic_rules_are_off_by_default(monkeypatch):
    attacked(monkeypatch, (24940, "HETZNER-AS", "Content", 6))
    assert attackers.auto_rules() == [] and rules.actions() == {}


def test_automatic_rules_follow_the_recommendation(monkeypatch):
    attacked(monkeypatch, (24940, "HETZNER-AS", "Content", 6), (3320, "DTAG", "Eyeball", 9), (12876, "SCALEWAY", "Content", 5))
    exemptions.add([("asn", "12876", "")])
    db.put("attackers_auto", "recommended")
    now = time.time()
    added = attackers.auto_rules(now)
    assert [(r["asn"], r["action"]) for r in added] == [(24940, "ban")]  # never consumer or exempt networks
    rule = rules.active()[24940]
    assert rule["source"] == "attackers" and rule["note"].startswith("automatic: 6 attacking IPs")
    assert rule["expires_at"] == now + 30 * 86400
    assert attackers.take_added() == added and attackers.take_added() == []
    assert attackers.auto_rules(now) == []  # now a rule: nothing more to do
    assert db.audit_log()[0]["user"] == "automatic"


def test_automatic_rules_only_captcha(monkeypatch):
    attacked(monkeypatch, (24940, "HETZNER-AS", "Content", 6))
    db.put("attackers_auto", "captcha")
    db.put("attackers_auto_days", 7)
    assert [(r["asn"], r["action"]) for r in attackers.auto_rules()] == [(24940, "captcha")]


def test_a_removed_automatic_rule_stays_removed_for_its_lifetime(monkeypatch):
    attacked(monkeypatch, (24940, "HETZNER-AS", "Content", 6))
    db.put("attackers_auto", "recommended")
    now = time.time()
    assert attackers.auto_rules(now)
    rules.delete([24940])
    assert attackers.auto_rules(now + 86400) == []
    assert [r["asn"] for r in attackers.auto_rules(now + 31 * 86400)] == [24940]


def test_automatic_rules_are_limited_per_collection(monkeypatch):
    monkeypatch.setattr(attackers, "MAX_AUTO", 2)
    attacked(monkeypatch, *((64500 + k, f"NET-{k}", "Content", 5) for k in range(4)))
    db.put("attackers_auto", "recommended")
    assert len(attackers.auto_rules()) == 2
    assert len(attackers.auto_rules()) == 2
    assert len(rules.actions()) == 4
