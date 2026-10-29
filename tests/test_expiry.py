import time

from fastapi.testclient import TestClient

from app import attackers, db, engine, main, notify
from app.store import rules
from tests.conftest import FakeBackend
from tests.test_api import H, setup_local
from tests.test_attackers import alert, names


def rule(asn, expires_at=None, action="ban"):
    rules.upsert([{"asn": asn, "name": f"AS{asn}", "action": action, "expires_at": expires_at}])


def test_expired_rules_no_longer_count_and_are_removed():
    rule(1, None)
    rule(2, time.time() + 3600)
    rule(3, time.time() - 1)
    assert set(engine.rules()) == {1, 2}  # expired, even before the scheduler removed it
    rev = db.get("config_rev")
    assert engine.expire_rules() == [3]
    assert db.get("config_rev") == rev + 1
    assert sorted(rules.asns()) == [1, 2]
    assert db.q1("SELECT action FROM audit_log ORDER BY id DESC LIMIT 1")["action"] == "asn.expired"
    assert engine.expire_rules() == []


def test_api_keeps_and_exports_the_lifetime(monkeypatch):
    monkeypatch.setattr(main.engine, "scheduler", lambda: None)
    until = time.time() + 30 * 86400
    with TestClient(main.app) as client:
        setup_local(client)
        assert client.put("/api/asns", headers=H, json=[{"asn": 64500, "action": "ban", "expires_at": until}]).status_code == 200
        assert client.get("/api/asns").json()[0]["expires_at"] == until
        # switching the action from the UI sends the lifetime along
        client.put("/api/asns", headers=H, json=[{"asn": 64500, "action": "captcha", "expires_at": until}])
        assert rules.listing()[0]["expires_at"] == until
        assert client.get("/api/export").json()["asns"][0]["expires_at"] == until
        # without a lifetime the rule is permanent
        client.put("/api/asns", headers=H, json=[{"asn": 64500, "action": "captcha"}])
        assert rules.listing()[0]["expires_at"] is None
        assert client.put("/api/asns", headers=H, json=[{"asn": 64500, "action": "ban", "expires_at": -5}]).status_code == 422


def test_old_database_gets_the_expiry_column(tmp_path, monkeypatch):
    import sqlite3
    f = tmp_path / "old.db"
    con = sqlite3.connect(f)
    con.execute("CREATE TABLE asn_rules (asn INTEGER PRIMARY KEY, name TEXT NOT NULL DEFAULT '', action TEXT NOT NULL, "
                "note TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT 'manual', updated_at REAL NOT NULL)")
    con.execute("INSERT INTO asn_rules(asn,action,updated_at) VALUES(64500,'ban',0)")
    con.commit()
    con.close()
    monkeypatch.setattr(db, "DB_FILE", f)
    monkeypatch.setattr(db._local, "conn", None, raising=False)
    db.init()
    assert set(engine.rules()) == {64500}


def test_new_attacking_networks_are_notified_once(monkeypatch):
    sent = []
    monkeypatch.setattr(attackers, "_fetch_sizes", lambda: None)
    monkeypatch.setattr(notify, "send", lambda title, msg, *a, **kw: sent.append((title, msg, kw)))
    names((24940, "HETZNER-AS", "Content", "DE"))
    be = FakeBackend()
    be.alert_list = [alert(i, f"5.9.0.{i}") for i in range(1, 7)]
    attackers.collect(be)
    assert not sent  # no notification target configured
    db.put("notify_url", "https://ntfy.example/topic")
    be.alert_list.append(alert(7, "5.9.0.7"))
    attackers.collect(be)
    assert len(sent) == 1 and "AS24940" in sent[0][1] and sent[0][2]["page"] == "attackers"
    be.alert_list.append(alert(8, "5.9.0.8"))
    attackers.collect(be)
    assert len(sent) == 1  # the same network is not reported again right away
