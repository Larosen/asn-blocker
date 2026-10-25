import ipaddress
import struct

import pytest
from fastapi.testclient import TestClient

from app import crowdsec, db, engine, main, selfprotect, sources
from tests.conftest import FakeBackend
from tests.test_api import H, setup_local


def utmp_record(typ, user, line, host, ip=None):
    addr = [0, 0, 0, 0]
    if ip:
        raw = ipaddress.ip_address(ip).packed
        addr = list(struct.unpack("<4i", raw.ljust(16, b"\0"))) if len(raw) == 4 else list(struct.unpack("<4i", raw))
    return selfprotect._UTMP.pack(typ, 1234, line.encode(), b"ts/0", user.encode(), host.encode(), 0, 0, 0, 1700000000, 0, *addr)


@pytest.fixture
def utmp(tmp_path, monkeypatch):
    p = tmp_path / "utmp"
    p.write_bytes(
        utmp_record(2, "reboot", "~", "6.8.0")                               # BOOT_TIME
        + utmp_record(7, "root", "pts/0", "10.0.5.77", "10.0.5.77")          # SSH, but private -> ignored
        + utmp_record(7, "root", "pts/1", "88.198.50.23", "88.198.50.23")  # SSH from the internet
        + utmp_record(7, "alice", "pts/2", "", "2001:4860::8888")            # only ut_addr_v6 set
        + utmp_record(8, "bob", "pts/3", "203.0.113.9"))                     # DEAD_PROCESS -> ignored
    monkeypatch.setattr(selfprotect, "HOST_UTMP", p)
    return p


def test_utmp_parsing(utmp):
    assert selfprotect._UTMP.size == 384
    sessions, status = selfprotect.ssh_sessions(utmp)
    assert status == "ok"
    assert [(s["ip"], s["user"], s["line"]) for s in sessions] == [("88.198.50.23", "root", "pts/1"), ("2001:4860::8888", "alice", "pts/2")]


def test_utmp_missing(tmp_path):
    assert selfprotect.ssh_sessions(tmp_path / "nope") == ([], "not mounted")


@pytest.fixture
def env(monkeypatch, utmp):
    # 88.198.0.0/16 belongs to AS1 (blocked), 84.150.0.0/16 to AS5 (own connection)
    pfx = {1: ["88.198.0.0/16"], 5: ["84.150.0.0/16"]}
    monkeypatch.setattr(sources, "asn_prefixes", lambda a, use_cache=True: pfx[a])
    monkeypatch.setattr(sources, "ip_info", lambda ip: {"asns": [5], "prefix": "84.150.0.0/16"})
    monkeypatch.setattr(engine.notify, "send", lambda *a, **k: None)
    be = FakeBackend()
    monkeypatch.setattr(crowdsec, "backend", lambda: be)
    db.put("crowdsec_mode", "lapi")
    with db.tx() as c:
        c.execute("INSERT INTO asn_rules(asn,name,action,updated_at) VALUES(1,'a','ban',0),(5,'own','ban',0)")
    return be


def applied():
    return [r["value"] for r in db.q("SELECT value FROM applied WHERE type='ban'")]


def test_active_ssh_session_is_carved_out(env):
    engine.run("apply", "t")
    assert engine.status_of("88.198.50.23", {"ban": applied()}) is None  # active SSH session
    assert engine.status_of("88.198.50.24", {"ban": applied()}) == "ban"  # neighbour stays blocked


def test_protected_asn_rule_ignored_and_prefixes_carved(env):
    selfprotect.protect_ip("84.150.3.10", "home connection", with_asn=True, asn_mode="exempt")
    assert db.q1("SELECT 1 x FROM protected WHERE kind='asn' AND value='5'")
    engine.run("apply", "t")
    run = db.q1("SELECT * FROM runs ORDER BY id DESC LIMIT 1")
    assert run["status"] == "ok" and "AS5 is protected" in run["log"]
    assert engine.status_of("84.150.200.1", {"ban": applied()}) is None  # whole ASN protected, not just the IP


def test_guard_aborts_if_protection_would_be_violated(env, monkeypatch):
    # simulates a bug while carving out: the final check must stop the run
    monkeypatch.setattr(engine.netset, "subtract", lambda src, ex: engine.netset.collapse(src))
    engine.run("apply", "t")
    run = db.q1("SELECT * FROM runs ORDER BY id DESC LIMIT 1")
    assert run["status"] == "failed" and "Self-protection violated" in run["log"]
    assert env.decisions == []


def test_api_rejects_rule_for_protected_asn_and_lists_sessions(env, monkeypatch):
    monkeypatch.setattr(main.engine, "scheduler", lambda: None)
    with TestClient(main.app) as client:
        setup_local(client)
        r = client.post("/api/protect", headers=H, json={"ip": "84.150.3.10", "with_asn": True, "asn_mode": "exempt"})
        assert r.json()["asns"] == [5]
        assert db.q1("SELECT 1 x FROM asn_rules WHERE asn=5") is None  # existing rule removed
        r = client.put("/api/asns", headers=H, json=[{"asn": 5, "action": "ban"}])
        assert r.status_code == 422 and "Self-protection: AS5" in r.json()["detail"]
        p = client.get("/api/protect").json()
        assert p["utmp"] == "ok" and [s["ip"] for s in p["sessions"]] == ["88.198.50.23", "2001:4860::8888"]
        assert {(x["kind"], x["value"]) for x in p["protected"]} == {("ip", "84.150.3.10"), ("asn", "5")}


def test_cli_protect_from_ssh_client(env, monkeypatch, capsys):
    from app import cli

    monkeypatch.setenv("SSH_CLIENT", "84.150.3.10 51234 22")
    assert cli.protect(["--asn-exempt"])
    out = capsys.readouterr().out
    assert "Protected: 84.150.3.10, AS5" in out and "Removed block rules: AS5" in out
    monkeypatch.delenv("SSH_CLIENT")
    assert not cli.protect([])


def test_local_browser_ip_not_offered(env, monkeypatch):
    monkeypatch.setattr(main.engine, "scheduler", lambda: None)
    with TestClient(main.app) as client:
        setup_local(client)
        assert client.get("/api/protect").json()["client_ip"] is None  # TestClient peer is not a public IP


def logind_session(directory, name, **kv):
    (directory / name).write_text("# This is private data. Do not parse.\n" + "".join(f"{k}={v}\n" for k, v in kv.items()))


def test_logind_sessions(tmp_path):
    d = tmp_path / "sessions"
    d.mkdir()
    logind_session(d, "3", UID=0, USER="root", STATE="active", REMOTE=1, SERVICE="sshd", TTY="pts/0",
                   REMOTE_HOST="88.198.50.23", REALTIME="1700000000123456")
    logind_session(d, "4", USER="alice", STATE="active", REMOTE=1, SERVICE="sshd", REMOTE_HOST="2001:4860::8888")
    logind_session(d, "5", USER="bob", STATE="active", REMOTE=1, REMOTE_HOST="10.0.0.7")      # private -> ignored
    logind_session(d, "6", USER="carol", STATE="active", SERVICE="login", TTY="tty1")       # local console
    logind_session(d, "7", USER="dave", STATE="closing", REMOTE=1, REMOTE_HOST="84.150.3.10")
    logind_session(d, "8", USER="eve", REMOTE=1, REMOTE_HOST="gateway.example.net")          # hostname -> ignored
    (d / "3.ref").write_text("")                                                             # FIFO placeholder
    sessions, status = selfprotect.ssh_sessions(tmp_path / "no-utmp", d)
    assert status == "ok"
    assert [(s["ip"], s["user"], s["line"]) for s in sessions] == [
        ("88.198.50.23", "root", "pts/0"), ("2001:4860::8888", "alice", "session 4")]
    assert sessions[0]["since"] == 1700000000


def test_utmp_directory_created_by_docker_counts_as_not_mounted(tmp_path):
    (tmp_path / "utmp").mkdir()  # what Docker creates when the host has no utmp file
    assert selfprotect.ssh_sessions(tmp_path / "utmp", tmp_path / "nope") == ([], "not mounted")


def test_utmp_and_logind_combined(utmp, tmp_path):
    d = tmp_path / "sessions"
    d.mkdir()
    logind_session(d, "9", USER="root", REMOTE=1, TTY="pts/1", REMOTE_HOST="88.198.50.23")  # same as utmp pts/1
    logind_session(d, "10", USER="root", REMOTE=1, TTY="pts/7", REMOTE_HOST="84.150.3.10")
    sessions, status = selfprotect.ssh_sessions(utmp, d)
    assert status == "ok" and [s["ip"] for s in sessions] == ["88.198.50.23", "2001:4860::8888", "84.150.3.10"]


def test_protection_defaults_to_the_ip_only(env):
    assert selfprotect.protect_ip("84.150.3.10", "phone") == []
    assert [(r["kind"], r["value"]) for r in selfprotect.protected()] == [("ip", "84.150.3.10")]
    engine.run("apply", "t")
    assert engine.status_of("84.150.3.10", {"ban": applied()}) is None   # the IP is safe …
    assert engine.status_of("84.150.3.11", {"ban": applied()}) == "ban"  # … its neighbours are not


def test_asn_protected_against_bans_only_gets_captcha(env):
    selfprotect.protect_ip("84.150.3.10", "home", with_asn=True, asn_mode="captcha")
    engine.run("apply", "t")
    run = db.q1("SELECT * FROM runs ORDER BY id DESC LIMIT 1")
    assert run["status"] == "ok" and "AS5 is protected against bans – captcha instead" in run["log"]
    cap = [r["value"] for r in db.q("SELECT value FROM applied WHERE type='captcha'")]
    assert engine.status_of("84.150.200.1", {"ban": applied(), "captcha": cap}) == "captcha"
    assert engine.status_of("84.150.3.10", {"ban": applied(), "captcha": cap}) is None  # the protected IP itself
    assert engine.status_of("88.198.1.1", {"ban": applied()}) == "ban"                 # other networks unchanged


def test_ban_from_another_rule_inside_a_capped_network_becomes_captcha(env, monkeypatch):
    # AS1 announces a prefix that covers part of the protected AS5 network
    monkeypatch.setattr(sources, "asn_prefixes", lambda a, use_cache=True: {1: ["88.198.0.0/16", "84.150.128.0/17"], 5: ["84.150.0.0/16"]}[a])
    with db.tx() as c:
        c.execute("DELETE FROM asn_rules WHERE asn=5")
    selfprotect.add("asn", "5", "home", "captcha")
    engine.run("apply", "t")
    cap = [r["value"] for r in db.q("SELECT value FROM applied WHERE type='captcha'")]
    assert engine.status_of("84.150.200.1", {"ban": applied(), "captcha": cap}) == "captcha"
    assert "captcha instead of ban" in db.q1("SELECT log FROM runs ORDER BY id DESC LIMIT 1")["log"]


def test_api_protection_modes(env, monkeypatch):
    monkeypatch.setattr(main.engine, "scheduler", lambda: None)
    with TestClient(main.app) as client:
        setup_local(client)
        r = client.post("/api/protect", headers=H, json={"ip": "84.150.3.10", "with_asn": True})
        assert r.json()["asns"] == [5]
        assert db.q1("SELECT action FROM asn_rules WHERE asn=5")["action"] == "captcha"  # ban rule downgraded
        assert client.put("/api/asns", headers=H, json=[{"asn": 5, "action": "ban"}]).status_code == 422
        assert client.put("/api/asns", headers=H, json=[{"asn": 5, "action": "captcha"}]).status_code == 200
        assert client.put("/api/protect/asn/5", headers=H, json={"mode": "exempt"}).status_code == 200
        assert db.q1("SELECT 1 x FROM asn_rules WHERE asn=5") is None                     # never block: rule removed
        assert client.put("/api/protect/asn/77", headers=H, json={"mode": "exempt"}).status_code == 404
        p = client.get("/api/protect").json()
        assert {(x["kind"], x["value"], x["mode"]) for x in p["protected"]} == {("ip", "84.150.3.10", "exempt"), ("asn", "5", "exempt")}


def test_old_database_gets_the_mode_column(tmp_path, monkeypatch):
    import sqlite3
    f = tmp_path / "old.db"
    con = sqlite3.connect(f)
    con.execute("CREATE TABLE protected (kind TEXT NOT NULL, value TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', "
                "created REAL NOT NULL DEFAULT 0, PRIMARY KEY (kind, value))")
    con.execute("INSERT INTO protected VALUES('asn','3320','home',0)")
    con.commit()
    con.close()
    monkeypatch.setattr(db, "DB_FILE", f)
    db._local.__dict__.clear()
    db.init()
    assert selfprotect.protected_asns("exempt") == {3320}  # existing protection keeps its behaviour
