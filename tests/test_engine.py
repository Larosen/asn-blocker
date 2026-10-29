import json
import time

import pytest

from app import crowdsec, db, engine, sources
from app.store import exemptions, rules, vpn
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
    rules.upsert([{"asn": 1, "name": "a", "action": "ban"}, {"asn": 2, "name": "b", "action": "captcha"}])
    vpn.add([("nordvpn", "DE")])
    exemptions.add([("asn", "3", ""), ("cidr", "11.1.0.0/16", "")])
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
    exemptions.delete("asn", "3")
    db.put("sanity_percent", 100)
    engine.run("apply", "test")
    s = __import__("json").loads(last_run()["summary"])
    assert s["ban_added"] >= 1 and s["ban_removed"] >= 1
    assert engine.status_of("11.0.7.1", {"ban": list(applied("ban"))}) == "ban"


def test_add_happens_before_delete(env):
    engine.run("apply", "test")
    vpn.select("nordvpn", [], "exact")
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
    rules.delete([2])
    engine.run("apply", "test")
    assert last_run()["status"] == "blocked"
    assert env.decisions == before
    engine.run("apply", "test", force=True)
    assert last_run()["status"] == "ok"
    assert applied("captcha") == set()


def test_stopped_run_records_every_reason(env):
    engine.run("apply", "test")
    rules.delete([2])
    engine.run("apply", "test")
    reasons = json.loads(last_run()["summary"])["stopped"]
    assert len(reasons) >= 2 and any("Range count" in r for r in reasons), reasons


def test_confirmed_run_applies_only_the_reviewed_result(env):
    engine.run("apply", "test")
    rules.delete([2])
    engine.run("apply", "test")
    stopped = last_run()
    before = list(env.decisions)
    reviewed = json.loads(stopped["summary"])
    # data changed after the review: the confirmation does not cover it
    engine.run("apply", "test", confirmed=(stopped["id"], reviewed | {"ban": reviewed["ban"] + 50}))
    assert last_run()["status"] == "blocked" and "since the run you confirmed" in last_run()["log"]
    assert env.decisions == before
    engine.run("apply", "test", confirmed=(stopped["id"], reviewed))
    assert last_run()["status"] == "ok" and f"review of run #{stopped['id']}" in last_run()["log"]
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
    rules.delete([2])
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
        id, name, host_suffix = "x", "Surfshark", ".example.com"

        def fetch(self):
            return [("DE", "Germany", "de-fra.prod.example.com")]

    monkeypatch.setattr(sources, "_resolve", lambda h: [])
    with pytest.raises(sources.SourceError, match="DNS resolution"):
        S().ips("DE")


def test_hostnames_only_resolved_in_the_providers_domain(monkeypatch):
    calls = []
    monkeypatch.setattr(sources, "_resolve", lambda h: calls.append(h) or ["8.8.8.8"])

    class P(sources.Provider):
        id, name, host_suffix = "p", "P", ".vpn.example"

        def fetch(self):
            return [("DE", "Germany", "a.vpn.example"), ("DE", "Germany", "evil.attacker.example"),
                    ("DE", "Germany", "1.1.1.1")]

    class Q(sources.Provider):
        id, name = "q", "Q"     # IP lists only: hostnames are never resolved

        def fetch(self):
            return [("DE", "Germany", "x.attacker.example"), ("DE", "Germany", "1.0.0.1")]

    assert P().ips("DE") == ["1.1.1.1", "8.8.8.8"] and calls == ["a.vpn.example"]
    assert Q().ips("DE") == ["1.0.0.1"] and calls == ["a.vpn.example"]


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


def test_ipv6_flood_is_capped(env, monkeypatch):
    db.put("include_ipv6", True)
    flood = {**PREFIXES, 1: [f"{i:x}::/16" for i in range(0x2002, 0x4000)]}   # merges into 2000::/3-sized blocks
    monkeypatch.setattr(sources, "asn_prefixes", lambda a, use_cache=True: flood[a])
    engine.run("apply", "test")
    assert last_run()["status"] == "blocked" and "IPv6 /48" in last_run()["log"]
    assert env.decisions == []


def test_range_count_cap_on_first_run(env, monkeypatch):
    monkeypatch.setattr(engine, "MAX_RANGES", 10)
    engine.run("apply", "test")
    assert last_run()["status"] == "blocked" and "ranges would be pushed" in last_run()["log"]


def test_huge_exempt_asn_prefix_is_ignored(env, monkeypatch):
    poisoned = {**PREFIXES, 3: ["0.0.0.0/0", "::/0", "11.0.7.0/24"]}
    monkeypatch.setattr(sources, "asn_prefixes", lambda a, use_cache=True: poisoned[a])
    engine.run("apply", "test")
    assert last_run()["status"] == "ok" and "exempt AS3" in last_run()["log"]
    assert engine.status_of("11.0.1.1", {"ban": list(applied("ban"))}) == "ban"


def test_ipv4_mapped_protection_covers_the_ipv4_address(env):
    from app import selfprotect
    selfprotect.add("ip", "::ffff:11.0.1.5", "mapped")
    engine.run("apply", "test")
    assert last_run()["status"] == "ok", last_run()["log"]
    assert engine.status_of("11.0.1.5", {"ban": list(applied("ban"))}) is None


def test_additions_happen_before_any_deletion(env):
    engine.run("apply", "test")
    rules.upsert([{"asn": 2, "name": "b", "action": "ban"}])   # AS2 moves its ranges from captcha to ban
    env.calls.clear()
    engine.run("apply", "test", force=True)
    ops = [c[0] for c in env.calls]
    assert "add" in ops and "delete" in ops and max(i for i, o in enumerate(ops) if o == "add") < ops.index("delete")


def test_run_log_strips_control_characters(env, monkeypatch):
    from app import selfprotect
    selfprotect.add("ip", "198.51.100.77", "a\n12:00:00 Done‮")
    engine.run("apply", "test")
    assert "\n12:00:00 Done" not in last_run()["log"] and "‮" not in last_run()["log"]


def test_fetch_deadline_holds_against_dripping_headers():
    import socket
    import threading
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    stop = threading.Event()

    def drip():
        conn, _ = srv.accept()
        conn.recv(1024)
        conn.sendall(b"HTTP/1.1 200 OK\r\n")
        while not stop.is_set():
            try:
                conn.sendall(b"X-Slow: 1\r\n")
            except OSError:
                break
            stop.wait(0.5)
        conn.close()

    threading.Thread(target=drip, daemon=True).start()
    t0 = time.monotonic()
    with pytest.raises(sources.httpx.HTTPError):
        sources._fetch(f"http://127.0.0.1:{srv.getsockname()[1]}/", None, timeout=1)
    stop.set()
    assert time.monotonic() - t0 < 10


def test_zip_with_too_many_entries_is_refused(monkeypatch):
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i in range(30):
            z.writestr(f"f{i}.ovpn", "")
    monkeypatch.setattr(sources, "_fetch", lambda *a, **k: bytearray(buf.getvalue()))
    assert len(sources._zip_names("https://x.example/a.zip")) == 30
    with pytest.raises(sources.SourceError):
        sources._zip_names("https://x.example/a.zip", max_entries=10)


def test_country_name_parsing_is_bounded():
    t0 = time.monotonic()
    assert sources._cc("(" * 200000) == "" and sources._cc("word " * 100000) == ""
    assert sources._cc("USA Austin") == "US" and sources._cc("Korea (South)") == "KR"
    assert time.monotonic() - t0 < 1


def test_clean_removes_control_and_bidi():
    assert sources.clean("a\nb\x1b[31m‮c") == "a?b?[31m?c"
    assert sources.clean("x" * 500, 10) == "x" * 10 + "…"


def test_ipvanish_falls_back_to_gluetun_when_refused(monkeypatch):
    def refused(url, *a, **k):
        raise sources.SourceError(f"{url}: Client error '403 Forbidden'")

    monkeypatch.setattr(sources, "_zip_names", refused)
    monkeypatch.setattr(sources, "http_get", lambda url, *a, **k: {"servers": [
        {"country": "Germany", "city": "Frankfurt", "hostname": "fra-a01.ipvanish.com", "ips": ["203.0.113.5"]}]})
    prov = sources.IPVanish()
    assert prov.fetch() == [("DE", "Germany", "203.0.113.5")] and prov.source == "gluetun fallback"


def test_check_ip_points_to_neighbouring_vpn_servers(env, monkeypatch):
    monkeypatch.setattr(sources, "ip_info", lambda ip: {"asns": [1], "prefix": "11.0.0.0/16"})
    engine.run("apply", "test")
    r = engine.check_ip("11.0.6.200")  # NordVPN NO lists 11.0.6.9; the exit IP is a neighbour
    assert r["status"] == "ban"
    assert r["vpn_near"] == [{"provider": "nordvpn", "name": "NordVPN", "country": "NO", "selected": False, "mode": "exact"}]
    assert engine.check_ip("11.0.9.9")["vpn_near"] == []
