import pytest
from fastapi.testclient import TestClient

from app import auth, db, main

H = {"X-Requested-With": "asn-blocker"}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(main.engine, "scheduler", lambda: None)
    with TestClient(main.app) as c:
        c.token = auth.new_setup_token()
        yield c


def setup_local(client):
    token = getattr(client, "token", None) or auth.new_setup_token()
    r = client.post("/api/setup/auth", headers=H, json={"token": token, "mode": "local", "username": "admin",
                                                        "password": "correct-horse-battery"})
    assert r.status_code == 200, r.text


def test_setup_required_and_token(client):
    assert client.get("/api/session").json()["setup_required"]
    assert client.get("/api/overview").status_code == 409
    r = client.post("/api/setup/auth", headers=H, json={"token": "wrong", "mode": "local", "password": "x" * 12})
    assert r.status_code == 403
    setup_local(client)
    assert client.get("/api/overview").status_code == 200
    assert client.post("/api/setup/auth", headers=H, json={"token": client.token, "mode": "local", "password": "x" * 12}).status_code == 409


def test_csrf_header_and_origin(client):
    setup_local(client)
    assert client.post("/api/runs", json={"kind": "plan"}).status_code == 403
    r = client.post("/api/watch", headers={**H, "Origin": "https://evil.example"}, json={"ip": "1.1.1.1"})
    assert r.status_code == 403
    assert client.post("/api/watch", headers={**H, "Origin": "http://testserver"}, json={"ip": "1.1.1.1"}).status_code == 200


def test_login_logout_and_throttle(client):
    setup_local(client)
    client.post("/api/logout", headers=H)
    assert client.get("/api/overview").status_code == 401
    for _ in range(5):
        assert client.post("/api/login", headers=H, json={"username": "admin", "password": "nope"}).status_code == 401
    assert client.post("/api/login", headers=H, json={"username": "admin", "password": "correct-horse-battery"}).status_code == 429
    auth._failed.clear()
    assert client.post("/api/login", headers=H, json={"username": "admin", "password": "correct-horse-battery"}).status_code == 200
    assert client.get("/api/overview").status_code == 200


def test_proxy_mode_rejects_lockout_and_untrusted(client):
    body = {"token": client.token, "mode": "proxy", "trusted_proxies": ["10.9.9.9"], "user_header": "Remote-User"}
    r = client.post("/api/setup/auth", headers={**H, "Remote-User": "alice"}, json=body)
    assert r.status_code == 422 and "lock you out" in r.json()["detail"]   # the TestClient peer is 'testclient'
    db.put("auth_mode", "proxy")
    db.put("trusted_proxies", ["10.9.9.9/32"])
    assert client.get("/api/overview", headers={"Remote-User": "mallory"}).status_code == 401


def test_proxy_mode_trusted(client, monkeypatch):
    db.put("auth_mode", "proxy")
    db.put("trusted_proxies", ["127.0.0.0/8"])
    monkeypatch.setattr(auth, "peer_ip", lambda r: "127.0.0.1")
    assert client.get("/api/overview").status_code == 401
    r = client.get("/api/overview", headers={"Remote-User": "alice", "X-Forwarded-For": "203.0.113.5"})
    assert r.status_code == 200 and r.json()["user"] == "alice" and r.json()["me"]["ip"] == "203.0.113.5"


def test_security_headers_and_no_docs(client):
    r = client.get("/")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    for p in ("/docs", "/openapi.json", "/redoc"):
        assert client.get(p).status_code == 404


def test_rules_crud_and_validation(client):
    setup_local(client)
    assert client.put("/api/asns", headers=H, json=[{"asn": 24940, "action": "ban", "note": "Hetzner"}]).status_code == 200
    assert client.put("/api/asns", headers=H, json=[{"asn": 1, "action": "drop"}]).status_code == 422
    assert client.get("/api/overview").json()["pending"]
    assert client.post("/api/exemptions", headers=H, json={"kind": "cidr", "value": "not-an-ip"}).status_code == 422
    assert client.post("/api/exemptions", headers=H, json={"kind": "cidr", "value": "198.51.100.7"}).json()["value"] == "198.51.100.7/32"
    assert client.put("/api/vpn/nordvpn", headers=H, json={"countries": ["deu"]}).status_code == 422
    assert client.put("/api/vpn/nordvpn", headers=H, json={"countries": ["de", "NO"], "mode": "exact"}).status_code == 200
    assert client.put("/api/vpn/unknown", headers=H, json={"countries": []}).status_code == 404
    exp = client.get("/api/export").json()
    assert exp["asns"][0]["asn"] == 24940 and len(exp["vpn"]) == 2


def test_parse_pasted_list(client):
    setup_local(client)
    text = "ASN_LIST=(\n  15169    # Google\n # 13335    # Cloudflare\n  AS8075 Microsoft\n)"
    r = client.post("/api/asns/parse", headers=H, json={"text": text, "action": "ban"}).json()
    assert [x["asn"] for x in r] == [15169, 8075]
    assert r[0]["note"] == "Google"


def test_crowdsec_unreachable_is_422_not_500(client):
    setup_local(client)
    r = client.put("/api/crowdsec", headers=H, json={"mode": "lapi", "lapi_url": "http://127.0.0.1:1", "machine_id": "m", "password": "p"})
    assert r.status_code == 422 and "127.0.0.1:1" in r.json()["detail"]


def test_bulk_delete(client):
    setup_local(client)
    client.put("/api/asns", headers=H, json=[{"asn": a, "action": "ban"} for a in (1, 2, 3)])
    assert client.post("/api/asns/delete", headers=H, json={"asns": [1, 3]}).status_code == 200
    assert [r["asn"] for r in client.get("/api/asns").json()] == [2]


def test_static_js_served_with_csp(client):
    r = client.get("/static/text.js")
    assert r.status_code == 200 and "export function t" in r.text


def test_security_headers_on_csrf_rejection(client):
    r = client.post("/api/runs", json={"kind": "plan"})
    assert r.status_code == 403 and "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"


def test_body_size_limit(client):
    r = client.post("/api/login", headers={**H, "Content-Type": "application/json"}, content=b"x" * (main.MAX_BODY + 1))
    assert r.status_code == 413


def test_setup_token_not_throttled_and_rotated(client):
    for _ in range(20):
        assert client.post("/api/setup/auth", headers=H, json={"token": "wrong", "mode": "local", "password": "x" * 12}).status_code == 403
    old = client.token
    new = auth.new_setup_token()
    r = client.post("/api/setup/auth", headers=H, json={"token": old, "mode": "local", "password": "x" * 12})
    assert r.status_code == 403
    r = client.post("/api/setup/auth", headers=H, json={"token": new, "mode": "local", "password": "x" * 12})
    assert r.status_code == 200
    assert db.get("setup_token_hash") is None   # single use


def test_reserved_identity_header_rejected(client, monkeypatch):
    monkeypatch.setattr(auth, "peer_ip", lambda r: "10.9.9.9")
    body = {"token": client.token, "mode": "proxy", "trusted_proxies": ["10.9.9.9"], "user_header": "User-Agent"}
    assert client.post("/api/setup/auth", headers=H, json=body).status_code == 422


def test_duplicate_identity_header_rejected(client, monkeypatch):
    db.put("auth_mode", "proxy")
    db.put("auth_user_header", "Remote-User")
    db.put("trusted_proxies", ["10.9.9.9/32"])
    monkeypatch.setattr(auth, "peer_ip", lambda r: "10.9.9.9")
    assert client.get("/api/overview", headers=[("Remote-User", "mallory"), ("Remote-User", "alice")]).status_code == 401
    assert client.get("/api/overview", headers={"Remote-User": " alice "}).json()["user"] == "alice"


def test_throttle_counts_before_check_and_buckets_ipv6():
    for i in range(5):
        auth.attempt(f"2001:db8:1:2::{i + 1}")
    with pytest.raises(auth.HTTPException):
        auth.attempt("2001:db8:1:2:ffff::1")           # same /64
    auth.attempt("2001:db8:1:3::1")                     # other /64
    key = auth.attempt("198.51.100.7")
    auth.forgive(key)
    assert "198.51.100.7" not in auth._failed


def test_cli_reset_auth_prints_working_token(client, capsys, monkeypatch):
    from app import cli
    setup_local(client)
    monkeypatch.setattr("sys.argv", ["cli", "reset-auth"])
    cli.main()
    token = capsys.readouterr().out.split("token:")[1].split()[0]
    assert client.get("/api/session").json()["setup_required"]
    r = client.post("/api/setup/auth", headers=H, json={"token": token, "mode": "local", "password": "y" * 12})
    assert r.status_code == 200


def test_lapi_password_not_reused_for_new_url(client, monkeypatch):
    setup_local(client)
    seen = []

    class FakeLapi:
        def __init__(self, url, machine, password):
            seen.append((url, password))

        def test(self):
            return "Connected"

    monkeypatch.setattr(main.crowdsec, "Lapi", FakeLapi)
    cfg = {"mode": "lapi", "lapi_url": "http://crowdsec:8080", "machine_id": "asnb", "password": "S3cret"}
    assert client.put("/api/crowdsec", headers=H, json=cfg).status_code == 200
    assert client.put("/api/crowdsec", headers=H, json={**cfg, "password": ""}).status_code == 200   # same target
    assert seen[-1] == ("http://crowdsec:8080", "S3cret")
    r = client.put("/api/crowdsec", headers=H, json={**cfg, "lapi_url": "http://attacker:80", "password": ""})
    assert r.status_code == 422 and seen[-1][0] != "http://attacker:80"
    for bad in ("http://evil?x", "http://evil#x", "http://user@evil"):
        assert client.put("/api/crowdsec", headers=H, json={**cfg, "lapi_url": bad}).status_code == 422


def test_notify_url_is_masked_and_kept(client, monkeypatch):
    from app import notify
    setup_local(client)
    monkeypatch.setattr(notify, "send", lambda *a, **k: None)
    cfg = {"notify_url": "https://ntfy.example/secret-topic?auth=TOKEN", "notify_format": "ntfy"}
    assert client.post("/api/notify/test", headers=H, json=cfg).status_code == 200
    assert client.put("/api/notify", headers=H, json=cfg).status_code == 200
    shown = client.get("/api/settings").json()["notify_url"]
    assert shown == "https://ntfy.example/***"
    assert client.post("/api/notify/test", headers=H, json={**cfg, "notify_url": shown}).status_code == 200
    assert client.put("/api/notify", headers=H, json={**cfg, "notify_url": shown}).status_code == 200
    assert db.get("notify_url") == "https://ntfy.example/secret-topic?auth=TOKEN"
    assert "secret-topic" not in client.get("/api/audit").text

def test_input_bounds(client):
    setup_local(client)
    for bad in ("-5", "99999999999", "1_0", "٣"):
        assert client.post("/api/exemptions", headers=H, json={"kind": "asn", "value": bad}).status_code == 422, bad
    assert client.post("/api/exemptions", headers=H, json={"kind": "asn", "value": "AS13335"}).json()["value"] == "13335"
    assert client.get("/api/audit?limit=-1").status_code == 422
    assert client.get("/api/runs?limit=-1").status_code == 422


def test_notify_requires_successful_test_before_save(client, monkeypatch):
    from app import notify
    setup_local(client)
    ok = [True]

    def fake_send(*a, cfg=None, **k):
        if not ok[0]:
            raise notify.NotifyError("ntfy server answered HTTP 403")
        fake_send.last = cfg

    monkeypatch.setattr(notify, "send", fake_send)
    cfg = {"notify_url": "https://ntfy.example/alerts", "notify_format": "ntfy", "notify_token": "tk_secret123",
           "public_url": "https://asnb.example"}
    r = client.put("/api/notify", headers=H, json=cfg)
    assert r.status_code == 409 and db.get("notify_url") == ""          # untested -> nothing saved
    ok[0] = False
    assert client.post("/api/notify/test", headers=H, json=cfg).status_code == 502
    assert client.put("/api/notify", headers=H, json=cfg).status_code == 409  # failed test does not count
    ok[0] = True
    assert client.post("/api/notify/test", headers=H, json=cfg).status_code == 200
    assert fake_send.last == ("https://ntfy.example/alerts", "ntfy", "tk_secret123", "https://asnb.example")
    assert client.put("/api/notify", headers=H, json={**cfg, "notify_token": "tk_other"}).status_code == 409  # other values
    assert client.put("/api/notify", headers=H, json=cfg).status_code == 200
    s = client.get("/api/settings").json()
    assert s["notify_token_set"] and "tk_secret123" not in client.get("/api/settings").text
    assert "tk_secret123" not in client.get("/api/audit").text
    # form sent again unchanged (masked URL, empty token field): test + save keep the token
    same = {"notify_url": s["notify_url"], "notify_format": "ntfy"}
    assert client.post("/api/notify/test", headers=H, json=same).status_code == 200
    assert fake_send.last[2] == "tk_secret123"
    assert client.put("/api/notify", headers=H, json=same).status_code == 200
    assert db.get("notify_token") == "tk_secret123" and db.get("public_url") == "https://asnb.example"
    # different server without a new token -> stored token is never sent there
    other = {"notify_url": "https://evil.example/x", "notify_format": "ntfy"}
    assert client.post("/api/notify/test", headers=H, json=other).status_code == 200
    assert fake_send.last[2] == ""
    # switching off needs no test
    assert client.put("/api/notify", headers=H, json={"notify_url": "", "notify_format": "ntfy"}).status_code == 200
    assert db.get("notify_url") == "" and db.get("notify_token") == ""
    for bad in ("tk with space", "tk\nInjected: 1"):
        assert client.post("/api/notify/test", headers=H, json={**cfg, "notify_token": bad}).status_code == 422


def test_ntfy_request_and_test_errors(client, monkeypatch):
    from app import notify
    setup_local(client)
    sent, status = [], [200]

    class R:
        def __init__(self):
            self.status_code = status[0]

    def post(url, **kw):
        sent.append((url, kw))
        return R()

    monkeypatch.setattr(notify.httpx, "post", post)
    db.put("notify_url", "https://ntfy.example/alerts")
    db.put("notify_format", "ntfy")
    db.put("notify_token", "tk_abc")
    db.put("public_url", "https://asnb.example")
    notify.send("asn-blocker: run failed", "boom", "error", run_id=7)
    url, kw = sent[-1]
    h = kw["headers"]
    assert url == "https://ntfy.example/alerts" and kw["content"] == b"boom"
    assert h["Authorization"] == "Bearer tk_abc" and h["Priority"] == "high" and h["Click"] == "https://asnb.example/#/runs/7"
    assert h["Title"] == "asn-blocker: run failed" and "rotating_light" in h["Tags"]
    assert client.post("/api/notify/test", headers=H, json={"notify_url": "https://ntfy.example/***"}).status_code == 200
    status[0] = 403
    r = client.post("/api/notify/test", headers=H, json={"notify_url": "https://ntfy.example/***"})
    assert r.status_code == 502 and "403" in r.json()["detail"] and "token" in r.json()["detail"]
    notify.send("x", "y")   # background sends never raise
    db.put("notify_format", "gotify")
    status[0] = 200
    notify.send("t", "m", "warning", run_id=3)
    url, kw = sent[-1]
    assert kw["headers"]["X-Gotify-Key"] == "tk_abc" and kw["json"]["priority"] == 6
    assert kw["json"]["extras"]["client::notification"]["click"]["url"] == "https://asnb.example/#/runs/3"


def test_ui_files_are_revalidated(client):
    for path in ("/", "/static/app.js", "/static/app.css"):
        r = client.get(path)
        assert r.status_code == 200 and r.headers["cache-control"] == "no-cache", path
    etag = client.get("/static/app.js").headers["etag"]
    assert client.get("/static/app.js", headers={"If-None-Match": etag}).status_code == 304
    assert client.get("/api/session").headers["cache-control"] == "no-store"


def test_blocking_own_network_needs_confirmation(client, monkeypatch):
    from app import sources
    db.put("auth_mode", "proxy")
    db.put("auth_user_header", "Remote-User")
    db.put("trusted_proxies", ["10.9.9.9/32"])
    monkeypatch.setattr(auth, "peer_ip", lambda r: "10.9.9.9")
    monkeypatch.setattr(sources, "ip_info", lambda ip: {"asns": [3320], "prefix": "84.128.0.0/10"})
    hdr = {**H, "Remote-User": "alice", "X-Forwarded-For": "84.150.3.10"}
    rules = [{"asn": 3320, "action": "ban"}, {"asn": 14061, "action": "ban"}]
    r = client.put("/api/asns", headers=hdr, json=rules)
    assert r.status_code == 409
    d = r.json()["detail"]
    assert d["code"] == "own_asn" and d["asns"] == [3320] and d["ip"] == "84.150.3.10"
    assert db.q1("SELECT count(*) n FROM asn_rules")["n"] == 0            # nothing saved
    assert client.put("/api/asns", headers=hdr, json=rules[1:]).status_code == 200   # other networks: no question
    assert client.put("/api/asns?confirm_own=1", headers=hdr, json=rules).status_code == 200
    assert {r["asn"] for r in db.q("SELECT asn FROM asn_rules")} == {3320, 14061}
    assert client.put("/api/asns", headers=hdr, json=[{"asn": 3320, "action": "captcha"}]).status_code == 200  # existing rule
    r = client.post("/api/import", headers=hdr, json={"version": 1, "asns": [{"asn": 3320, "action": "ban"}]})
    assert r.status_code == 200   # already present
    with db.tx() as c:
        c.execute("DELETE FROM asn_rules")
    r = client.post("/api/import", headers=hdr, json={"version": 1, "asns": [{"asn": 3320, "action": "ban"}]})
    assert r.status_code == 409


def test_suggestions(client):
    from app import selfprotect, suggestions
    setup_local(client)
    with db.tx() as c:
        c.execute("INSERT INTO asn_rules(asn,name,action,updated_at) VALUES(14061,'DO','ban',0)")
    selfprotect.add("asn", "24940", "test")
    sg = client.get("/api/asns/suggestions").json()
    assert [x["id"] for x in sg["lists"]] == [x["id"] for x in suggestions.LISTS]
    vps = next(x for x in sg["lists"] if x["id"] == "vps")
    flags = {a["asn"]: (a["present"], a["protected"]) for a in vps["asns"]}
    assert flags[14061] == (True, False) and flags[24940] == (False, True)
    asns = [a for x in suggestions.LISTS for a, _ in x["asns"]]
    assert len(asns) == len(set(asns)) and all(0 < a < 2**32 for a in asns)


def test_search_by_ip_returns_its_asn(client, monkeypatch):
    from app import sources
    setup_local(client)
    calls = []
    monkeypatch.setattr(sources, "ip_info", lambda ip: calls.append(ip) or {"asns": [8075], "prefix": "8.8.4.0/24"})
    with db.tx() as c:
        c.execute("INSERT INTO asn_names VALUES(8075,'Microsoft Corporation','Content','US')")
    r = client.get("/api/asn/search", params={"q": " 8.8.4.4 "}).json()
    assert r == [{"asn": 8075, "name": "Microsoft Corporation", "class": "Content", "cc": "US", "rule": None,
                  "via": {"ip": "8.8.4.4", "prefix": "8.8.4.0/24"}}]
    assert client.get("/api/asn/search", params={"q": "2a01:4f8::1"}).status_code == 200
    for private in ("10.0.0.1", "127.0.0.1", "fd00::1"):
        assert client.get("/api/asn/search", params={"q": private}).status_code == 422
    assert calls == ["8.8.4.4", "2a01:4f8::1"]          # name searches never hit RIPE for IPs
    assert client.get("/api/asn/search", params={"q": "8.8.4"}).status_code == 200   # partial: normal search
    assert calls == ["8.8.4.4", "2a01:4f8::1"]


def test_search_by_unrouted_ip_explains(client, monkeypatch):
    from app import sources
    setup_local(client)
    monkeypatch.setattr(sources, "ip_info", lambda ip: {"asns": [], "prefix": ""})
    monkeypatch.setattr(sources, "ip_holder", lambda ip: "Example Org (EXAMPLE-1)")
    r = client.get("/api/asn/search", params={"q": "8.8.4.4"}).json()
    assert r == [{"asn": None, "rule": None, "via": {"ip": "8.8.4.4", "prefix": None, "holder": "Example Org (EXAMPLE-1)"}}]


def test_busy_hashing_does_not_use_up_attempts(client):
    setup_local(client)
    client.post("/api/logout", headers=H)
    assert auth._hashing.acquire(blocking=False) and auth._hashing.acquire(blocking=False)
    try:
        for _ in range(8):   # a flood keeping both scrypt slots busy
            assert client.post("/api/login", headers=H, json={"username": "admin", "password": "x"}).status_code == 429
    finally:
        auth._hashing.release()
        auth._hashing.release()
    ok = client.post("/api/login", headers=H, json={"username": "admin", "password": "correct-horse-battery"})
    assert ok.status_code == 200


def test_throttle_wide_ipv6_bucket_and_lru_eviction():
    for i in range(20):                       # 20 different /64s in one /48
        auth.attempt(f"2001:db8:7:{i:x}::1")
    with pytest.raises(auth.HTTPException):
        auth.attempt("2001:db8:7:ff::1")
    auth._failed.clear()
    for _ in range(5):
        auth.attempt("198.51.100.9")
    for i in range(10001):                    # rotation must not reset the locked bucket
        auth._failed[f"x{i}"] = [__import__("time").time() - 1]
    auth.attempt("203.0.113.1")
    with pytest.raises(auth.HTTPException):
        auth.attempt("198.51.100.9")


def test_all_trusted_xff_chain_falls_back_to_peer(client, monkeypatch):
    db.put("trusted_proxies", ["0.0.0.0/0"])
    monkeypatch.setattr(auth, "peer_ip", lambda r: "10.1.1.1")

    class R:
        headers = {"x-forwarded-for": "6.6.6.6, 10.2.2.2"}
    assert auth.client_ip(R()) == "10.1.1.1"
    assert auth.broad_trusted_proxies() == ["0.0.0.0/0"]


def test_notify_token_bound_to_scheme_host_port():
    from app import notify
    assert notify.same_host("https://h.example/a", "https://h.example:443/b")
    for other in ("http://h.example/a", "https://h.example:8443/a", "https://g.example/a"):
        assert not notify.same_host(other, "https://h.example/b"), other


def test_notify_rejects_link_local_and_limits_tests(client, monkeypatch):
    from app import main as m
    from app import notify
    setup_local(client)
    with pytest.raises(notify.NotifyError):
        notify.check_target("http://169.254.169.254/latest")
    notify.check_target("http://127.0.0.1:2586/x")          # internal services stay allowed
    r = client.post("/api/notify/test", headers=H, json={"notify_url": "http://169.254.169.254/x"})
    assert r.status_code == 502 and "not allowed" in r.json()["detail"]
    r = client.put("/api/crowdsec", headers=H, json={"mode": "lapi", "lapi_url": "http://169.254.169.254", "machine_id": "a", "password": "p"})
    assert r.status_code == 422
    idn = {"notify_url": "https://n.example/x", "public_url": "https://bücher.example"}
    assert client.post("/api/notify/test", headers=H, json=idn).status_code == 422
    monkeypatch.setattr(notify, "send", lambda *a, **k: None)
    m._notify_tests.clear()
    codes = [client.post("/api/notify/test", headers=H, json={"notify_url": "https://n.example/x"}).status_code for _ in range(11)]
    assert codes[-1] == 429 and codes[:-1].count(200) >= 9


def test_notify_send_never_raises_into_runs(monkeypatch):
    from app import notify
    db.put("notify_url", "https://n.example/x")

    def boom(*a, **k):
        raise UnicodeEncodeError("ascii", "ü", 0, 1, "x")
    monkeypatch.setattr(notify.httpx, "post", boom)
    monkeypatch.setattr(notify, "check_target", lambda url: None)
    notify.send("t", "m")            # must not raise


def test_import_is_validated_before_writing(client):
    setup_local(client)
    bad = {"version": 1, "asns": [{"asn": 14061, "action": "ban"}],
           "exemptions": [{"kind": "cidr", "value": "203.0.113.0/24"}, {"kind": "cidr", "value": "0.0.0.0/0"}]}
    r = client.post("/api/import", headers=H, json=bad)
    assert r.status_code == 422 and "too large" in r.json()["detail"]
    assert db.q1("SELECT count(*) n FROM asn_rules")["n"] == 0 and db.q1("SELECT count(*) n FROM exemptions")["n"] == 0
    assert client.post("/api/exemptions", headers=H, json={"kind": "cidr", "value": "::/0"}).status_code == 422
    good = {**bad, "exemptions": bad["exemptions"][:1], "watch": [{"ip": "198.51.100.1"}]}
    assert client.post("/api/import", headers=H, json=good).status_code == 200
    assert db.q1("SELECT count(*) n FROM asn_rules")["n"] == 1 and db.q1("SELECT count(*) n FROM watch_ips")["n"] == 1


def test_search_rejects_odd_digits(client):
    setup_local(client)
    with db.tx() as c:
        c.execute("INSERT INTO asn_names VALUES(14061,'DIGITALOCEAN','Content','US')")
    for q in ("²", "9" * 40):
        assert client.get("/api/asn/search", params={"q": q}).status_code == 200


def test_only_the_latest_stopped_run_can_be_confirmed(client, monkeypatch):
    from app import engine
    setup_local(client)
    db.put("crowdsec_mode", "lapi")
    calls = []
    monkeypatch.setattr(engine, "run", lambda kind, user, force=False, confirmed=None: calls.append(confirmed))
    with db.tx() as c:
        c.execute("INSERT INTO runs(kind,status,triggered_by,started_at,summary) VALUES"
                  "('apply','blocked','x',1,'{\"ban\": 5}'),('apply','blocked','x',2,'{\"ban\": 7}'),"
                  "('plan','blocked','x',3,NULL)")
    assert client.post("/api/runs", headers=H, json={"kind": "apply", "confirm": 1}).status_code == 409   # superseded
    assert client.post("/api/runs", headers=H, json={"kind": "plan", "confirm": 2}).status_code == 409
    assert client.post("/api/runs", headers=H, json={"kind": "apply", "force": True}).status_code == 200  # force is ignored
    r = client.post("/api/runs", headers=H, json={"kind": "apply", "confirm": 2})
    assert r.status_code == 200
    import time
    for _ in range(50):
        if len(calls) == 2:
            break
        time.sleep(0.05)
    assert calls == [None, (2, {"ban": 7})]
