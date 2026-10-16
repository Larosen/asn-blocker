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


def test_parse_bash_list(client):
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


def test_notify_url_is_masked_and_kept(client):
    setup_local(client)
    s = client.get("/api/settings").json()
    s["notify_url"] = "https://ntfy.example/secret-topic?auth=TOKEN"
    body = {k: s[k] for k in ("interval_hours", "decision_hours", "include_ipv6", "sanity_percent", "notify_url",
                              "notify_format", "spamhaus_asndrop", "trusted_proxies", "auth_user_header")}
    assert client.put("/api/settings", headers=H, json=body).status_code == 200
    shown = client.get("/api/settings").json()["notify_url"]
    assert shown == "https://ntfy.example/***"
    assert client.put("/api/settings", headers=H, json={**body, "notify_url": shown}).status_code == 200
    assert db.get("notify_url") == "https://ntfy.example/secret-topic?auth=TOKEN"
    assert "secret-topic" not in client.get("/api/audit").text


def test_input_bounds(client):
    setup_local(client)
    for bad in ("-5", "99999999999", "1_0", "٣"):
        assert client.post("/api/exemptions", headers=H, json={"kind": "asn", "value": bad}).status_code == 422, bad
    assert client.post("/api/exemptions", headers=H, json={"kind": "asn", "value": "AS13335"}).json()["value"] == "13335"
    assert client.get("/api/audit?limit=-1").status_code == 422
    assert client.get("/api/runs?limit=-1").status_code == 422
