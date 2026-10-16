import pytest
from fastapi.testclient import TestClient

from app import auth, db, main

H = {"X-Requested-With": "asn-blocker"}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(main.engine, "scheduler", lambda: None)
    with TestClient(main.app) as c:
        yield c


def setup_local(client):
    r = client.post("/api/setup/auth", headers=H, json={"token": auth.SETUP_TOKEN, "mode": "local", "username": "admin",
                                                        "password": "correct-horse-battery"})
    assert r.status_code == 200, r.text


def test_setup_required_and_token(client):
    assert client.get("/api/session").json()["setup_required"]
    assert client.get("/api/overview").status_code == 409
    r = client.post("/api/setup/auth", headers=H, json={"token": "wrong", "mode": "local", "password": "x" * 12})
    assert r.status_code == 403
    setup_local(client)
    assert client.get("/api/overview").status_code == 200
    assert client.post("/api/setup/auth", headers=H, json={"token": auth.SETUP_TOKEN, "mode": "local", "password": "x" * 12}).status_code == 409


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
    body = {"token": auth.SETUP_TOKEN, "mode": "proxy", "trusted_proxies": ["10.9.9.9"], "user_header": "Remote-User"}
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
