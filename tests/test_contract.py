"""API contract: the routes and the shape of every read endpoint stay as the web UI expects them.

The snapshot in tests/contract.json holds, per endpoint, the JSON structure (keys and value types, not the values).
A refactoring that changes it fails here; an intended change is recorded with
    UPDATE_CONTRACT=1 pytest tests/test_contract.py
and shows up in the diff of contract.json.
"""
import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import main
from tests.test_api import H
from tests.ui import server

SNAPSHOT = Path(__file__).with_name("contract.json")
READS = ["/api/session", "/api/overview", "/api/asns", "/api/asns/suggestions", "/api/vpn/providers",
         "/api/vpn/nordvpn/countries", "/api/exemptions", "/api/watch", "/api/protect", "/api/attackers?days=30",
         "/api/attackers/64506?days=30", "/api/check/203.0.113.10", "/api/settings", "/api/runs", "/api/runs/1",
         "/api/audit", "/api/export", "/api/preview"]


def shape(v):
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    if v is None:
        return "null"
    if isinstance(v, dict):
        return {k: shape(x) for k, x in sorted(v.items())}
    merged = None
    for x in v:
        merged = merge(merged, shape(x))
    return [merged] if merged is not None else []


def merge(a, b):
    """Union of two shapes: keys of both objects, alternative scalar types as 'number|null'."""
    if a is None:
        return b
    if isinstance(a, dict) and isinstance(b, dict):
        return {k: merge(a.get(k), b.get(k)) if k in a and k in b else (a.get(k) or b.get(k)) for k in sorted(a | b)}
    if isinstance(a, list) and isinstance(b, list):
        return [merge(a[0] if a else None, b[0] if b else None)] if a or b else []
    if a == b:
        return a
    if isinstance(a, str) and isinstance(b, str):
        return "|".join(sorted(set(a.split("|")) | set(b.split("|"))))
    return a if isinstance(a, (dict, list)) else b


@pytest.fixture
def client(monkeypatch):
    server.install_fakes(monkeypatch.setattr)
    monkeypatch.setattr(main.engine, "scheduler", lambda: None)
    server.seed()
    with TestClient(main.app) as c:
        r = c.post("/api/login", headers=H, json={"username": "admin", "password": server.PASSWORD})
        assert r.status_code == 200
        yield c


def current(client):
    routes = sorted(f"{m} {r.path}" for r in main.app.routes if hasattr(r, "methods") for m in r.methods if m != "HEAD")
    shapes = {}
    for path in READS:
        r = client.get(path)
        assert r.status_code == 200, (path, r.text)
        shapes[path] = shape(r.json())
    return {"routes": routes, "shapes": shapes}


def test_api_contract(client):
    now = current(client)
    if os.environ.get("UPDATE_CONTRACT"):
        SNAPSHOT.write_text(json.dumps(now, indent=1, sort_keys=True) + "\n")
    want = json.loads(SNAPSHOT.read_text())
    assert now["routes"] == want["routes"]
    for path in READS:
        assert now["shapes"][path] == want["shapes"][path], path
