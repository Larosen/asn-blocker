"""Runs against a real CrowdSec LAPI: set CROWDSEC_LAPI_URL, CROWDSEC_MACHINE_ID, CROWDSEC_PASSWORD."""
import os

import pytest

from app import crowdsec

URL = os.environ.get("CROWDSEC_LAPI_URL")
pytestmark = pytest.mark.skipif(not URL, reason="no LAPI configured")


def test_roundtrip():
    lapi = crowdsec.Lapi(URL, os.environ["CROWDSEC_MACHINE_ID"], os.environ["CROWDSEC_PASSWORD"])
    reason = "asn-blocker integration-test"
    lapi.delete_scenario(reason)
    lapi.add(["192.0.2.0/24", "198.51.100.0/24", "2001:db8::/32"], "captcha", reason, 3600)
    cur = lapi.list(reason)
    assert {d["value"] for d in cur} == {"192.0.2.0/24", "198.51.100.0/24", "2001:db8::/32"}
    assert all(d["type"] == "captcha" and d["until"] > 0 for d in cur)
    lapi.delete_ids([cur[0]["id"]])
    assert len(lapi.list(reason)) == 2
    assert lapi.delete_scenario(reason) == 2
    assert lapi.list(reason) == []


def test_attackers_from_real_alerts():
    """A detection as an agent reports it is counted per ASN; manual decisions and our own alerts are not."""
    from datetime import datetime, timezone

    from app import attackers, db
    lapi = crowdsec.Lapi(URL, os.environ["CROWDSEC_MACHINE_ID"], os.environ["CROWDSEC_PASSWORD"])
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ip = "8.8.4.4"
    detection = {
        "scenario": "crowdsecurity/ssh-bf", "scenario_hash": "", "scenario_version": "", "message": "test detection",
        "events": [], "events_count": 1, "capacity": 5, "leakspeed": "10s", "simulated": False,
        "start_at": now, "stop_at": now, "created_at": now,
        "source": {"scope": "Ip", "value": ip, "ip": ip, "as_number": "15169", "as_name": "GOOGLE"},
        "decisions": [{"duration": "60s", "origin": "crowdsec", "scenario": "crowdsecurity/ssh-bf", "scope": "Ip",
                       "type": "ban", "value": ip}],
    }
    lapi._req("POST", "/alerts", json=[detection])
    raw = lapi.alerts(1)
    assert any((a.get("source") or {}).get("value") == ip and a.get("scenario") == "crowdsecurity/ssh-bf" for a in raw)
    assert all(isinstance(a.get("id"), int) for a in raw)
    attackers.collect(lapi)
    row = db.q1("SELECT asn, as_name, alerts FROM attack_ips WHERE ip=?", (ip,))
    assert row["asn"] == 15169 and row["alerts"] >= 1
