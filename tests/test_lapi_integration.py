"""Gegen eine echte CrowdSec-LAPI: CROWDSEC_LAPI_URL, CROWDSEC_MACHINE_ID, CROWDSEC_PASSWORD setzen."""
import os

import pytest

from app import crowdsec

URL = os.environ.get("CROWDSEC_LAPI_URL")
pytestmark = pytest.mark.skipif(not URL, reason="keine LAPI konfiguriert")


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
