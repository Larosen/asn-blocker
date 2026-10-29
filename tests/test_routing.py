import json
import threading

import pytest

from app import db, routing, sources


def table(path, extra=(), v4=3000, v6=300):
    """A table.jsonl in bgp.tools format: enough filler prefixes to pass the plausibility check, plus extra lines."""
    with open(path, "w") as f:
        for i in range(v4):
            f.write(json.dumps({"CIDR": f"{11 + i // 65536}.{(i // 256) % 256}.{i % 256}.0/24", "ASN": 64600 + i % 7, "Hits": 100}) + "\n")
        for i in range(v6):
            f.write(json.dumps({"CIDR": f"2a0{i // 65536 % 10}:{i % 65536:x}::/48", "ASN": 64700, "Hits": 100}) + "\n")
        for line in extra:
            f.write((line if isinstance(line, str) else json.dumps(line)) + "\n")


EXTRA = [
    {"CIDR": "5.9.0.0/16", "ASN": 24940, "Hits": 3000},
    {"CIDR": "5.9.8.0/24", "ASN": 64999, "Hits": 3000},       # more specific of another network
    {"CIDR": "2a01:4f8::/32", "ASN": 24940, "Hits": 3000},
    {"CIDR": "5.9.0.0/16", "ASN": 64998, "Hits": 3000},       # announced by two ASNs (MOAS)
    {"CIDR": "94.130.0.0/16", "ASN": 24940, "Hits": 2},        # seen by too few peers: leak or noise
    {"CIDR": "4.0.0.0/7", "ASN": 64997, "Hits": 3000},         # implausibly large
    {"CIDR": "10.0.0.0/8", "ASN": 64996, "Hits": 3000},        # not public
    {"CIDR": "5.9.1.1/16", "ASN": 64995, "Hits": 3000},        # host bits set
    {"CIDR": "6.0.0.0/16", "ASN": "AS1", "Hits": 3000},        # malformed ASN
    "not json",
]


@pytest.fixture(autouse=True)
def small_tables(monkeypatch):
    monkeypatch.setattr(routing, "MIN_PREFIXES", {4: 2000, 6: 200})  # the real threshold needs ~700,000 lines


@pytest.fixture(scope="module")
def jsonl(tmp_path_factory):
    p = tmp_path_factory.mktemp("routing") / "table.jsonl"
    table(p, EXTRA)
    return p


def load(jsonl):
    return routing.refresh(download=lambda p: p.write_bytes(jsonl.read_bytes()))


def test_prefixes_and_lookup(jsonl):
    assert not routing.fresh() and routing.prefixes(24940) is None and routing.lookup("5.9.0.1") is None
    load(jsonl)
    assert routing.fresh()
    assert routing.prefixes(24940) == ["2a01:4f8::/32", "5.9.0.0/16"]
    assert routing.lookup("5.9.0.1") == {"asns": [24940, 64998], "prefix": "5.9.0.0/16"}
    assert routing.lookup("5.9.8.7") == {"asns": [64999], "prefix": "5.9.8.0/24"}   # longest match
    assert routing.lookup("::ffff:5.9.8.7") == {"asns": [64999], "prefix": "5.9.8.0/24"}
    assert routing.lookup("2a01:4f8:1::1")["asns"] == [24940]
    assert routing.lookup("94.130.1.1") == {"asns": [], "prefix": ""}
    assert routing.prefixes(64997) == routing.prefixes(64996) == routing.prefixes(64995) == []
    st = routing.status()
    assert st["active"] and st["error"] is None and st["prefixes"] == 3300 + 4


def test_sources_use_the_table_and_fall_back_to_ripestat(jsonl, monkeypatch):
    calls = []
    monkeypatch.setattr(sources, "_ripe", lambda ep, res, timeout=60: calls.append((ep, res)) or
                        ({"prefixes": [{"prefix": "192.0.2.0/24"}]} if ep == "announced-prefixes" else {"asns": [64512], "prefix": "192.0.2.0/24"}))
    assert sources.asn_prefixes(24940) == ["192.0.2.0/24"]          # no table yet: RIPEstat
    load(jsonl)
    calls.clear()
    assert sources.asn_prefixes(24940) == ["2a01:4f8::/32", "5.9.0.0/16"]
    assert sources.ip_info("5.9.8.7")["asns"] == [64999]
    assert calls == []
    db.put("routes_updated", 1.0)                                     # too old: RIPEstat again
    assert sources.asn_prefixes(64512, use_cache=False) == ["192.0.2.0/24"] and calls


def test_implausible_table_is_rejected_and_the_old_one_stays(jsonl, tmp_path):
    load(jsonl)
    small = tmp_path / "small.jsonl"
    table(small, v4=1000, v6=300)
    with pytest.raises(routing.RoutingError, match="implausible"):
        routing.refresh(download=lambda p: p.write_bytes(small.read_bytes()))
    assert routing.prefixes(24940) == ["2a01:4f8::/32", "5.9.0.0/16"]
    assert "implausible" in routing.status()["error"]
    assert not list(db.DATA_DIR.glob("routes.*.new")) and not list(db.DATA_DIR.glob("*.part"))


def test_failed_download_keeps_the_table(jsonl):
    load(jsonl)

    def broken(p):
        raise sources.SourceError("https://bgp.tools/table.jsonl: response larger than 256 MB")
    with pytest.raises(routing.RoutingError):
        routing.refresh(download=broken)
    assert routing.fresh() and routing.lookup("5.9.0.1")["asns"] == [24940, 64998]


def test_readers_switch_to_a_new_table(jsonl, tmp_path):
    load(jsonl)
    seen = []
    t = threading.Thread(target=lambda: seen.append(routing.lookup("5.9.8.7")))  # a connection in another thread
    t.start()
    t.join()
    assert routing.lookup("5.9.8.7")["asns"] == [64999]
    moved = tmp_path / "moved.jsonl"
    table(moved, [{"CIDR": "5.9.8.0/24", "ASN": 64990, "Hits": 3000}])
    routing.refresh(download=lambda p: p.write_bytes(moved.read_bytes()))
    assert routing.lookup("5.9.8.7")["asns"] == [64990]               # same thread, reopened after the swap
    assert seen[0]["asns"] == [64999]


def test_scheduler_refreshes_daily_and_retries_hourly(monkeypatch):
    now = [1_000_000.0]
    monkeypatch.setattr(routing.time, "time", lambda: now[0])
    assert routing.due()
    db.put("routes_tried", now[0])
    assert not routing.due()                      # just failed: wait an hour
    now[0] += 3601
    assert routing.due()
    db.put("routes_updated", now[0])
    now[0] += 23 * 3600
    assert not routing.due()
    now[0] += 2 * 3600
    assert routing.due()
