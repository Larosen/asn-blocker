import ipaddress as I

from app import netset


def n(x):
    return I.ip_network(x)


def test_subtract_carves_hole():
    r = netset.subtract([n("10.0.0.0/16")], [n("10.0.5.0/24")])
    assert n("10.0.5.0/24") not in r
    assert sum(x.num_addresses for x in r) == 65536 - 256
    assert not any(x.overlaps(n("10.0.5.0/24")) for x in r)


def test_subtract_full_cover_and_disjoint():
    assert netset.subtract([n("10.0.0.0/24")], [n("10.0.0.0/16")]) == []
    assert netset.subtract([n("10.0.0.0/24")], [n("192.168.0.0/16")]) == [n("10.0.0.0/24")]


def test_subtract_mixed_versions_and_many_exemptions():
    src = [n("10.0.0.0/8"), n("2001:db8::/32")]
    ex = [n(f"10.{i}.0.0/16") for i in range(0, 256, 2)] + [n("2001:db8:1::/48")]
    r = netset.subtract(src, ex)
    v4 = [x for x in r if x.version == 4]
    assert sum(x.num_addresses for x in v4) == 2**24 // 2
    assert not any(x.overlaps(n("2001:db8:1::/48")) for x in r)


def test_subtract_exemption_starting_before_source():
    r = netset.subtract([n("10.0.1.0/24")], [n("10.0.0.0/23")])
    assert r == []


def test_contains():
    assert netset.contains(["10.0.0.0/8", "192.168.0.0/16"], "10.1.2.3") == ["10.0.0.0/8"]
