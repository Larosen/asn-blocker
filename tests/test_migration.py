import json

from app import db


def test_prototype_config_is_imported(tmp_path):
    (tmp_path / "config.json").write_text(json.dumps({
        "asns": [{"asn": 24940, "name": "HETZNER", "action": "ban", "note": "x"}],
        "vpn_whitelist": [{"provider": "nordvpn", "country": "DE"}],
        "exempt_asns": [207137], "manual_exempt": ["198.51.100.7"], "widen_vpn_ips": True, "include_ipv6": False}))
    db._migrate_prototype()
    assert db.q1("SELECT action FROM asn_rules WHERE asn=24940")["action"] == "ban"
    assert db.q("SELECT kind, value FROM exemptions ORDER BY kind") == [{"kind": "asn", "value": "207137"}, {"kind": "cidr", "value": "198.51.100.7"}]
    assert db.get("vpn_modes")["nordvpn"] == "net"
    db._migrate_prototype()  # idempotent
    assert db.q1("SELECT count(*) n FROM asn_rules")["n"] == 1
