import json

from app import db
from app.store import exemptions, rules, vpn


def test_prototype_config_is_imported(tmp_path):
    (tmp_path / "config.json").write_text(json.dumps({
        "asns": [{"asn": 24940, "name": "HETZNER", "action": "ban", "note": "x"}],
        "vpn_whitelist": [{"provider": "nordvpn", "country": "DE"}],
        "exempt_asns": [207137], "manual_exempt": ["198.51.100.7"], "widen_vpn_ips": True, "include_ipv6": False}))
    db._migrate_prototype()
    assert rules.actions() == {24940: "ban"}
    assert [(e["kind"], e["value"]) for e in exemptions.listing()] == [("asn", "207137"), ("cidr", "198.51.100.7")]
    assert vpn.selections() == {"nordvpn": ["DE"]}
    assert db.get("vpn_modes")["nordvpn"] == "net"
    db._migrate_prototype()  # idempotent
    assert rules.count() == 1
