"""The unified policy model: precedence between overlapping policies, and the explanation per IP."""
import pytest

from app import engine, policy, selfprotect, sources
from app.store import exemptions, lists, policies, rules, vpn

PREFIXES = {1: ["11.0.0.0/16"], 2: ["11.0.0.0/8"], 3: ["11.0.7.0/24"], 5: ["11.5.0.0/16"], 9: ["11.9.0.0/16"]}


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setattr(sources, "asn_prefixes", lambda a, use_cache=True: PREFIXES[a])
    monkeypatch.setattr(sources, "prefixes_many", lambda asns, use_cache=True: {a: PREFIXES[a] for a in asns})
    monkeypatch.setattr(sources, "ip_info", lambda ip: {"asns": [9] if ip.startswith("11.9.") else [2], "prefix": ""})
    monkeypatch.setattr(sources, "spamhaus_asndrop", lambda use_cache=True: [{"asn": 9, "name": "BAD", "cc": ""}])
    monkeypatch.setattr(selfprotect, "ssh_sessions", lambda *a: ([{"ip": "11.0.9.9", "user": "root", "line": "pts/0"}], "ok"))
    monkeypatch.setattr(sources, "_public_ip", lambda v: v)

    class P(sources.Provider):
        id, name = "nordvpn", "NordVPN"

        def fetch(self):
            return [("DE", "Germany", "11.0.5.9")]
    monkeypatch.setitem(sources.PROVIDERS, "nordvpn", P())
    monkeypatch.setattr(policy.ipaddress.IPv4Address, "is_global", property(lambda self: True))  # test networks count as public


def why(ip):
    e = policy.explain(ip)
    return e["decision"], [(m["source"], m["value"], m["effect"], m["wins"]) for m in e["matches"]], e


def test_block_rules_and_their_precedence():
    rules.upsert([{"asn": 1, "action": "ban"}, {"asn": 2, "action": "captcha"}])
    assert why("11.0.1.1")[:2] == ("ban", [("asn", "1", "ban", True), ("asn", "2", "captcha", False)])
    assert why("11.200.0.1")[:2] == ("captcha", [("asn", "2", "captcha", True)])
    assert why("12.0.0.1")[:2] == (None, [])


def test_allow_beats_everything_and_names_the_exemption():
    rules.upsert([{"asn": 1, "action": "ban"}])
    exemptions.add([("asn", "3", "cdn")])
    vpn.add([("nordvpn", "DE")])
    assert why("11.0.7.1")[:2] == ("allow", [("asn", "3", "allow", True), ("asn", "1", "ban", False)])
    d, m, _ = why("11.0.5.9")
    assert d == "allow" and m[0][:3] == ("vpn", "nordvpn:DE", "allow")
    d, m, e = why("11.0.9.9")  # an active SSH session
    assert d == "allow" and e["implicit"] == ["SSH session root@pts/0"]


def test_cap_turns_a_ban_into_captcha_but_keeps_captcha():
    rules.upsert([{"asn": 2, "action": "ban"}])
    selfprotect.add("asn", "5", "home", "captcha")
    d, m, e = why("11.5.1.1")
    assert d == "captcha" and e["capped"] and m[0][:3] == ("asn", "5", "cap") and m[1][3]  # the ban wins, limited
    ranges, _ = engine.build(lambda _m: None)
    assert engine.status_of("11.5.1.1", ranges) == "captcha" and engine.status_of("11.6.1.1", ranges) == "ban"


def test_locked_allow_wins_over_an_unlocked_one():
    exemptions.add([("cidr", "11.0.1.0/24", "partner")])
    selfprotect.add("ip", "11.0.1.5", "phone")
    _, m, _ = why("11.0.1.5")
    assert [(x[0], x[3]) for x in m] == [("ip", True), ("cidr", False)]


def test_lists_and_expired_policies():
    lists.set_spamhaus("ban")
    assert why("11.9.0.1")[:2] == ("ban", [("list", "spamhaus-asndrop", "ban", True)])
    rules.upsert([{"asn": 1, "action": "ban", "expires_at": 1.0}])  # long expired
    assert why("11.0.1.1")[0] is None


def test_evaluation_and_explanation_agree():
    rules.upsert([{"asn": 1, "action": "ban"}, {"asn": 2, "action": "captcha"}])
    exemptions.add([("asn", "3", ""), ("cidr", "11.1.0.0/16", "")])
    selfprotect.add("asn", "5", "", "captcha")
    lists.set_spamhaus("ban")
    ranges, _ = engine.build(lambda _m: None)
    for ip in ("11.0.1.1", "11.0.7.1", "11.1.2.3", "11.5.1.1", "11.9.0.1", "11.200.0.1", "11.0.9.9", "12.0.0.1"):
        d = policy.explain(ip)["decision"]
        assert engine.status_of(ip, ranges) == (None if d == "allow" else d), ip


def test_one_policy_per_kind_and_source():
    rules.upsert([{"asn": 1, "action": "ban"}])
    rules.upsert([{"asn": 1, "action": "captcha"}])         # replaces the block policy
    exemptions.add([("asn", "1", "")])                      # an exemption is a different kind: both exist
    selfprotect.add("asn", "1", "", "captcha")              # and so is protection
    assert sorted((p["effect"], p["locked"]) for p in policies.listing("asn", "1")) == [("allow", False), ("cap", True), ("captcha", False)]
    with pytest.raises(ValueError):
        policies.upsert([{"source": "asn", "value": 1, "effect": "block"}])


def test_sanity_counts_spamhaus_as_a_rule(monkeypatch):
    """With only Spamhaus enabled and no ranges computed, the run must stop instead of clearing every block."""
    lists.set_spamhaus("ban")
    monkeypatch.setattr(sources, "spamhaus_asndrop", lambda use_cache=True: [])
    with pytest.raises(engine.Blocked, match="0 ranges computed"):
        engine._sanity({"ban": [], "captcha": []})
