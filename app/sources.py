"""Externe Datenquellen: RIPEstat, bgp.tools (ASN-Namen), Spamhaus ASN-DROP, VPN-Serverlisten."""
import csv
import io
import ipaddress
import json
import os
import socket
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

from . import db

USER_AGENT = os.environ.get("USER_AGENT", "asn-blocker (+https://github.com/larosen/asn-blocker)")
RIPE = "https://stat.ripe.net/data"
RIPE_APP = "asn-blocker"
PREFIX_TTL = 6 * 3600
PROVIDER_TTL = 3600
CONTINENTS = json.loads((Path(__file__).parent / "data" / "continents.json").read_text())


class SourceError(RuntimeError):
    pass


def http_get(url, params=None, timeout=60, as_text=False):
    last = None
    for _ in range(3):
        try:
            r = httpx.get(url, params=params, timeout=timeout, follow_redirects=True,
                          headers={"User-Agent": USER_AGENT})
            r.raise_for_status()
            return r.text if as_text else r.json()
        except (httpx.HTTPError, ValueError) as e:
            last = e
    raise SourceError(f"{url}: {last}")


def _ripe(endpoint, resource, timeout=60):
    return http_get(f"{RIPE}/{endpoint}/data.json", {"resource": resource, "sourceapp": RIPE_APP}, timeout).get("data", {})


# --- ASN-Namen (lokal, fuer Suche) ---------------------------------------------------------

def refresh_asn_names():
    """bgp.tools/asns.csv (~5 MB) in SQLite laden. Spalten: asn,name,class,cc"""
    text = http_get("https://bgp.tools/asns.csv", timeout=120, as_text=True)
    rows = []
    for r in csv.DictReader(io.StringIO(text)):
        n = str(r.get("asn", "")).upper().removeprefix("AS")
        if n.isdigit():
            rows.append((int(n), r.get("name") or "", r.get("class") or "", r.get("cc") or ""))
    if len(rows) < 10000:
        raise SourceError(f"bgp.tools asns.csv unplausibel ({len(rows)} Zeilen)")
    with db.tx() as c:
        c.execute("DELETE FROM asn_names")
        c.executemany("INSERT INTO asn_names VALUES(?,?,?,?)", rows)
        db.put("asn_names_updated", __import__("time").time(), c)
    return len(rows)


def search_asn(query, limit=25):
    q = query.strip()
    if not q:
        return []
    digits = q.upper().removeprefix("AS")
    have_local = db.q1("SELECT 1 AS x FROM asn_names LIMIT 1")
    if digits.isdigit():
        rows = db.q("SELECT asn,name,class,cc FROM asn_names WHERE asn=? OR CAST(asn AS TEXT) LIKE ? "
                    "ORDER BY asn=? DESC, asn LIMIT ?", (int(digits), digits + "%", int(digits), limit))
        if rows or have_local:
            return rows
        d = _ripe("as-overview", f"AS{digits}", 20)
        return [{"asn": int(digits), "name": d.get("holder") or "", "class": "", "cc": ""}] if d.get("holder") else []
    if have_local:
        like = f"%{q}%"
        return db.q("SELECT asn,name,class,cc FROM asn_names WHERE name LIKE ? "
                    "ORDER BY name LIKE ? DESC, length(name), asn LIMIT ?", (like, q + "%", limit))
    data = http_get(f"{RIPE}/searchcomplete/data.json", {"resource": q, "sourceapp": RIPE_APP}, 20)
    out = []
    for cat in data.get("data", {}).get("categories", []):
        if cat.get("category") == "ASNs":
            for s in cat.get("suggestions", []):
                v = str(s.get("value", "")).upper().removeprefix("AS")
                if v.isdigit():
                    out.append({"asn": int(v), "name": s.get("description") or s.get("label") or "", "class": "", "cc": ""})
    return out[:limit]


def asn_name(asn):
    r = db.q1("SELECT name FROM asn_names WHERE asn=?", (asn,))
    return r["name"] if r else ""


# --- Prefixe ------------------------------------------------------------------------------------

def asn_prefixes(asn, use_cache=True):
    """Alle announced Prefixe (v4+v6) eines ASN, gecacht. Wirft SourceError bei ungueltiger Antwort."""
    key = f"prefixes:{asn}"
    if use_cache:
        hit = db.cache_get(key, PREFIX_TTL)
        if hit is not None:
            return hit
    prefixes = _ripe("announced-prefixes", f"AS{asn}").get("prefixes")
    if prefixes is None:
        raise SourceError(f"AS{asn}: ungueltige Antwort von RIPEstat")
    out = sorted({p["prefix"] for p in prefixes})
    db.cache_put(key, out)
    return out


def prefixes_many(asns, use_cache=True):
    """Parallel, max. 4 gleichzeitige Anfragen an RIPEstat."""
    asns = list(asns)
    with ThreadPoolExecutor(4) as ex:
        return dict(zip(asns, ex.map(lambda a: asn_prefixes(a, use_cache), asns), strict=True))


def ip_info(ip):
    key = f"ipinfo:{ip}"
    hit = db.cache_get(key, 86400)
    if hit is not None:
        return hit
    d = _ripe("network-info", ip, 20)
    out = {"asns": [int(a) for a in d.get("asns", []) if str(a).isdigit()], "prefix": d.get("prefix")}
    db.cache_put(key, out)
    return out


def spamhaus_asndrop(use_cache=True):
    """NDJSON: {"asn":..., "asname":..., "cc":...} je Zeile, letzte Zeile Metadaten."""
    if use_cache:
        hit = db.cache_get("spamhaus_asndrop", PREFIX_TTL)
        if hit is not None:
            return hit
    text = http_get("https://www.spamhaus.org/drop/asndrop.json", timeout=60, as_text=True)
    out = []
    for line in text.splitlines():
        try:
            o = json.loads(line)
        except ValueError:
            continue
        if isinstance(o.get("asn"), int):
            out.append({"asn": o["asn"], "name": o.get("asname", ""), "cc": o.get("cc", "")})
    if not out:
        raise SourceError("Spamhaus ASN-DROP: leere Liste")
    db.cache_put("spamhaus_asndrop", out)
    return out


# --- VPN-Anbieter ---------------------------------------------------------------------------------
# fetch() liefert [(country_code, country_name, ip_oder_hostname)]. IPs werden erst fuer die
# ausgewaehlten Laender aufgeloest und auf oeffentliche Adressen gefiltert.

def _public_ip(v):
    try:
        a = ipaddress.ip_address(str(v).strip())
    except ValueError:
        return None
    return str(a) if a.is_global else None


class Provider:
    id = name = note = ""
    exit_asn = None  # bekannter ASN der Exit-IPs, als Hinweis in der UI

    def fetch(self):
        raise NotImplementedError

    def entries(self):
        key = f"vpn:{self.id}"
        hit = db.cache_get(key, PROVIDER_TTL)
        if hit is None:
            hit = [list(e) for e in self.fetch() if e[0] and e[2]]
            if not hit:
                raise SourceError(f"{self.name}: leere Serverliste")
            db.cache_put(key, hit)
        return hit

    def countries(self):
        acc = {}
        for cc, name, _ in self.entries():
            c = acc.setdefault(cc.upper(), {"code": cc.upper(), "name": name, "servers": 0,
                                            "continent": CONTINENTS.get(cc.upper(), "")})
            c["servers"] += 1
        return sorted(acc.values(), key=lambda c: c["name"])

    def ips(self, code):
        vals = [v for cc, _, v in self.entries() if cc.upper() == code]
        hosts = [v for v in vals if _public_ip(v) is None and any(ch.isalpha() for ch in v)]
        ips = {_public_ip(v) for v in vals} - {None}
        if hosts:
            with ThreadPoolExecutor(16) as ex:
                for res in ex.map(_resolve, hosts):
                    ips.update(filter(None, map(_public_ip, res)))
            if not ips:
                raise SourceError(f"{self.name} {code}: DNS-Auflösung für {len(hosts)} Hostnamen fehlgeschlagen "
                                  f"(z. B. {hosts[0]}) – hat der Container DNS?")
        return sorted(ips)


def _resolve(host):
    try:
        return [i[4][0] for i in socket.getaddrinfo(host, None)]
    except OSError:
        return []


class NordVPN(Provider):
    id, name, exit_asn = "nordvpn", "NordVPN", 207137
    note = "api.nordvpn.com – Einwahl-IPs; Exit-IPs liegen meist in AS207137 (PacketHub)."

    def fetch(self):
        servers = http_get("https://api.nordvpn.com/v1/servers", {"limit": 20000}, timeout=180)
        out = []
        for s in servers:
            loc = (s.get("locations") or [{}])[0].get("country") or {}
            cc, name = loc.get("code", ""), loc.get("name", "")
            for v in [s.get("station")] + [(i.get("ip") or {}).get("ip") for i in s.get("ips") or []]:
                if v:
                    out.append((cc, name, v))
        return out


class Mullvad(Provider):
    id, name = "mullvad", "Mullvad"
    note = "api.mullvad.net/www/relays/all/"

    def fetch(self):
        return [(r.get("country_code", ""), r.get("country_name", ""), v)
                for r in http_get("https://api.mullvad.net/www/relays/all/")
                for v in (r.get("ipv4_addr_in"), r.get("ipv6_addr_in")) if v]


class Surfshark(Provider):
    id, name = "surfshark", "Surfshark"
    note = "api.surfshark.com – nur Hostnamen, IPs per DNS aufgelöst."

    def fetch(self):
        return [(c.get("countryCode", ""), c.get("country", ""), c.get("connectionName"))
                for c in http_get("https://api.surfshark.com/v4/server/clusters/generic")]


class IVPN(Provider):
    id, name = "ivpn", "IVPN"
    note = "api.ivpn.net/v5/servers.json"

    def fetch(self):
        data = http_get("https://api.ivpn.net/v5/servers.json")
        out = []
        for proto in ("wireguard", "openvpn"):
            for g in data.get(proto, []):
                for h in g.get("hosts", []):
                    out.append((g.get("country_code", ""), g.get("country", ""), h.get("host")))
        return out


class PIA(Provider):
    id, name = "pia", "Private Internet Access"
    note = "serverlist.piaservers.net (JSON + Signatur)"

    def fetch(self):
        text = http_get("https://serverlist.piaservers.net/vpninfo/servers/v6", as_text=True)
        data = json.loads(text.split("\n", 1)[0])
        out = []
        for r in data.get("regions", []):
            for group in (r.get("servers") or {}).values():
                for s in group:
                    out.append((r.get("country", ""), r.get("name", ""), s.get("ip")))
        return out


class AirVPN(Provider):
    id, name = "airvpn", "AirVPN"
    note = "airvpn.org/api/status/"

    def fetch(self):
        out = []
        for s in http_get("https://airvpn.org/api/status/").get("servers", []):
            for k, v in s.items():
                if k.startswith(("ip_v4_in", "ip_v6_in")) and v:
                    out.append((s.get("country_code", ""), s.get("country_name", ""), v))
        return out


PROVIDERS = {p.id: p for p in (NordVPN(), Mullvad(), Surfshark(), IVPN(), PIA(), AirVPN())}
