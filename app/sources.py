"""Datenquellen: RIPEstat (ASN-Suche, Prefixe) und oeffentliche VPN-Serverlisten."""
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

import httpx

from .config import USER_AGENT

RIPE = "https://stat.ripe.net/data"


class SourceError(RuntimeError):
    pass


def _get(url: str, params: dict | None = None, timeout: float = 60):
    last = None
    for _ in range(3):
        try:
            r = httpx.get(url, params=params, timeout=timeout, headers={"User-Agent": USER_AGENT},
                          follow_redirects=True)
            r.raise_for_status()
            return r.json()
        except (httpx.HTTPError, ValueError) as e:
            last = e
    raise SourceError(f"{url}: {last}")


# --- ASN ----------------------------------------------------------------------

def search_asn(query: str) -> list[dict]:
    q = query.strip()
    if not q:
        return []
    digits = q.upper().removeprefix("AS")
    if digits.isdigit():
        return [asn_overview(int(digits))]
    data = _get(f"{RIPE}/searchcomplete/data.json", {"resource": q}, timeout=20)
    out = []
    for cat in data.get("data", {}).get("categories", []):
        if cat.get("category") != "ASNs":
            continue
        for s in cat.get("suggestions", []):
            val = str(s.get("value", "")).upper().removeprefix("AS")
            if val.isdigit():
                out.append({"asn": int(val), "name": s.get("description") or s.get("label") or ""})
    return out


def asn_overview(asn: int) -> dict:
    data = _get(f"{RIPE}/as-overview/data.json", {"resource": f"AS{asn}"}, timeout=20).get("data", {})
    return {"asn": asn, "name": data.get("holder") or "", "announced": bool(data.get("announced"))}


def asn_prefixes(asn: int, ipv6: bool = False) -> list[str]:
    data = _get(f"{RIPE}/announced-prefixes/data.json", {"resource": f"AS{asn}"})
    prefixes = data.get("data", {}).get("prefixes")
    if prefixes is None:
        raise SourceError(f"AS{asn}: ungueltige Antwort von RIPEstat")
    return [p["prefix"] for p in prefixes if ipv6 or ":" not in p["prefix"]]


# --- VPN-Anbieter ---------------------------------------------------------------
# Jeder Provider liefert countries() -> [{code, name, servers}] und ips(code) -> [ip]

def _valid_ips(values) -> list[str]:
    out = set()
    for v in values:
        try:
            out.add(str(ipaddress.ip_address(str(v).strip())))
        except ValueError:
            pass
    return sorted(out)


class NordVPN:
    id, name = "nordvpn", "NordVPN"
    note = "Offizielle API api.nordvpn.com (station + ips[])."
    API = "https://api.nordvpn.com/v1"

    def _countries_raw(self):
        return _get(f"{self.API}/servers/countries")

    def countries(self):
        return sorted(({"code": c["code"], "name": c["name"], "servers": c.get("serverCount")}
                       for c in self._countries_raw()), key=lambda c: c["name"])

    def ips(self, code):
        cid = next((c["id"] for c in self._countries_raw() if c["code"] == code), None)
        if cid is None:
            raise SourceError(f"NordVPN: unbekanntes Land {code}")
        servers = _get(f"{self.API}/servers", {"filters[country_id]": cid, "limit": 9999}, timeout=180)
        if not isinstance(servers, list) or not servers:
            raise SourceError(f"NordVPN: leere Serverliste fuer {code}")
        vals = []
        for s in servers:
            vals.append(s.get("station"))
            vals.extend((i.get("ip") or {}).get("ip") for i in s.get("ips") or [])
        return _valid_ips(vals)


class Mullvad:
    id, name = "mullvad", "Mullvad"
    note = "Offizielle Relay-Liste api.mullvad.net/www/relays/all/."
    URL = "https://api.mullvad.net/www/relays/all/"

    def _relays(self):
        data = _get(self.URL)
        if not isinstance(data, list) or not data:
            raise SourceError("Mullvad: leere Relay-Liste")
        return data

    def countries(self):
        acc = {}
        for r in self._relays():
            c = acc.setdefault(r["country_code"].upper(), {"code": r["country_code"].upper(),
                                                           "name": r.get("country_name", ""), "servers": 0})
            c["servers"] += 1
        return sorted(acc.values(), key=lambda c: c["name"])

    def ips(self, code):
        vals = []
        for r in self._relays():
            if r["country_code"].upper() == code:
                vals += [r.get("ipv4_addr_in"), r.get("ipv6_addr_in")]
        return _valid_ips(v for v in vals if v)


class Surfshark:
    id, name = "surfshark", "Surfshark"
    note = "Offizielle Cluster-Liste; IPs werden per DNS der Server-Hostnamen aufgeloest."
    URL = "https://api.surfshark.com/v4/server/clusters/generic"

    def _clusters(self):
        data = _get(self.URL)
        if not isinstance(data, list) or not data:
            raise SourceError("Surfshark: leere Cluster-Liste")
        return data

    def countries(self):
        acc = {}
        for c in self._clusters():
            e = acc.setdefault(c["countryCode"].upper(), {"code": c["countryCode"].upper(),
                                                          "name": c.get("country", ""), "servers": 0})
            e["servers"] += 1
        return sorted(acc.values(), key=lambda c: c["name"])

    def ips(self, code):
        hosts = [c["connectionName"] for c in self._clusters()
                 if c["countryCode"].upper() == code and c.get("connectionName")]

        def resolve(h):
            try:
                return [i[4][0] for i in socket.getaddrinfo(h, None)]
            except OSError:
                return []

        with ThreadPoolExecutor(16) as ex:
            ips = _valid_ips(ip for res in ex.map(resolve, hosts) for ip in res)
        if hosts and not ips:
            raise SourceError(f"Surfshark: keine DNS-Aufloesung fuer {code}")
        return ips


PROVIDERS = {p.id: p for p in (NordVPN(), Mullvad(), Surfshark())}
