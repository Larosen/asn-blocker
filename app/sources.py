"""External data sources: RIPEstat, bgp.tools (ASN names), Spamhaus ASN-DROP, VPN server lists."""
import csv
import io
import ipaddress
import json
import os
import re
import socket
import time
import zipfile
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
_COUNTRIES = json.loads((Path(__file__).parent / "data" / "country_names.json").read_text())
COUNTRY_CODES, COUNTRY_NAMES = _COUNTRIES["codes"], _COUNTRIES["names"]  # lower-case name -> ISO-2, ISO-2 -> name


class SourceError(RuntimeError):
    pass


MAX_BYTES = 64 * 2**20  # largest real response: NordVPN server list, ~27 MB


def _fetch(url, params, timeout):
    """GET with a hard size cap (after decompression), an overall deadline and redirects only to https on the
    same host."""
    deadline = time.monotonic() + timeout
    host = httpx.URL(url).host
    for _ in range(4):
        with httpx.stream("GET", url, params=params, timeout=min(timeout, 30), follow_redirects=False,
                          headers={"User-Agent": USER_AGENT}) as r:
            if r.is_redirect:
                nxt = r.url.join(r.headers.get("location", ""))
                if nxt.scheme != "https" or nxt.host != host:
                    raise httpx.HTTPError(f"refused redirect to {nxt.scheme}://{nxt.host}")
                url, params = str(nxt), None
                continue
            r.raise_for_status()
            buf = bytearray()
            for chunk in r.iter_bytes():
                buf += chunk
                if len(buf) > MAX_BYTES:
                    raise httpx.HTTPError(f"response larger than {MAX_BYTES // 2**20} MB")
                if time.monotonic() > deadline:
                    raise httpx.HTTPError(f"no complete response within {timeout} s")
            return bytes(buf), r.encoding or "utf-8"
    raise httpx.HTTPError("too many redirects")


def http_get(url, params=None, timeout=60, as_text=False):
    last = None
    for _ in range(3):
        try:
            body, enc = _fetch(url, params, timeout)
            return body.decode(enc, errors="replace") if as_text else json.loads(body)
        except (httpx.HTTPError, ValueError) as e:
            last = e
    raise SourceError(f"{url}: {last}")


def _ripe(endpoint, resource, timeout=60):
    return http_get(f"{RIPE}/{endpoint}/data.json", {"resource": resource, "sourceapp": RIPE_APP}, timeout).get("data", {})


# --- ASN names (local, for search) -------------------------------------------------------

def refresh_asn_names():
    """Load bgp.tools/asns.csv (~5 MB) into SQLite. Columns: asn,name,class,cc"""
    text = http_get("https://bgp.tools/asns.csv", timeout=120, as_text=True)
    rows = []
    for r in csv.DictReader(io.StringIO(text)):
        n = str(r.get("asn", "")).upper().removeprefix("AS")
        if n.isdigit():
            rows.append((int(n), r.get("name") or "", r.get("class") or "", r.get("cc") or ""))
    if len(rows) < 10000:
        raise SourceError(f"bgp.tools asns.csv implausible ({len(rows)} rows)")
    with db.tx() as c:
        c.execute("DELETE FROM asn_names")
        c.executemany("INSERT INTO asn_names VALUES(?,?,?,?)", rows)
        db.put("asn_names_updated", time.time(), c)
    return len(rows)


def search_asn(query, limit=25):
    q = query.strip()
    if not q:
        return []
    digits = q.upper().removeprefix("AS")
    have_local = db.q1("SELECT 1 AS x FROM asn_names LIMIT 1")
    if re.fullmatch(r"[0-9]{1,10}", digits) and int(digits) < 2**32:
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


# --- Prefixes ----------------------------------------------------------------------------------

def asn_prefixes(asn, use_cache=True):
    """All announced prefixes (v4+v6) of an ASN, cached. Raises SourceError on an invalid response."""
    key = f"prefixes:{asn}"
    if use_cache:
        hit = db.cache_get(key, PREFIX_TTL)
        if hit is not None:
            return hit
    prefixes = _ripe("announced-prefixes", f"AS{asn}").get("prefixes")
    if prefixes is None:
        raise SourceError(f"AS{asn}: invalid response from RIPEstat")
    if not isinstance(prefixes, list):
        raise SourceError(f"AS{asn}: invalid response from RIPEstat")
    out = sorted({p["prefix"] for p in prefixes if isinstance(p, dict) and isinstance(p.get("prefix"), str)})
    db.cache_put(key, out)
    return out


def prefixes_many(asns, use_cache=True):
    """Parallel, at most 4 concurrent requests to RIPEstat."""
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


def ip_holder(ip):
    """Registered holder of an address block (whois via RIPEstat, any registry), cached for a day."""
    key = f"holder:{ip}"
    hit = db.cache_get(key, 86400)
    if hit is not None:
        return hit
    d = _ripe("whois", ip, 20)
    found = {}
    for rec in d.get("records") or []:
        for r in rec if isinstance(rec, list) else []:
            if isinstance(r, dict) and str(r.get("key", "")).lower() in ("organization", "orgname", "org-name", "descr", "netname"):
                found.setdefault(str(r["key"]).lower(), str(r.get("value", ""))[:200])
    out = next((found[k] for k in ("organization", "orgname", "org-name", "descr", "netname") if found.get(k)), "")
    db.cache_put(key, out)
    return out


def spamhaus_asndrop(use_cache=True):
    """NDJSON: {"asn":..., "asname":..., "cc":...} per line, last line is metadata."""
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
        if isinstance(o, dict) and type(o.get("asn")) is int and 0 < o["asn"] < 2**32:
            out.append({"asn": o["asn"], "name": o.get("asname", ""), "cc": o.get("cc", "")})
    if not out or len(out) > 20000:
        raise SourceError(f"Spamhaus ASN-DROP: implausible list ({len(out)} entries)")
    db.cache_put("spamhaus_asndrop", out)
    return out


# --- VPN providers -------------------------------------------------------------------------------
# fetch() returns [(country_code, country_name, ip_or_hostname)]. IPs are resolved only for the
# selected countries and filtered to public addresses.

def _public_ip(v):
    try:
        a = ipaddress.ip_address(str(v).strip())
    except ValueError:
        return None
    return str(a) if a.is_global else None


class Provider:
    id = name = note = ""
    exit_asn = None  # known ASN of the exit IPs, shown as a hint in the UI

    def fetch(self):
        raise NotImplementedError

    def entries(self):
        key = f"vpn:{self.id}"
        hit = db.cache_get(key, PROVIDER_TTL)
        if hit is None:
            hit = [[str(e[0]), str(e[1]), str(e[2])] for e in self.fetch() if e[0] and e[2]]
            if not hit:
                raise SourceError(f"{self.name}: empty server list")
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
                raise SourceError(f"{self.name} {code}: DNS resolution failed for {len(hosts)} hostnames "
                                  f"(e.g. {hosts[0]}) – does the container have DNS?")
        return sorted(ips)


def _resolve(host):
    try:
        return [i[4][0] for i in socket.getaddrinfo(str(host), None)]
    except (OSError, UnicodeError, ValueError):
        return []


class NordVPN(Provider):
    id, name, exit_asn = "nordvpn", "NordVPN", 207137
    note = "api.nordvpn.com – entry IPs; exit IPs are usually in AS207137 (PacketHub)."

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
    note = "api.surfshark.com – hostnames only, IPs resolved via DNS."

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
    note = "serverlist.piaservers.net (JSON + signature)"

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


def _cc(*names):
    """ISO-2 for free-text country names such as 'USA Austin', 'Korea (South)' or 'Hong' + 'Kong'."""
    for name in names:
        words = re.sub(r"\s*\(.*?\)", "", str(name or "")).strip().lower().split()
        for n in range(len(words), 0, -1):
            code = COUNTRY_CODES.get(" ".join(words[:n]))
            if code:
                return code
    return ""


def _zip_names(url, timeout=120):
    """File names inside a remote zip. Only the directory is read – nothing is decompressed."""
    try:
        with zipfile.ZipFile(io.BytesIO(_fetch(url, None, timeout)[0])) as z:
            return z.namelist()
    except (httpx.HTTPError, zipfile.BadZipFile) as e:
        raise SourceError(f"{url}: {e}") from e


class Windscribe(Provider):
    id, name = "windscribe", "Windscribe"
    note = "assets.windscribe.com – connection IPs of every node (three per node)."

    def fetch(self):
        out = []
        for loc in http_get("https://assets.windscribe.com/serverlist/mob-v2/1/0").get("data", []):
            cc = str(loc.get("country_code", "")).upper()
            for g in loc.get("groups") or []:
                for n in g.get("nodes") or []:
                    out += [(cc, COUNTRY_NAMES.get(cc, cc), n[k]) for k in ("ip", "ip2", "ip3") if n.get(k)]
        return out


class OVPN(Provider):
    id, name = "ovpn", "OVPN"
    note = "ovpn.com client API."

    def fetch(self):
        return [(str(d.get("country", "")).upper(), d.get("country_name", ""), s.get("ip"))
                for d in http_get("https://www.ovpn.com/v2/api/client/entry").get("datacenters", [])
                for s in d.get("servers") or []]


class Privado(Provider):
    id, name = "privado", "PrivadoVPN"
    note = "privadovpn.com server export."

    def fetch(self):
        out = []
        for s in http_get("https://privadovpn.com/apps/servers_export.json").get("servers", []):
            cc = _cc(s.get("country"))
            out.append((cc, COUNTRY_NAMES.get(cc, ""), s.get("ip")))
        return out


class IPVanish(Provider):
    id, name = "ipvanish", "IPVanish"
    note = "configs.ipvanish.com OpenVPN configs (~5 MB) – hostnames, IPs resolved via DNS."

    def fetch(self):
        out = []
        for f in _zip_names("https://configs.ipvanish.com/openvpn/v2.6.0-0/configs.zip"):
            m = re.match(r"ipvanish-([A-Z]{2})-.*-([a-z0-9]+-[a-z]\d+)\.ovpn$", f)
            if m:  # ipvanish-DE-Frankfurt-fra-a01.ovpn -> fra-a01.ipvanish.com
                out.append((m[1], COUNTRY_NAMES.get(m[1], m[1]), f"{m[2]}.ipvanish.com"))
        return out


class ProtonVPN(Provider):
    id, name = "protonvpn", "Proton VPN"
    note = ("Exit IPs from github.com/tn3w/ProtonVPN-IPs (third party, updated daily) – Proton's own API needs a "
            "login.")

    def fetch(self):
        data = http_get("https://raw.githubusercontent.com/tn3w/ProtonVPN-IPs/master/protonvpn_logicals.json")
        return [(str(lg.get("ExitCountry", "")).upper(), COUNTRY_NAMES.get(lg.get("ExitCountry", ""), ""), s.get("ExitIP"))
                for lg in data.get("LogicalServers", []) for s in lg.get("Servers") or []]


class Gluetun(Provider):
    """Providers without a public list of their own: server data collected by the gluetun project
    (github.com/qdm12/gluetun-servers, MIT), refreshed roughly monthly."""
    BASE = "https://raw.githubusercontent.com/qdm12/gluetun-servers/main/pkg/servers/"

    def __init__(self, id, name, file):
        self.id, self.name, self.file = id, name, file
        self.note = ("Server IPs collected by the gluetun project (third party, updated about monthly); "
                     "locations may be virtual.")

    def fetch(self):
        out = []
        for s in http_get(self.BASE + self.file.replace(" ", "%20") + ".json").get("servers", []):
            name = s.get("country") or s.get("region") or ""
            cc = _cc(name, f"{name} {s.get('city', '')}")
            out += [(cc, COUNTRY_NAMES.get(cc, name), ip) for ip in s.get("ips") or []]
        return out


PROVIDERS = {p.id: p for p in (
    NordVPN(), Mullvad(), Surfshark(), IVPN(), PIA(), AirVPN(), ProtonVPN(), Windscribe(), IPVanish(), Privado(),
    OVPN(),
    Gluetun("purevpn", "PureVPN", "purevpn"), Gluetun("expressvpn", "ExpressVPN", "expressvpn"),
    Gluetun("cyberghost", "CyberGhost", "cyberghost"), Gluetun("torguard", "TorGuard", "torguard"),
    Gluetun("privatevpn", "PrivateVPN", "privatevpn"), Gluetun("vyprvpn", "VyprVPN", "vyprvpn"),
    Gluetun("fastestvpn", "FastestVPN", "fastestvpn"), Gluetun("vpnunlimited", "VPN Unlimited", "vpn unlimited"),
    Gluetun("vpnsecure", "VPNSecure", "vpnsecure"),
)}
