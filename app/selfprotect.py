"""Self-protection: prevents you from locking yourself out via SSH (or web).

- Protected IPs and ASNs (table `protected`) are cut out of all blocks on every run,
  and no rules are accepted for protected ASNs.
- If the host's /var/run/utmp is mounted (HOST_UTMP), the IPs of all currently logged-in
  SSH sessions are protected automatically as well.
"""
import ipaddress
import os
import struct
import time
from pathlib import Path

from . import db

HOST_UTMP = Path(os.environ.get("HOST_UTMP", "/host/utmp"))

# struct utmp (glibc, Linux x86_64 and aarch64): 384 bytes
_UTMP = struct.Struct("<hxxi32s4s32s256shhiii4i20x")
USER_PROCESS = 7


def _cstr(b: bytes) -> str:
    return b.split(b"\0", 1)[0].decode(errors="replace")


def _addr(host: str, addr_v6) -> str | None:
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if any(addr_v6[1:]):
        raw = struct.pack("<4i", *addr_v6)
        return str(ipaddress.IPv6Address(raw))
    if addr_v6[0]:
        return str(ipaddress.IPv4Address(struct.pack("<i", addr_v6[0])))
    return None


def ssh_sessions(path: Path | None = None):
    """Reads utmp and returns ([{ip,user,line,since}], status). status: 'ok' | 'not mounted' | error."""
    path = path or HOST_UTMP
    if not path.exists():
        return [], "not mounted"
    try:
        data = path.read_bytes()
    except OSError as e:
        return [], f"not readable: {e}"
    out, seen = [], set()
    for off in range(0, len(data) - _UTMP.size + 1, _UTMP.size):
        typ, _pid, line, _id, user, host, _e1, _e2, _sess, sec, _usec, *addr = _UTMP.unpack_from(data, off)
        if typ != USER_PROCESS:
            continue
        ip = _addr(_cstr(host), addr)
        if not ip or not ipaddress.ip_address(ip).is_global:
            continue  # local logins / console
        key = (ip, _cstr(line))
        if key in seen:
            continue
        seen.add(key)
        out.append({"ip": ip, "user": _cstr(user), "line": _cstr(line), "since": sec})
    return out, "ok"


def protected():
    return db.q("SELECT kind, value, note, created FROM protected ORDER BY kind, value")


def protected_asns():
    return {int(r["value"]) for r in db.q("SELECT value FROM protected WHERE kind='asn'")}


def add(kind: str, value: str, note: str = ""):
    with db.tx() as c:
        c.execute("INSERT OR REPLACE INTO protected(kind,value,note,created) VALUES(?,?,?,?)", (kind, value, note, time.time()))
        db.bump_rev(c)


def protect_ip(ip: str, note: str, with_asn: bool = True):
    """Protects an IP and (optionally) its ASN. Returns the protected ASNs."""
    from . import sources

    ip = str(ipaddress.ip_address(ip))
    add("ip", ip, note)
    asns = []
    if with_asn and ipaddress.ip_address(ip).is_global:
        info = sources.ip_info(ip)
        for asn in info["asns"]:
            add("asn", str(asn), f"{note} ({ip})")
            asns.append(asn)
    return asns
