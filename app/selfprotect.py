"""Self-protection: prevents you from locking yourself out via SSH (or web).

- Protected IPs and ASNs (table `protected`) are cut out of all blocks on every run,
  and no rules are accepted for protected ASNs.
- If the host's session registry is mounted – systemd-logind's /run/systemd/sessions (HOST_SESSIONS) on current
  distributions, /var/run/utmp (HOST_UTMP) on older ones – the IPs of all active SSH sessions are protected
  automatically as well.
"""
import ipaddress
import os
import re
import struct
import time
from pathlib import Path

from . import db

HOST_UTMP = Path(os.environ.get("HOST_UTMP", "/host/utmp"))
# systemd-logind's session registry (/run/systemd/sessions): the only source on distributions without utmp
HOST_SESSIONS = Path(os.environ.get("HOST_SESSIONS", "/host/sessions"))

# struct utmp (glibc, Linux x86_64 and aarch64): 384 bytes
_UTMP = struct.Struct("<hxxi32s4s32s256shhiii4i20x")
USER_PROCESS = 7


def _cstr(b: bytes) -> str:
    return b.split(b"\0", 1)[0].decode(errors="replace")


def _canonical(a):
    return a.ipv4_mapped if a.version == 6 and a.ipv4_mapped else a


def _addr(host: str, addr_v6) -> str | None:
    """Only ut_addr_v6, which sshd fills in. ut_host is free text that local tools writing utmp (e.g. via
    libutempter) can set to anything – trusting it would let a local user exempt any IP."""
    if any(addr_v6[1:]):
        raw = struct.pack("<4i", *addr_v6)
        return str(_canonical(ipaddress.IPv6Address(raw)))
    if addr_v6[0]:
        return str(ipaddress.IPv4Address(struct.pack("<i", addr_v6[0])))
    return None


def _global_ip(host: str) -> str | None:
    try:
        a = _canonical(ipaddress.ip_address(host.strip().removeprefix("[").removesuffix("]")))
    except ValueError:
        return None
    return str(a) if a.is_global else None


def _utmp_sessions(path: Path):
    out = []
    data = path.read_bytes()
    for off in range(0, len(data) - _UTMP.size + 1, _UTMP.size):
        typ, _pid, line, _id, user, host, _e1, _e2, _sess, sec, _usec, *addr = _UTMP.unpack_from(data, off)
        if typ != USER_PROCESS:
            continue
        ip = _addr(_cstr(host), addr)
        if not ip or not ipaddress.ip_address(ip).is_global:
            continue  # local logins / console
        out.append({"ip": ip, "user": _cstr(user), "line": _cstr(line), "since": sec})
    return out


def _logind_sessions(directory: Path):
    """One key=value file per session; remote logins carry REMOTE_HOST (the client address with UseDNS no)."""
    out = []
    for f in sorted(directory.iterdir()):
        if not f.is_file() or f.suffix == ".ref":
            continue
        try:
            kv = dict(line.split("=", 1) for line in f.read_text(errors="replace").splitlines() if "=" in line)
        except OSError:
            continue  # session closed meanwhile
        ip = _global_ip(kv.get("REMOTE_HOST", ""))
        if not ip or kv.get("STATE") == "closing":
            continue
        since = int(kv["REALTIME"]) // 1_000_000 if re.fullmatch(r"[0-9]{1,20}", kv.get("REALTIME", "")) else 0
        out.append({"ip": ip, "user": kv.get("USER", ""), "line": kv.get("TTY") or f"session {f.name}", "since": since})
    return out


def ssh_sessions(path: Path | None = None, sessions_dir: Path | None = None):
    """Active remote sessions from utmp and/or systemd-logind: ([{ip,user,line,since}], status).
    status: 'ok' (at least one source read) | 'not mounted' | 'not readable: ...'."""
    path, sessions_dir = path or HOST_UTMP, sessions_dir or HOST_SESSIONS
    found, errors, read = [], [], False
    if path.is_file():  # Docker creates an empty directory if the host has no utmp – that counts as not mounted
        try:
            found += _utmp_sessions(path)
            read = True
        except OSError as e:
            errors.append(f"utmp: {e}")
    if sessions_dir.is_dir():
        try:
            found += _logind_sessions(sessions_dir)
            read = True
        except OSError as e:
            errors.append(f"logind: {e}")
    out, seen = [], set()
    for s in found:
        if (s["ip"], s["line"]) not in seen:
            seen.add((s["ip"], s["line"]))
            out.append(s)
    if read:
        return out, "ok"
    return [], ("not readable: " + "; ".join(errors)) if errors else "not mounted"


ASN_MODES = ("exempt", "captcha")  # never blocked | at most behind a captcha (never banned)


def protected():
    return db.q("SELECT kind, value, note, created, mode FROM protected ORDER BY kind, value")


def protected_asns(mode=None):
    """Protected ASNs, optionally only those with the given mode."""
    rows = db.q("SELECT value, mode FROM protected WHERE kind='asn'")
    return {int(r["value"]) for r in rows if mode is None or r["mode"] == mode}


def add(kind: str, value: str, note: str = "", mode: str = "exempt"):
    with db.tx() as c:
        c.execute("INSERT OR REPLACE INTO protected(kind,value,note,created,mode) VALUES(?,?,?,?,?)",
                  (kind, value, note, time.time(), mode if kind == "asn" else "exempt"))
        db.bump_rev(c)


def set_mode(asn: int, mode: str) -> bool:
    if mode not in ASN_MODES:
        raise ValueError(mode)
    with db.tx() as c:
        n = c.execute("UPDATE protected SET mode=? WHERE kind='asn' AND value=?", (mode, str(asn))).rowcount
        if n:
            db.bump_rev(c)
    return bool(n)


def protect_ip(ip: str, note: str, with_asn: bool = False, asn_mode: str = "captcha"):
    """Protects an IP and, optionally, its ASN (by default only against bans, captcha stays possible).
    Returns the protected ASNs."""
    from . import sources

    ip = str(_canonical(ipaddress.ip_address(ip)))
    add("ip", ip, note)
    asns = []
    if with_asn and ipaddress.ip_address(ip).is_global:
        info = sources.ip_info(ip)
        for asn in info["asns"]:
            add("asn", str(asn), f"{note} ({ip})", asn_mode)
            asns.append(asn)
    return asns
