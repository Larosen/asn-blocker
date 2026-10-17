"""Authentication: proxy header (SSO in front) or local login. Plus the initial setup token."""
import hashlib
import hmac
import ipaddress
import secrets
import threading
import time
from contextlib import contextmanager

from fastapi import HTTPException, Request

from . import db

SESSION_COOKIE = "asnb_session"
SESSION_TTL = 12 * 3600
_failed: dict[str, list[float]] = {}
_failed_lock = threading.Lock()
# scrypt needs 32 MiB per hash: limit concurrent hashes so a login flood cannot exhaust memory
_hashing = threading.BoundedSemaphore(2)
MAX_PASSWORD = 1024
# Headers that are set by clients or the proxy itself and must never be used as identity header
RESERVED_HEADERS = {"host", "user-agent", "origin", "referer", "cookie", "authorization", "accept", "accept-language",
                    "accept-encoding", "content-type", "content-length", "connection", "x-requested-with",
                    "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port", "x-real-ip",
                    "forwarded", "via", "te", "upgrade", "cache-control", "pragma", "dnt"}


def check_user_header(name: str) -> str:
    if name.lower() in RESERVED_HEADERS or name.lower().startswith("sec-"):
        raise ValueError(f"{name} cannot be used as username header")
    return name


# --- Passwords (scrypt from the standard library) ----------------------------------------------

def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2**15, r=8, p=1, maxmem=64 * 2**20)
    return f"scrypt${salt.hex()}${h.hex()}"


_DUMMY = "scrypt$" + "00" * 16 + "$" + "00" * 64


@contextmanager
def hashing_slot():
    """One of the two scrypt slots, taken *before* an attempt is counted: a flood that keeps the slots busy only
    delays sign-ins, it cannot use up the admin's attempts."""
    if not _hashing.acquire(blocking=False):
        raise HTTPException(429, "Too many concurrent sign-in attempts, please try again")
    try:
        yield
    finally:
        _hashing.release()


def verify_password(pw: str, stored: str | None) -> bool:
    """Constant work: always runs scrypt (against a dummy hash if nothing is stored). Call inside hashing_slot()."""
    try:
        _, salt, h = (stored or _DUMMY).split("$")
        calc = hashlib.scrypt(pw.encode()[:MAX_PASSWORD], salt=bytes.fromhex(salt), n=2**15, r=8, p=1,
                              maxmem=64 * 2**20)
        return hmac.compare_digest(calc.hex(), h) and bool(stored)
    except ValueError:
        return False


# --- Network / client IP ---------------------------------------------------------------------------------

def ip_in(ip: str, nets) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in ipaddress.ip_network(n, strict=False) for n in nets or [])


def _trusted(ip: str) -> bool:
    return ip_in(ip, db.get("trusted_proxies"))


def peer_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def client_ip(request: Request) -> str:
    """Real client IP: only evaluate X-Forwarded-For if the direct peer is a trusted proxy."""
    peer = peer_ip(request)
    if not _trusted(peer):
        return peer
    chain = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
    for ip in reversed(chain):
        if not _trusted(ip):
            return ip
    return peer  # every hop trusted: the leftmost entry is client-controlled, so don't use it


def is_https(request: Request) -> bool:
    # Only used to make the cookie *stricter*, so an untrusted X-Forwarded-Proto is harmless here
    return request.url.scheme == "https" or "https" in request.headers.get("x-forwarded-proto", "").lower()


def untrusted_proxy(request: Request) -> str | None:
    """Peer IP if the request was evidently forwarded by a proxy that is not configured as trusted."""
    peer = peer_ip(request)
    if request.headers.get("x-forwarded-for") and not _trusted(peer):
        return peer
    return None


def broad_trusted_proxies() -> list[str]:
    """Trusted entries covering more than one address: every host in them could impersonate any user."""
    out = []
    for n in db.get("trusted_proxies") or []:
        try:
            net = ipaddress.ip_network(n, strict=False)
        except ValueError:
            continue
        if net.num_addresses > 1:
            out.append(str(net))
    return out


# --- Sessions ---------------------------------------------------------------------------------------------

def _h(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(user):
    token = secrets.token_urlsafe(32)
    with db.tx() as c:
        c.execute("DELETE FROM sessions WHERE expires < ?", (time.time(),))
        c.execute("INSERT INTO sessions VALUES(?,?,?)", (_h(token), user, time.time() + SESSION_TTL))
    return token


def drop_session(token):
    with db.tx() as c:
        c.execute("DELETE FROM sessions WHERE token_hash=?", (_h(token or ""),))


def drop_all_sessions():
    with db.tx() as c:
        c.execute("DELETE FROM sessions")


def _bucket(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip[:64]
    if a.version == 6:
        if a.ipv4_mapped:
            return str(a.ipv4_mapped)
        return str(ipaddress.ip_network(f"{a}/64", strict=False))  # one IPv6 customer = one /64
    return str(a)


def _wide_bucket(ip: str) -> str | None:
    """IPv6 /48 (one site): a second, coarser limit so rotating through /64s does not multiply the budget."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if a.version == 6 and not a.ipv4_mapped:
        return "w:" + str(ipaddress.ip_network(f"{a}/48", strict=False))
    return None


LIMITS = {"narrow": 5, "wide": 20}  # attempts per 15 minutes


def attempt(ip) -> list[str]:
    """Counts a sign-in attempt *before* the password check (so parallel requests cannot bypass the limit).
    At most 5 attempts per 15 min per IP (IPv6: per /64, and 20 per /48). Returns the bucket keys for forgive()."""
    keys = [(_bucket(ip), LIMITS["narrow"])]
    if wide := _wide_bucket(ip):
        keys.append((wide, LIMITS["wide"]))
    now = time.time()
    with _failed_lock:
        if len(_failed) > 10000:  # bounded memory under IP rotation: drop stale, then the least recently used
            for k in [k for k, v in _failed.items() if not v or now - v[-1] >= 900]:
                del _failed[k]
            for k in sorted(_failed, key=lambda k: _failed[k][-1])[:max(0, len(_failed) - 9000)]:
                del _failed[k]
        recent = {k: [t for t in _failed.get(k, []) if now - t < 900] for k, _ in keys}
        for k, limit in keys:
            if len(recent[k]) >= limit:
                _failed[k] = recent[k]
                raise HTTPException(429, "Too many failed attempts, please try again later")
        for k, _ in keys:
            _failed[k] = recent[k] + [now]
    return [k for k, _ in keys]


def forgive(keys):
    """Successful sign-in: the narrow bucket is cleared, the wide one only loses this attempt."""
    with _failed_lock:
        _failed.pop(keys[0], None)
        for k in keys[1:]:
            if _failed.get(k):
                _failed[k].pop()


# --- Request checks ------------------------------------------------------------------------------------------

def current_user(request: Request) -> str | None:
    mode = db.get("auth_mode")
    if mode == "proxy":
        if not _trusted(peer_ip(request)):
            return None
        values = request.headers.getlist(db.get("auth_user_header") or "")
        if len(values) != 1:  # missing, or appended to a client-supplied value by the proxy
            return None
        return values[0].strip() or None
    if mode == "local":
        token = request.cookies.get(SESSION_COOKIE)
        if not token:
            return None
        r = db.q1("SELECT user FROM sessions WHERE token_hash=? AND expires>?", (_h(token), time.time()))
        return r["user"] if r else None
    return None


# --- Setup token ---------------------------------------------------------------------------------------------
# 144 bits of entropy: guessing is hopeless, so there is deliberately no throttle (it would only let
# anyone behind the same proxy IP lock the admin out of the setup). Only its hash is stored.

def new_setup_token() -> str:
    token = secrets.token_urlsafe(18)
    with db.tx() as c:
        db.put("setup_token_hash", _h(token), c)
    return token


def check_setup_token(token: str):
    stored = db.get("setup_token_hash")
    if not stored or not hmac.compare_digest(_h(token or ""), stored):
        raise HTTPException(403, "Wrong setup token (see the container log)")
