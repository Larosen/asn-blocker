"""Authentication: proxy header (SSO in front) or local login. Plus the initial setup token."""
import hashlib
import hmac
import ipaddress
import secrets
import time

from fastapi import HTTPException, Request

from . import db

SESSION_COOKIE = "asnb_session"
SESSION_TTL = 12 * 3600
SETUP_TOKEN = secrets.token_urlsafe(18)
_failed: dict[str, list[float]] = {}


# --- Passwords (scrypt from the standard library) ----------------------------------------------

def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2**15, r=8, p=1, maxmem=64 * 2**20)
    return f"scrypt${salt.hex()}${h.hex()}"


def verify_password(pw: str, stored: str | None) -> bool:
    try:
        _, salt, h = (stored or "").split("$")
        calc = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2**15, r=8, p=1, maxmem=64 * 2**20)
        return hmac.compare_digest(calc.hex(), h)
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
    return chain[0] if chain else peer


def is_https(request: Request) -> bool:
    if request.url.scheme == "https":
        return True
    return _trusted(peer_ip(request)) and request.headers.get("x-forwarded-proto", "").lower() == "https"


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


def throttle(ip):
    """At most 5 failed attempts per 15 min and IP."""
    now = time.time()
    tries = [t for t in _failed.get(ip, []) if now - t < 900]
    _failed[ip] = tries
    if len(tries) >= 5:
        raise HTTPException(429, "Too many failed attempts, please try again later")


def record_failure(ip):
    _failed.setdefault(ip, []).append(time.time())


# --- Request checks ------------------------------------------------------------------------------------------

def current_user(request: Request) -> str | None:
    mode = db.get("auth_mode")
    if mode == "proxy":
        if not _trusted(peer_ip(request)):
            return None
        return request.headers.get(db.get("auth_user_header")) or None
    if mode == "local":
        token = request.cookies.get(SESSION_COOKIE)
        if not token:
            return None
        r = db.q1("SELECT user FROM sessions WHERE token_hash=? AND expires>?", (_h(token), time.time()))
        return r["user"] if r else None
    return None


def check_setup_token(token: str, ip: str):
    throttle(ip)
    if not hmac.compare_digest(token or "", SETUP_TOKEN):
        record_failure(ip)
        raise HTTPException(403, "Wrong setup token (see the container log)")
