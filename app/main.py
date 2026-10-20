import hmac
import ipaddress
import logging
import re
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from . import auth, crowdsec, db, engine, logs, notify, selfprotect, sources, suggestions

logs.setup()
log = logging.getLogger("asn_blocker")

STATIC = Path(__file__).parent / "static"
logging.getLogger("uvicorn.access").addFilter(lambda r: "/healthz" not in r.getMessage())
VERSION = "0.7.1"


@asynccontextmanager
async def lifespan(_app):
    db.init()
    with db.tx() as c:
        c.execute("UPDATE runs SET status='failed', finished_at=? WHERE status='running'", (time.time(),))
    if not db.get("auth_mode"):
        log.warning("Initial setup: setup token = %s", auth.new_setup_token())
    threading.Thread(target=engine.scheduler, daemon=True, name="scheduler").start()
    yield


app = FastAPI(title="asn-blocker", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=STATIC), name="static")

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "font-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


MAX_BODY = 4 * 2**20


def _reject(request: Request) -> JSONResponse | None:
    if request.method in ("GET", "HEAD", "OPTIONS") or not request.url.path.startswith("/api/"):
        return None
    # CSRF: state-changing requests require a custom header (forces a CORS preflight) and a matching Origin
    if request.headers.get("x-requested-with") != "asn-blocker":
        return JSONResponse({"detail": "Missing CSRF header"}, 403)
    origin = request.headers.get("origin")
    if origin:
        host = request.headers.get("host", "")
        if auth._trusted(auth.peer_ip(request)):
            host = request.headers.get("x-forwarded-host", host)
        if urlsplit(origin).netloc != host.split(",")[0].strip():
            return JSONResponse({"detail": "Origin mismatch"}, 403)
    # Bounded request bodies (browsers always send Content-Length for fetch bodies)
    if "transfer-encoding" in request.headers:
        return JSONResponse({"detail": "Content-Length required"}, 411)
    try:
        if int(request.headers.get("content-length") or 0) > MAX_BODY:
            return JSONResponse({"detail": "Request body too large"}, 413)
    except ValueError:
        return JSONResponse({"detail": "Invalid Content-Length"}, 400)
    return None


@app.middleware("http")
async def guard(request: Request, call_next):
    resp = _reject(request)
    if resp is None:
        try:
            resp = await call_next(request)
        except Exception:  # noqa: BLE001 - still answer with the security headers below
            log.exception("Unhandled error on %s %s", request.method, request.url.path)
            resp = JSONResponse({"detail": "Internal error"}, 500)
    h = resp.headers
    h["Content-Security-Policy"] = CSP
    h["X-Content-Type-Options"] = "nosniff"
    h["Referrer-Policy"] = "no-referrer"
    h["X-Frame-Options"] = "DENY"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), interest-cohort=()"
    if request.url.path.startswith("/api/"):
        h["Cache-Control"] = "no-store"
    elif "cache-control" not in h:
        # UI files: the browser may keep them but must revalidate (cheap 304 via ETag), so an update shows at once
        h["Cache-Control"] = "no-cache"
    return resp


def require_user(request: Request) -> str:
    if not db.get("auth_mode"):
        raise HTTPException(409, "Initial setup not completed")
    user = auth.current_user(request)
    if not user:
        raise HTTPException(401, "Not signed in")
    return user


pub = APIRouter(prefix="/api")
api = APIRouter(prefix="/api", dependencies=[Depends(require_user)])


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/healthz", include_in_schema=False)
def healthz():
    db.q1("SELECT 1 x")
    return {"ok": True}


# --- Session / initial setup ----------------------------------------------------------------------

@pub.get("/session")
def session(request: Request):
    user, mode = auth.current_user(request), db.get("auth_mode")
    peer = auth.peer_ip(request) if not user and not mode else None
    return {"setup_required": not mode, "auth_mode": mode, "user": user,
            "peer_ip": peer, "peer_name": auth.reverse_name(peer, 1.0) if peer else None,
            "denied": auth.denied_details(request) if mode == "proxy" and not user else None,
            "crowdsec_configured": bool(db.get("crowdsec_mode")) if user else None, "version": VERSION}


class SetupAuth(BaseModel):
    token: str
    mode: Literal["proxy", "local"]
    user_header: str = Field("Remote-User", pattern=r"^[A-Za-z0-9-]{1,64}$")
    trusted_proxies: list[str] = []
    username: str = Field("admin", pattern=r"^[\w.@-]{1,64}$")
    password: str = Field("", max_length=auth.MAX_PASSWORD)

    @field_validator("user_header")
    @classmethod
    def _header(cls, v):
        return auth.check_user_header(v)

    @field_validator("trusted_proxies")
    @classmethod
    def _proxies(cls, v):
        return [auth.normalize_proxy(x) for x in v if x.strip()]


@pub.post("/setup/auth")
def setup_auth(s: SetupAuth, request: Request, response: Response):
    if db.get("auth_mode"):
        raise HTTPException(409, "Already set up")
    auth.check_setup_token(s.token)
    if s.mode == "proxy":
        if not s.trusted_proxies:
            raise HTTPException(422, "At least one trusted proxy (container name, IP or CIDR) is required")
        peer = auth.peer_ip(request)
        if not auth.ip_in(peer, s.trusted_proxies) or not request.headers.get(s.user_header):
            raise HTTPException(422, f"This request came from {peer} "
                                     f"{'with' if request.headers.get(s.user_header) else 'without'} header {s.user_header}. "
                                     "These settings would lock you out. "
                                     "Open the setup through the reverse proxy with SSO.")
    elif len(s.password) < 12:
        raise HTTPException(422, "Password: at least 12 characters")
    password_hash = auth.hash_password(s.password) if s.mode == "local" else None
    with db.tx() as c:
        if db.get("auth_mode"):  # concurrent setup request won the race
            raise HTTPException(409, "Already set up")
        db.put("setup_token_hash", None, c)
        db.put("auth_mode", s.mode, c)
        db.put("auth_user_header", s.user_header, c)
        db.put("trusted_proxies", s.trusted_proxies, c)
        if s.mode == "local":
            db.put("local_user", s.username, c)
            db.put("local_password_hash", password_hash, c)
    user = s.username if s.mode == "local" else request.headers.get(s.user_header)
    if s.mode == "local":
        _set_cookie(response, request, auth.create_session(s.username))
    db.audit(user, "setup.auth", {"mode": s.mode})
    return {"ok": True}


def _set_cookie(response, request, token):
    response.set_cookie(auth.SESSION_COOKIE, token, max_age=auth.SESSION_TTL, httponly=True,
                        secure=auth.is_https(request), samesite="strict", path="/")


class Login(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=auth.MAX_PASSWORD)


@pub.post("/login")
def login(body: Login, request: Request, response: Response):
    if db.get("auth_mode") != "local":
        raise HTTPException(400, "Local login is not enabled")
    ip = auth.client_ip(request)
    with auth.hashing_slot():
        key = auth.attempt(ip)
        pw_ok = auth.verify_password(body.password, db.get("local_password_hash"))  # always hashes: no enumeration
    if not (hmac.compare_digest(body.username.encode(), (db.get("local_user") or "").encode()) and pw_ok):
        raise HTTPException(401, "Wrong username or password")
    auth.forgive(key)
    _set_cookie(response, request, auth.create_session(body.username))
    db.audit(body.username, "login", {"ip": ip})
    return {"ok": True}


@pub.post("/logout")
def logout(request: Request, response: Response):
    auth.drop_session(request.cookies.get(auth.SESSION_COOKIE))
    response.delete_cookie(auth.SESSION_COOKIE, path="/")
    return {"ok": True}


class Password(BaseModel):
    current: str = Field(max_length=auth.MAX_PASSWORD)
    new: str = Field(min_length=12, max_length=auth.MAX_PASSWORD)


@api.put("/account/password")
def change_password(body: Password, user: str = Depends(require_user)):
    if db.get("auth_mode") != "local":
        raise HTTPException(400, "Local login is not enabled")
    with auth.hashing_slot():
        key = auth.attempt(f"account:{user}")
        ok = auth.verify_password(body.current, db.get("local_password_hash"))
    if not ok:
        raise HTTPException(400, "Current password is wrong")
    auth.forgive(key)
    db.put("local_password_hash", auth.hash_password(body.new))
    auth.drop_all_sessions()
    db.audit(user, "account.password")
    return {"ok": True}


# --- Overview --------------------------------------------------------------------------------------

def _run_row(r):
    if r and r.get("summary"):
        r["summary"] = __import__("json").loads(r["summary"])
    return r


@api.get("/overview")
def overview(request: Request, user: str = Depends(require_user)):
    ip = auth.client_ip(request)
    me = None
    try:
        ipaddress.ip_address(ip)
        applied = {}
        for r in db.q("SELECT type, value FROM applied"):
            applied.setdefault(r["type"], []).append(r["value"])
        me = {"ip": ip, "status": engine.status_of(ip, applied)}
    except ValueError:
        pass
    counts = {t: db.q1("SELECT count(*) n FROM applied WHERE type=?", (t,))["n"] for t in engine.REASONS}
    return {
        "user": user, "auth_mode": db.get("auth_mode"), "me": me, "applied": counts,
        "rules": {"asns": db.q1("SELECT count(*) n FROM asn_rules")["n"],
                  "vpn": db.q1("SELECT count(*) n FROM vpn_rules")["n"],
                  "exemptions": db.q1("SELECT count(*) n FROM exemptions")["n"],
                  "watch": db.q1("SELECT count(*) n FROM watch_ips")["n"]},
        "pending": db.get("config_rev") != db.get("applied_rev"),
        "running": engine.is_running(), "next_run": engine.next_due(),
        "last_apply": _run_row(db.q1("SELECT id,status,started_at,finished_at,summary,triggered_by FROM runs "
                                     "WHERE kind='apply' ORDER BY id DESC LIMIT 1")),
        "crowdsec_mode": db.get("crowdsec_mode"), "interval_hours": db.get("interval_hours"),
        "asn_names": db.q1("SELECT count(*) n FROM asn_names")["n"],
        "untrusted_proxy": auth.untrusted_proxy(request) if db.get("auth_mode") == "local" else None,
        "broad_proxies": auth.broad_trusted_proxies(),
    }


# --- ASNs ---------------------------------------------------------------------------------------------

def _src(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except sources.SourceError as e:
        raise HTTPException(502, str(e))


@api.get("/asn/search")
def asn_search(q: str = Query(max_length=100)):
    rules = {r["asn"]: r["action"] for r in db.q("SELECT asn, action FROM asn_rules")}
    try:
        ip = ipaddress.ip_address(q.strip())
    except ValueError:
        return [{**r, "rule": rules.get(r["asn"])} for r in _src(sources.search_asn, q)]
    # An IP (e.g. from a CrowdSec alert): which network does it belong to?
    if not ip.is_global:
        raise HTTPException(422, f"{ip} is not a public address")
    info = _src(sources.ip_info, str(ip))
    if not info["asns"]:  # not routed: there is no network to block
        try:
            holder = sources.ip_holder(str(ip))
        except sources.SourceError:
            holder = ""
        return [{"asn": None, "rule": None, "via": {"ip": str(ip), "prefix": None, "holder": holder}}]
    out = []
    for asn in info["asns"]:
        n = db.q1("SELECT name, class, cc FROM asn_names WHERE asn=?", (asn,)) or {}
        out.append({"asn": asn, "name": n.get("name", ""), "class": n.get("class", ""), "cc": n.get("cc", ""),
                    "rule": rules.get(asn), "via": {"ip": str(ip), "prefix": info.get("prefix")}})
    return out


def _prefix_stats(asn):
    p = db.cache_get(f"prefixes:{asn}", 7 * 86400)
    if p is None:
        return None
    v4 = [ipaddress.ip_network(x) for x in p if ":" not in x]
    return {"v4": len(v4), "v6": len(p) - len(v4), "addresses": sum(n.num_addresses for n in v4)}


@api.get("/asns")
def list_asns():
    rows = db.q("SELECT a.*, n.class, n.cc FROM asn_rules a LEFT JOIN asn_names n USING(asn) ORDER BY a.asn")
    return [{**r, "stats": _prefix_stats(r["asn"])} for r in rows]


@api.post("/asns/stats")
def load_stats():
    """Load prefix counts for all rules (cached) so the UI can show sizes."""
    asns = [r["asn"] for r in db.q("SELECT asn FROM asn_rules")]
    _src(sources.prefixes_many, asns)
    return {a: _prefix_stats(a) for a in asns}


class AsnRule(BaseModel):
    asn: int = Field(gt=0, lt=2**32)
    name: str = Field("", max_length=200)
    action: Literal["ban", "captcha"]
    note: str = Field("", max_length=500)


def _own_asns(request: Request) -> dict[int, str]:
    """ASNs of the network the current browser request comes from ({asn: ip}); empty if unknown."""
    ip = auth.client_ip(request)
    try:
        if not ipaddress.ip_address(ip).is_global:
            return {}
        return {a: ip for a in sources.ip_info(ip)["asns"]}
    except (ValueError, sources.SourceError):
        return {}


def _guard_own_asn(asns, request: Request, confirmed: bool):
    """Blocking the network you are connected from needs an explicit confirmation (e.g. a hotel or office network)."""
    existing = {r["asn"] for r in db.q("SELECT asn FROM asn_rules")}
    new = set(asns) - existing
    own = _own_asns(request) if new else {}
    hit = sorted(new & set(own))
    if hit and not confirmed:
        raise HTTPException(409, {"code": "own_asn", "asns": hit, "ip": own[hit[0]],
                                  "message": f"AS{hit[0]} is the network you are connected from ({own[hit[0]]}). "
                                             "Blocking it can lock you out of this page."})


@api.get("/asns/suggestions")
def asn_suggestions():
    existing = {r["asn"] for r in db.q("SELECT asn FROM asn_rules")}
    protected = selfprotect.protected_asns()
    return {"spamhaus": db.get("spamhaus_asndrop"), "lists": [
        {k: v for k, v in lst.items() if k != "asns"}
        | {"asns": [{"asn": a, "name": sources.asn_name(a) or label, "note": label, "present": a in existing,
                     "protected": a in protected} for a, label in lst["asns"]]}
        for lst in suggestions.LISTS]}


@api.put("/asns")
def put_asns(rules: list[AsnRule], request: Request, confirm_own: bool = Query(False), user: str = Depends(require_user)):
    if len(rules) > 5000:
        raise HTTPException(422, "At most 5000 rules per request")
    blocked = sorted({r.asn for r in rules} & selfprotect.protected_asns())
    if blocked:
        raise HTTPException(422, "Self-protection: " + ", ".join(f"AS{a}" for a in blocked)
                            + " is protected and cannot be blocked")
    _guard_own_asn([r.asn for r in rules], request, confirm_own)
    now = time.time()
    with db.tx() as c:
        for r in rules:
            name = r.name or sources.asn_name(r.asn)
            c.execute("INSERT INTO asn_rules(asn,name,action,note,updated_at) VALUES(?,?,?,?,?) "
                      "ON CONFLICT(asn) DO UPDATE SET name=excluded.name, action=excluded.action, "
                      "note=excluded.note, updated_at=excluded.updated_at", (r.asn, name, r.action, r.note, now))
        db.bump_rev(c)
    db.audit(user, "asn.put", [r.model_dump() for r in rules] + ([{"confirmed_own_network": True}] if confirm_own else []))
    return {"ok": True}


@api.delete("/asns/{asn}")
def delete_asn(asn: int, user: str = Depends(require_user)):
    with db.tx() as c:
        c.execute("DELETE FROM asn_rules WHERE asn=?", (asn,))
        db.bump_rev(c)
    db.audit(user, "asn.delete", {"asn": asn})
    return {"ok": True}


class AsnDelete(BaseModel):
    asns: list[int] = Field(max_length=5000)


@api.post("/asns/delete")
def delete_asns(body: AsnDelete, user: str = Depends(require_user)):
    with db.tx() as c:
        c.executemany("DELETE FROM asn_rules WHERE asn=?", [(a,) for a in body.asns])
        db.bump_rev(c)
    db.audit(user, "asn.delete", {"asns": body.asns})
    return {"ok": True}


class AsnImport(BaseModel):
    text: str = Field(max_length=200_000)
    action: Literal["ban", "captcha"]


ASN_LINE = re.compile(r"^\s*(?:AS)?(\d{1,10})\b[\s,;]*(?:#\s*)?(.*)$", re.I)


@api.post("/asns/parse")
def parse_asns(body: AsnImport):
    """Free text, one ASN per line with an optional comment -> preview. Commented-out lines are ignored."""
    out = []
    for line in body.text.splitlines():
        if line.strip().startswith("#"):
            continue
        m = ASN_LINE.match(line)
        if m and 0 < int(m.group(1)) < 2**32:
            asn = int(m.group(1))
            out.append({"asn": asn, "name": sources.asn_name(asn), "note": m.group(2).strip()[:500],
                        "action": body.action})
    return out


# --- VPN ---------------------------------------------------------------------------------------------

@api.get("/vpn/providers")
def providers():
    modes = db.get("vpn_modes") or {}
    sel = {}
    for r in db.q("SELECT provider, country FROM vpn_rules"):
        sel.setdefault(r["provider"], []).append(r["country"])
    return [{"id": p.id, "name": p.name, "note": p.note, "exit_asn": p.exit_asn, "mode": modes.get(p.id, "exact"),
             "countries": sorted(sel.get(p.id, []))} for p in sources.PROVIDERS.values()]


def _provider(pid):
    p = sources.PROVIDERS.get(pid)
    if not p:
        raise HTTPException(404, "Unknown provider")
    return p


@api.get("/vpn/{pid}/countries")
def vpn_countries(pid: str):
    return _src(_provider(pid).countries)


class VpnSel(BaseModel):
    countries: list[str] = Field(max_length=300)
    mode: Literal["exact", "net"] = "exact"

    @field_validator("countries")
    @classmethod
    def _cc(cls, v):
        v = sorted({c.upper() for c in v})
        if any(not re.fullmatch(r"[A-Z]{2}", c) for c in v):
            raise ValueError("Country codes must have two letters")
        return v


@api.put("/vpn/{pid}")
def put_vpn(pid: str, sel: VpnSel, user: str = Depends(require_user)):
    _provider(pid)
    modes = db.get("vpn_modes") or {}
    modes[pid] = sel.mode
    with db.tx() as c:
        c.execute("DELETE FROM vpn_rules WHERE provider=?", (pid,))
        c.executemany("INSERT INTO vpn_rules VALUES(?,?)", [(pid, cc) for cc in sel.countries])
        db.put("vpn_modes", modes, c)
        db.bump_rev(c)
    db.audit(user, "vpn.put", {"provider": pid, **sel.model_dump()})
    return {"ok": True}


# --- Exemptions & watch IPs ------------------------------------------------------------------------

class Exemption(BaseModel):
    kind: Literal["asn", "cidr"]
    value: str = Field(max_length=64)
    note: str = Field("", max_length=300)


@api.get("/exemptions")
def list_exemptions():
    rows = db.q("SELECT * FROM exemptions ORDER BY kind, value")
    for r in rows:
        if r["kind"] == "asn":
            r["name"] = sources.asn_name(int(r["value"]))
    return rows


def _asn(v: str) -> int:
    digits = v.strip().upper().removeprefix("AS")
    if not re.fullmatch(r"[0-9]{1,10}", digits) or not 0 < int(digits) < 2**32:
        raise ValueError(v)
    return int(digits)


def _exemption_value(e: Exemption) -> str:
    try:
        if e.kind == "asn":
            return str(_asn(e.value))
        net = ipaddress.ip_network(e.value.strip(), strict=False)
    except ValueError:
        raise HTTPException(422, f"Invalid: {e.value}")
    if net.prefixlen < engine.MIN_PREFIXLEN[net.version]:  # would silently switch off blocking for huge areas
        raise HTTPException(422, f"{net} is too large for an exemption (at most /{engine.MIN_PREFIXLEN[net.version]})")
    return str(net)


@api.post("/exemptions")
def add_exemption(e: Exemption, user: str = Depends(require_user)):
    value = _exemption_value(e)
    with db.tx() as c:
        c.execute("INSERT OR REPLACE INTO exemptions VALUES(?,?,?)", (e.kind, value, e.note))
        db.bump_rev(c)
    db.audit(user, "exemption.add", {"kind": e.kind, "value": value})
    return {"ok": True, "value": value}


@api.delete("/exemptions/{kind}/{value:path}")
def delete_exemption(kind: str, value: str, user: str = Depends(require_user)):
    with db.tx() as c:
        c.execute("DELETE FROM exemptions WHERE kind=? AND value=?", (kind, value))
        db.bump_rev(c)
    db.audit(user, "exemption.delete", {"kind": kind, "value": value})
    return {"ok": True}


class Watch(BaseModel):
    ip: str = Field(max_length=64)
    note: str = Field("", max_length=300)


def _watch_value(w: Watch) -> str:
    try:
        return str(ipaddress.ip_address(w.ip.strip()))
    except ValueError:
        raise HTTPException(422, f"Not a valid IP: {w.ip}")


@api.get("/watch")
def list_watch():
    return db.q("SELECT * FROM watch_ips ORDER BY ip")


@api.post("/watch")
def add_watch(w: Watch, user: str = Depends(require_user)):
    ip = _watch_value(w)
    with db.tx() as c:
        c.execute("INSERT OR REPLACE INTO watch_ips(ip,note) VALUES(?,?)", (ip, w.note))
    db.audit(user, "watch.add", {"ip": ip})
    return {"ok": True}


@api.delete("/watch/{ip}")
def delete_watch(ip: str, user: str = Depends(require_user)):
    with db.tx() as c:
        c.execute("DELETE FROM watch_ips WHERE ip=?", (ip,))
    db.audit(user, "watch.delete", {"ip": ip})
    return {"ok": True}


# --- Self-protection --------------------------------------------------------------------------------

@api.get("/protect")
def get_protect(request: Request):
    sessions, utmp = selfprotect.ssh_sessions()
    applied = {}
    for r in db.q("SELECT type, value FROM applied"):
        applied.setdefault(r["type"], []).append(r["value"])
    prot_asns = selfprotect.protected_asns()
    for s in sessions:
        s["status"] = engine.status_of(s["ip"], applied)
        try:
            asns = sources.ip_info(s["ip"])["asns"]
        except sources.SourceError:
            asns = []
        s["asns"] = [{"asn": a, "name": sources.asn_name(a), "protected": a in prot_asns} for a in asns]
    rows = selfprotect.protected()
    for r in rows:
        if r["kind"] == "asn":
            r["name"] = sources.asn_name(int(r["value"]))
    ip = auth.client_ip(request)
    try:
        ip = ip if ipaddress.ip_address(ip).is_global else None  # local addresses are never blocked anyway
    except ValueError:
        ip = None
    return {"utmp": utmp, "sessions": sessions, "protected": rows, "client_ip": ip}


class Protect(BaseModel):
    ip: str
    with_asn: bool = True
    note: str = Field("", max_length=200)


@api.post("/protect")
def add_protect(body: Protect, user: str = Depends(require_user)):
    try:
        asns = selfprotect.protect_ip(body.ip.strip(), body.note or f"by {user}", body.with_asn)
    except ValueError:
        raise HTTPException(422, "Not a valid IP address")
    except sources.SourceError as e:
        raise HTTPException(502, str(e))
    with db.tx() as c:
        c.executemany("DELETE FROM asn_rules WHERE asn=?", [(a,) for a in asns])
    db.audit(user, "protect.add", {"ip": body.ip, "asns": asns})
    return {"ok": True, "asns": asns}


@api.delete("/protect/{kind}/{value:path}")
def delete_protect(kind: str, value: str, user: str = Depends(require_user)):
    with db.tx() as c:
        c.execute("DELETE FROM protected WHERE kind=? AND value=?", (kind, value))
        db.bump_rev(c)
    db.audit(user, "protect.delete", {"kind": kind, "value": value})
    return {"ok": True}


@api.get("/check/{ip}")
def check(ip: str):
    try:
        return engine.check_ip(ip)
    except ValueError:
        raise HTTPException(422, "Not a valid IP address")


# --- Settings --------------------------------------------------------------------------------------------

PUBLIC_SETTINGS = ["interval_hours", "decision_hours", "include_ipv6", "sanity_percent", "notify_url",
                   "notify_format", "spamhaus_asndrop", "trusted_proxies", "auth_user_header", "auth_mode",
                   "crowdsec_mode", "lapi_url", "lapi_machine_id", "docker_container", "local_user"]


@api.get("/settings")
def get_settings():
    return {k: db.get(k) for k in PUBLIC_SETTINGS} | {"lapi_password_set": bool(db.get("lapi_password")),
                                                      "notify_url": notify.mask(db.get("notify_url")),
                                                      "notify_token_set": bool(db.get("notify_token"))}


class Settings(BaseModel):
    interval_hours: int = Field(ge=6, le=24 * 14)
    decision_hours: int = Field(ge=24, le=24 * 365 * 3)
    include_ipv6: bool
    sanity_percent: int = Field(ge=5, le=100)
    spamhaus_asndrop: Literal["ban", "captcha"] | None
    trusted_proxies: list[str]
    auth_user_header: str = Field(pattern=r"^[A-Za-z0-9-]{1,64}$")

    @field_validator("auth_user_header")
    @classmethod
    def _header(cls, v):
        return auth.check_user_header(v)

    @field_validator("trusted_proxies")
    @classmethod
    def _proxies(cls, v):
        return [auth.normalize_proxy(x) for x in v if x.strip()]


@api.put("/settings")
def put_settings(s: Settings, request: Request, user: str = Depends(require_user)):
    if s.decision_hours < s.interval_hours * 2:
        raise HTTPException(422, "Decision duration must be at least twice the interval")
    if db.get("auth_mode") == "proxy":
        if not auth.ip_in(auth.peer_ip(request), s.trusted_proxies) or not request.headers.get(s.auth_user_header):
            raise HTTPException(422, "These proxy settings would lock you out")
    affects = {k: db.get(k) for k in ("include_ipv6", "spamhaus_asndrop")} != \
        {"include_ipv6": s.include_ipv6, "spamhaus_asndrop": s.spamhaus_asndrop}
    with db.tx() as c:
        for k, v in s.model_dump().items():
            db.put(k, v, c)
        if affects:
            db.bump_rev(c)
    db.audit(user, "settings.put", s.model_dump())
    return {"ok": True}


class NotifyCfg(BaseModel):
    notify_url: str = Field("", max_length=500, pattern=r"^(https?://\S+)?$")
    notify_format: Literal["ntfy", "gotify", "webhook"] = "ntfy"
    notify_token: str | None = Field(None, max_length=256, pattern=r"^[\x21-\x7e]*$")  # None = keep, "" = remove
    public_url: str | None = Field(None, max_length=200,  # address of this UI (browser's location.origin)
                                  pattern=r"^https?://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(:\d{1,5})?$")


def _notify_values(c: NotifyCfg):
    """Form values -> (url, format, token, public_url); the masked URL and an empty token field mean 'unchanged'."""
    stored_url = db.get("notify_url")
    url = stored_url if c.notify_url and c.notify_url == notify.mask(stored_url) else c.notify_url
    token = c.notify_token
    if token is None:
        # keep the stored token – but never send it to a different server than it was entered for
        token = db.get("notify_token") if notify.same_host(url, stored_url) else ""
    return url, c.notify_format, token, c.public_url or db.get("public_url")


_notify_tests: list[float] = []
_notify_tests_lock = threading.Lock()


@api.post("/notify/test")
def notify_test(c: NotifyCfg):
    with _notify_tests_lock:  # at most 10 test notifications per minute
        now = time.time()
        _notify_tests[:] = [t for t in _notify_tests if now - t < 60]
        if len(_notify_tests) >= 10:
            raise HTTPException(429, "Too many test notifications, please wait a minute")
        _notify_tests.append(now)
    url, fmt, token, base = _notify_values(c)
    if not url:
        raise HTTPException(422, "Enter a notification URL first")
    try:
        notify.send("asn-blocker: test", "Notifications are working. Tap to open asn-blocker.", "info",
                    raise_errors=True, cfg=(url, fmt, token, base))
    except notify.NotifyError as e:
        raise HTTPException(502, str(e))
    notify.mark_tested(url, fmt, token, base)
    return {"ok": True}


@api.put("/notify")
def put_notify(c: NotifyCfg, user: str = Depends(require_user)):
    url, fmt, token, base = _notify_values(c)
    if url and not notify.was_tested(url, fmt, token, base):
        raise HTTPException(409, "Send a successful test notification with these settings first – nothing was saved")
    with db.tx() as cur:
        db.put("notify_url", url, cur)
        db.put("notify_format", fmt, cur)
        db.put("notify_token", token if url else "", cur)
        db.put("public_url", base, cur)
    db.audit(user, "notify.put", {"url": notify.mask(url), "format": fmt, "token_set": bool(token and url)})
    return {"ok": True}


class CrowdSecCfg(BaseModel):
    mode: Literal["lapi", "docker"]
    lapi_url: str = Field("http://crowdsec:8080", pattern=r"^https?://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(:\d{1,5})?/?$")
    machine_id: str = Field("", max_length=128)
    password: str = Field("", max_length=512)   # empty = keep the current one
    container: str = Field("crowdsec", pattern=r"^[\w.-]{1,128}$")


@api.put("/crowdsec")
def put_crowdsec(cfg: CrowdSecCfg, user: str = Depends(require_user)):
    # The stored password is only reused for the same LAPI and machine – otherwise it could be sent to any URL
    same = cfg.lapi_url == db.get("lapi_url") and cfg.machine_id == db.get("lapi_machine_id")
    password = cfg.password or (db.get("lapi_password") if same else "")
    if cfg.mode == "lapi" and not password:
        raise HTTPException(422, "Enter the machine password (required when URL or machine ID change)")
    if cfg.mode == "lapi":
        try:
            notify.check_target(cfg.lapi_url)
        except notify.NotifyError as e:
            raise HTTPException(422, str(e).replace("notification target", "LAPI address"))
    try:
        msg = (crowdsec.Lapi(cfg.lapi_url, cfg.machine_id, password) if cfg.mode == "lapi"
               else crowdsec.DockerCli(cfg.container)).test()
    except crowdsec.CrowdSecError as e:
        raise HTTPException(422, str(e))
    with db.tx() as c:
        db.put("crowdsec_mode", cfg.mode, c)
        db.put("lapi_url", cfg.lapi_url, c)
        db.put("lapi_machine_id", cfg.machine_id, c)
        db.put("lapi_password", password, c)
        db.put("docker_container", cfg.container, c)
    db.audit(user, "crowdsec.put", {"mode": cfg.mode, "url": cfg.lapi_url, "machine": cfg.machine_id})
    return {"ok": True, "message": msg}


class Cleanup(BaseModel):
    reason: str = Field(min_length=3, max_length=200)


@api.post("/crowdsec/cleanup")
def cleanup(body: Cleanup, user: str = Depends(require_user)):
    """Remove decisions that other tools or scripts added via cscli, selected by their reason (scenario)."""
    if body.reason.strip().casefold() in {r.casefold() for r in engine.REASONS.values()}:
        raise HTTPException(422, "Decisions owned by asn-blocker are managed through runs")
    try:
        n = crowdsec.backend().delete_scenario(body.reason)
    except crowdsec.CrowdSecError as e:
        raise HTTPException(502, str(e))
    db.audit(user, "crowdsec.cleanup", {"reason": body.reason, "deleted": n})
    return {"deleted": n}


# --- Runs ----------------------------------------------------------------------------------------------------

class RunReq(BaseModel):
    kind: Literal["plan", "apply"]
    confirm: int | None = None  # ID of the stopped run whose result the user reviewed and accepts


@api.post("/runs")
def start_run(body: RunReq, user: str = Depends(require_user)):
    if engine.is_running():
        raise HTTPException(409, "A run is already in progress")
    if body.kind == "apply" and not db.get("crowdsec_mode"):
        raise HTTPException(409, "CrowdSec connection is not set up yet")
    confirmed = None
    if body.confirm is not None:
        last = _run_row(db.q1("SELECT id,status,summary FROM runs WHERE kind='apply' ORDER BY id DESC LIMIT 1"))
        if body.kind != "apply" or not last or last["id"] != body.confirm or last["status"] != "blocked":
            raise HTTPException(409, "Only the latest stopped run can be confirmed")
        confirmed = (last["id"], last["summary"] or {})

    def go():
        try:
            engine.run(body.kind, user, confirmed=confirmed)
        except engine.Busy:
            pass

    threading.Thread(target=go, daemon=True).start()
    if body.kind == "apply":
        db.audit(user, "run.apply", {"confirmed_run": body.confirm} if body.confirm else None)
    return {"ok": True}


@api.get("/preview")
def get_preview():
    return engine.preview()


@api.get("/runs")
def list_runs(limit: int = Query(30, ge=1, le=500)):
    return [_run_row(r) for r in db.q("SELECT id,kind,status,triggered_by,started_at,finished_at,summary FROM runs "
                                      "ORDER BY id DESC LIMIT ?", (min(limit, 100),))]


@api.get("/runs/{run_id}")
def get_run(run_id: int):
    r = _run_row(db.q1("SELECT * FROM runs WHERE id=?", (run_id,)))
    if not r:
        raise HTTPException(404)
    r["changes"] = db.q("SELECT op,type,value FROM run_changes WHERE run_id=? LIMIT 500", (run_id,))
    return r


@api.get("/ranges/{typ}.txt", response_class=PlainTextResponse)
def ranges(typ: Literal["ban", "captcha"]):
    return "".join(r["value"] + "\n" for r in db.q("SELECT value FROM applied WHERE type=? ORDER BY value", (typ,)))


@api.get("/audit")
def audit_log(limit: int = Query(200, ge=1, le=1000)):
    return db.q("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (min(limit, 1000),))


# --- Export / Import -------------------------------------------------------------------------------------------

@api.get("/export")
def export():
    return {"version": 1, "asns": db.q("SELECT asn,name,action,note FROM asn_rules ORDER BY asn"),
            "vpn": db.q("SELECT provider,country FROM vpn_rules"), "vpn_modes": db.get("vpn_modes"),
            "exemptions": db.q("SELECT kind,value,note FROM exemptions"),
            "watch": db.q("SELECT ip,note FROM watch_ips")}


class ImportData(BaseModel):
    version: Literal[1]
    asns: list[AsnRule] = Field([], max_length=5000)
    vpn: list[dict] = Field([], max_length=5000)
    vpn_modes: dict[str, Literal["exact", "net"]] | None = None
    exemptions: list[Exemption] = Field([], max_length=5000)
    watch: list[Watch] = Field([], max_length=1000)


@api.post("/import")
def import_cfg(data: ImportData, request: Request, confirm_own: bool = Query(False), user: str = Depends(require_user)):
    """Everything is validated first and written in one transaction – an invalid entry changes nothing."""
    blocked = sorted({r.asn for r in data.asns} & selfprotect.protected_asns())
    if blocked:
        raise HTTPException(422, "Self-protection: " + ", ".join(f"AS{a}" for a in blocked)
                            + " is protected and cannot be blocked")
    _guard_own_asn([r.asn for r in data.asns], request, confirm_own)
    exemptions = [(e.kind, _exemption_value(e), e.note) for e in data.exemptions]
    watch = [(_watch_value(w), w.note) for w in data.watch]
    vpn = [(v["provider"], v["country"]) for v in data.vpn
           if v.get("provider") in sources.PROVIDERS and re.fullmatch(r"[A-Z]{2}", str(v.get("country", "")))]
    now = time.time()
    with db.tx() as c:
        for r in data.asns:
            c.execute("INSERT INTO asn_rules(asn,name,action,note,updated_at) VALUES(?,?,?,?,?) "
                      "ON CONFLICT(asn) DO UPDATE SET name=excluded.name, action=excluded.action, "
                      "note=excluded.note, updated_at=excluded.updated_at",
                      (r.asn, r.name or sources.asn_name(r.asn), r.action, r.note, now))
        c.executemany("INSERT OR REPLACE INTO exemptions VALUES(?,?,?)", exemptions)
        c.executemany("INSERT OR REPLACE INTO watch_ips(ip,note) VALUES(?,?)", watch)
        c.executemany("INSERT OR IGNORE INTO vpn_rules VALUES(?,?)", vpn)
        if data.vpn_modes:
            db.put("vpn_modes", {k: v for k, v in data.vpn_modes.items() if k in sources.PROVIDERS}, c)
        db.bump_rev(c)
    db.audit(user, "import", {"asns": len(data.asns), "exemptions": len(exemptions), "watch": len(watch),
                              "vpn": len(vpn), "confirmed_own_network": confirm_own})
    return {"ok": True}


app.include_router(pub)
app.include_router(api)
