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

from . import auth, crowdsec, db, engine, notify, sources

STATIC = Path(__file__).parent / "static"
logging.getLogger("uvicorn.access").addFilter(lambda r: "/healthz" not in r.getMessage())
VERSION = "0.2.0"


@asynccontextmanager
async def lifespan(_app):
    db.init()
    with db.tx() as c:
        c.execute("UPDATE runs SET status='failed', finished_at=? WHERE status='running'", (time.time(),))
    if not db.get("auth_mode"):
        print("=" * 60 + f"\nErsteinrichtung: Setup-Token = {auth.SETUP_TOKEN}\n" + "=" * 60, flush=True)
    threading.Thread(target=engine.scheduler, daemon=True, name="scheduler").start()
    yield


app = FastAPI(title="asn-blocker", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=STATIC), name="static")

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "font-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


@app.middleware("http")
async def guard(request: Request, call_next):
    # CSRF: aendernde Requests nur mit eigenem Header (erzwingt CORS-Preflight) und passendem Origin
    if request.method not in ("GET", "HEAD", "OPTIONS") and request.url.path.startswith("/api/"):
        if request.headers.get("x-requested-with") != "asn-blocker":
            return JSONResponse({"detail": "CSRF-Header fehlt"}, 403)
        origin = request.headers.get("origin")
        if origin:
            host = request.headers.get("host", "")
            if auth._trusted(auth.peer_ip(request)):
                host = request.headers.get("x-forwarded-host", host)
            if urlsplit(origin).netloc != host.split(",")[0].strip():
                return JSONResponse({"detail": "Origin passt nicht"}, 403)
    resp = await call_next(request)
    h = resp.headers
    h["Content-Security-Policy"] = CSP
    h["X-Content-Type-Options"] = "nosniff"
    h["Referrer-Policy"] = "no-referrer"
    h["X-Frame-Options"] = "DENY"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), interest-cohort=()"
    if request.url.path.startswith("/api/"):
        h["Cache-Control"] = "no-store"
    return resp


def require_user(request: Request) -> str:
    if not db.get("auth_mode"):
        raise HTTPException(409, "Ersteinrichtung nicht abgeschlossen")
    user = auth.current_user(request)
    if not user:
        raise HTTPException(401, "Nicht angemeldet")
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


# --- Sitzung / Ersteinrichtung --------------------------------------------------------------------

@pub.get("/session")
def session(request: Request):
    user = auth.current_user(request)
    return {"setup_required": not db.get("auth_mode"), "auth_mode": db.get("auth_mode"), "user": user,
            "peer_ip": auth.peer_ip(request) if not user and not db.get("auth_mode") else None,
            "crowdsec_configured": bool(db.get("crowdsec_mode")) if user else None, "version": VERSION}


class SetupAuth(BaseModel):
    token: str
    mode: Literal["proxy", "local"]
    user_header: str = Field("Remote-User", pattern=r"^[A-Za-z0-9-]{1,64}$")
    trusted_proxies: list[str] = []
    username: str = Field("admin", pattern=r"^[\w.@-]{1,64}$")
    password: str = ""

    @field_validator("trusted_proxies")
    @classmethod
    def _cidrs(cls, v):
        return [str(ipaddress.ip_network(x.strip(), strict=False)) for x in v if x.strip()]


@pub.post("/setup/auth")
def setup_auth(s: SetupAuth, request: Request, response: Response):
    if db.get("auth_mode"):
        raise HTTPException(409, "Bereits eingerichtet")
    auth.check_setup_token(s.token, auth.peer_ip(request))
    if s.mode == "proxy":
        if not s.trusted_proxies:
            raise HTTPException(422, "Mindestens ein vertrauenswürdiger Proxy (IP/CIDR) nötig")
        peer = auth.peer_ip(request)
        if not auth.ip_in(peer, s.trusted_proxies) or not request.headers.get(s.user_header):
            raise HTTPException(422, f"Diese Anfrage kam von {peer} "
                                     f"{'mit' if request.headers.get(s.user_header) else 'ohne'} Header {s.user_header}. "
                                     "Mit diesen Einstellungen würdest du dich aussperren. "
                                     "Rufe die Einrichtung über den Reverse Proxy mit SSO auf.")
    elif len(s.password) < 12:
        raise HTTPException(422, "Passwort: mindestens 12 Zeichen")
    with db.tx() as c:
        db.put("auth_mode", s.mode, c)
        db.put("auth_user_header", s.user_header, c)
        db.put("trusted_proxies", s.trusted_proxies, c)
        if s.mode == "local":
            db.put("local_user", s.username, c)
            db.put("local_password_hash", auth.hash_password(s.password), c)
    user = s.username if s.mode == "local" else request.headers.get(s.user_header)
    if s.mode == "local":
        _set_cookie(response, request, auth.create_session(s.username))
    db.audit(user, "setup.auth", {"mode": s.mode})
    return {"ok": True}


def _set_cookie(response, request, token):
    response.set_cookie(auth.SESSION_COOKIE, token, max_age=auth.SESSION_TTL, httponly=True,
                        secure=auth.is_https(request), samesite="strict", path="/")


class Login(BaseModel):
    username: str
    password: str


@pub.post("/login")
def login(body: Login, request: Request, response: Response):
    if db.get("auth_mode") != "local":
        raise HTTPException(400, "Lokaler Login ist nicht aktiv")
    ip = auth.client_ip(request)
    auth.throttle(ip)
    if body.username != db.get("local_user") or not auth.verify_password(body.password, db.get("local_password_hash")):
        auth.record_failure(ip)
        raise HTTPException(401, "Benutzername oder Passwort falsch")
    _set_cookie(response, request, auth.create_session(body.username))
    db.audit(body.username, "login", {"ip": ip})
    return {"ok": True}


@pub.post("/logout")
def logout(request: Request, response: Response):
    auth.drop_session(request.cookies.get(auth.SESSION_COOKIE))
    response.delete_cookie(auth.SESSION_COOKIE, path="/")
    return {"ok": True}


class Password(BaseModel):
    current: str
    new: str = Field(min_length=12)


@api.put("/account/password")
def change_password(body: Password, user: str = Depends(require_user)):
    if db.get("auth_mode") != "local" or not auth.verify_password(body.current, db.get("local_password_hash")):
        raise HTTPException(400, "Aktuelles Passwort falsch")
    db.put("local_password_hash", auth.hash_password(body.new))
    auth.drop_all_sessions()
    db.audit(user, "account.password")
    return {"ok": True}


# --- Uebersicht ------------------------------------------------------------------------------------

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
    return [{**r, "rule": rules.get(r["asn"])} for r in _src(sources.search_asn, q)]


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
    """Prefix-Zahlen fuer alle Regeln laden (gecacht), damit die UI Groessen zeigen kann."""
    asns = [r["asn"] for r in db.q("SELECT asn FROM asn_rules")]
    _src(sources.prefixes_many, asns)
    return {a: _prefix_stats(a) for a in asns}


class AsnRule(BaseModel):
    asn: int = Field(gt=0, lt=2**32)
    name: str = Field("", max_length=200)
    action: Literal["ban", "captcha"]
    note: str = Field("", max_length=500)


@api.put("/asns")
def put_asns(rules: list[AsnRule], user: str = Depends(require_user)):
    now = time.time()
    with db.tx() as c:
        for r in rules:
            name = r.name or sources.asn_name(r.asn)
            c.execute("INSERT INTO asn_rules(asn,name,action,note,updated_at) VALUES(?,?,?,?,?) "
                      "ON CONFLICT(asn) DO UPDATE SET name=excluded.name, action=excluded.action, "
                      "note=excluded.note, updated_at=excluded.updated_at", (r.asn, name, r.action, r.note, now))
        db.bump_rev(c)
    db.audit(user, "asn.put", [r.model_dump() for r in rules])
    return {"ok": True}


@api.delete("/asns/{asn}")
def delete_asn(asn: int, user: str = Depends(require_user)):
    with db.tx() as c:
        c.execute("DELETE FROM asn_rules WHERE asn=?", (asn,))
        db.bump_rev(c)
    db.audit(user, "asn.delete", {"asn": asn})
    return {"ok": True}


class AsnImport(BaseModel):
    text: str = Field(max_length=200_000)
    action: Literal["ban", "captcha"]


ASN_LINE = re.compile(r"^\s*(?:AS)?(\d{1,10})\b[\s,;]*(?:#\s*)?(.*)$", re.I)


@api.post("/asns/parse")
def parse_asns(body: AsnImport):
    """Freitext (z.B. ASN_LIST aus dem Bash-Skript) -> Vorschau. Auskommentierte Zeilen werden ignoriert."""
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
        raise HTTPException(404, "Unbekannter Anbieter")
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
            raise ValueError("Ländercodes müssen zweistellig sein")
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


# --- Ausnahmen & Waechter-IPs ----------------------------------------------------------------------

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


@api.post("/exemptions")
def add_exemption(e: Exemption, user: str = Depends(require_user)):
    try:
        value = str(int(e.value.upper().removeprefix("AS"))) if e.kind == "asn" else \
            str(ipaddress.ip_network(e.value.strip(), strict=False))
    except ValueError:
        raise HTTPException(422, f"Ungültig: {e.value}")
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
    ip: str
    note: str = Field("", max_length=300)


@api.get("/watch")
def list_watch():
    return db.q("SELECT * FROM watch_ips ORDER BY ip")


@api.post("/watch")
def add_watch(w: Watch, user: str = Depends(require_user)):
    try:
        ip = str(ipaddress.ip_address(w.ip.strip()))
    except ValueError:
        raise HTTPException(422, f"Keine gültige IP: {w.ip}")
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


@api.get("/check/{ip}")
def check(ip: str):
    try:
        return engine.check_ip(ip)
    except ValueError:
        raise HTTPException(422, "Keine gültige IP-Adresse")


# --- Einstellungen ---------------------------------------------------------------------------------------

PUBLIC_SETTINGS = ["interval_hours", "decision_hours", "include_ipv6", "sanity_percent", "notify_url",
                   "notify_format", "spamhaus_asndrop", "trusted_proxies", "auth_user_header", "auth_mode",
                   "crowdsec_mode", "lapi_url", "lapi_machine_id", "docker_container", "local_user"]


@api.get("/settings")
def get_settings():
    return {k: db.get(k) for k in PUBLIC_SETTINGS} | {"lapi_password_set": bool(db.get("lapi_password"))}


class Settings(BaseModel):
    interval_hours: int = Field(ge=6, le=24 * 14)
    decision_hours: int = Field(ge=24, le=24 * 365 * 3)
    include_ipv6: bool
    sanity_percent: int = Field(ge=5, le=100)
    notify_url: str = Field("", max_length=500, pattern=r"^(https?://\S+)?$")
    notify_format: Literal["ntfy", "gotify", "webhook"]
    spamhaus_asndrop: Literal["ban", "captcha"] | None
    trusted_proxies: list[str]
    auth_user_header: str = Field(pattern=r"^[A-Za-z0-9-]{1,64}$")

    @field_validator("trusted_proxies")
    @classmethod
    def _cidrs(cls, v):
        return [str(ipaddress.ip_network(x.strip(), strict=False)) for x in v if x.strip()]


@api.put("/settings")
def put_settings(s: Settings, request: Request, user: str = Depends(require_user)):
    if s.decision_hours < s.interval_hours * 2:
        raise HTTPException(422, "Decision-Dauer muss mindestens das Doppelte des Intervalls sein")
    if db.get("auth_mode") == "proxy":
        if not auth.ip_in(auth.peer_ip(request), s.trusted_proxies) or not request.headers.get(s.auth_user_header):
            raise HTTPException(422, "Mit diesen Proxy-Einstellungen würdest du dich aussperren")
    affects = {k: db.get(k) for k in ("include_ipv6", "spamhaus_asndrop")} != \
        {"include_ipv6": s.include_ipv6, "spamhaus_asndrop": s.spamhaus_asndrop}
    with db.tx() as c:
        for k, v in s.model_dump().items():
            db.put(k, v, c)
        if affects:
            db.bump_rev(c)
    db.audit(user, "settings.put", s.model_dump())
    return {"ok": True}


@api.post("/notify/test")
def notify_test():
    if not db.get("notify_url"):
        raise HTTPException(400, "Keine Benachrichtigungs-URL gespeichert")
    notify.send("asn-blocker: Test", "Benachrichtigungen funktionieren.", "info")
    return {"ok": True}


class CrowdSecCfg(BaseModel):
    mode: Literal["lapi", "docker"]
    lapi_url: str = Field("http://crowdsec:8080", pattern=r"^https?://[^\s/]+(:\d+)?/?$")
    machine_id: str = Field("", max_length=128)
    password: str = Field("", max_length=512)   # leer = bisheriges behalten
    container: str = Field("crowdsec", pattern=r"^[\w.-]{1,128}$")


@api.put("/crowdsec")
def put_crowdsec(cfg: CrowdSecCfg, user: str = Depends(require_user)):
    password = cfg.password or db.get("lapi_password")
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
    """Decisions eines alten Skripts (z.B. 'Auto-Block via ASN Bulk') entfernen."""
    if body.reason in engine.REASONS.values():
        raise HTTPException(422, "Eigene Decisions werden über Läufe verwaltet")
    try:
        n = crowdsec.backend().delete_scenario(body.reason)
    except crowdsec.CrowdSecError as e:
        raise HTTPException(502, str(e))
    db.audit(user, "crowdsec.cleanup", {"reason": body.reason, "deleted": n})
    return {"deleted": n}


# --- Laeufe --------------------------------------------------------------------------------------------------

class RunReq(BaseModel):
    kind: Literal["plan", "apply"]
    force: bool = False


@api.post("/runs")
def start_run(body: RunReq, user: str = Depends(require_user)):
    if engine.is_running():
        raise HTTPException(409, "Es läuft bereits ein Lauf")
    if body.kind == "apply" and not db.get("crowdsec_mode"):
        raise HTTPException(409, "CrowdSec-Verbindung ist noch nicht eingerichtet")

    def go():
        try:
            engine.run(body.kind, user, body.force)
        except engine.Busy:
            pass

    threading.Thread(target=go, daemon=True).start()
    if body.kind == "apply":
        db.audit(user, "run.apply", {"force": body.force})
    return {"ok": True}


@api.get("/runs")
def list_runs(limit: int = 30):
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
def audit_log(limit: int = 200):
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
    asns: list[AsnRule] = []
    vpn: list[dict] = []
    vpn_modes: dict[str, Literal["exact", "net"]] | None = None
    exemptions: list[Exemption] = []
    watch: list[Watch] = []


@api.post("/import")
def import_cfg(data: ImportData, user: str = Depends(require_user)):
    put_asns(data.asns, user)
    for e in data.exemptions:
        add_exemption(e, user)
    for w in data.watch:
        add_watch(w, user)
    with db.tx() as c:
        for v in data.vpn:
            if v.get("provider") in sources.PROVIDERS and re.fullmatch(r"[A-Z]{2}", str(v.get("country", ""))):
                c.execute("INSERT OR IGNORE INTO vpn_rules VALUES(?,?)", (v["provider"], v["country"]))
        if data.vpn_modes:
            db.put("vpn_modes", {k: v for k, v in data.vpn_modes.items() if k in sources.PROVIDERS}, c)
        db.bump_rev(c)
    db.audit(user, "import", {"asns": len(data.asns)})
    return {"ok": True}


app.include_router(pub)
app.include_router(api)
