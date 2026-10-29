import logging
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import VERSION, auth, crowdsec, db, engine, logs  # noqa: F401 - main.VERSION; tests patch main.crowdsec.backend
from .store import runs as runs_store

logs.setup()
log = logging.getLogger("asn_blocker")

STATIC = Path(__file__).parent / "static"
logging.getLogger("uvicorn.access").addFilter(lambda r: "/healthz" not in r.getMessage())


@asynccontextmanager
async def lifespan(_app):
    db.init()
    runs_store.mark_interrupted()
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




@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/healthz", include_in_schema=False)
def healthz():
    db.q1("SELECT 1 x")
    return {"ok": True}


from .api import attackers as attackers_api  # noqa: E402 - the routers import this module's app-wide pieces lazily
from .api import events, exemptions, overview, rules, runs, session, settings, transfer, vpn  # noqa: E402
from .api.deps import require_user  # noqa: E402,F401 - kept for callers that import it from here

app.include_router(session.public)
for _r in (session, overview, rules, vpn, exemptions, attackers_api, settings, runs, transfer, events):
    app.include_router(_r.router)
