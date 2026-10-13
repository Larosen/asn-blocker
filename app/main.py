import ipaddress
import secrets
import threading
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field

from . import config, engine, sources

security = HTTPBasic(auto_error=False)


def auth(cred: HTTPBasicCredentials | None = Depends(security)):
    if not config.ADMIN_PASSWORD:
        return
    if not cred or not (secrets.compare_digest(cred.username, config.ADMIN_USER)
                        and secrets.compare_digest(cred.password, config.ADMIN_PASSWORD)):
        raise HTTPException(401, headers={"WWW-Authenticate": "Basic"})


app = FastAPI(title="ASN Blocker", dependencies=[Depends(auth)])
STATIC = Path(__file__).parent / "static"


@app.on_event("startup")
def _start():
    st = config.load_state()
    st["running"] = False  # nach Neustart nicht haengenbleiben
    config.save_state(st)
    threading.Thread(target=engine.scheduler, daemon=True).start()


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


def _src(fn, *a):
    try:
        return fn(*a)
    except sources.SourceError as e:
        raise HTTPException(502, str(e))


# --- ASNs ---------------------------------------------------------------------

@app.get("/api/asn/search")
def asn_search(q: str):
    return _src(sources.search_asn, q)


class AsnEntry(BaseModel):
    asn: int = Field(gt=0, lt=2**32)
    name: str = ""
    action: str = Field(pattern="^(ban|captcha)$")
    note: str = ""


@app.get("/api/config")
def get_config():
    return config.load_config()


@app.put("/api/asns")
def put_asn(e: AsnEntry):
    cfg = config.load_config()
    cfg["asns"] = [a for a in cfg["asns"] if a["asn"] != e.asn] + [e.model_dump()]
    cfg["asns"].sort(key=lambda a: a["asn"])
    config.save_config(cfg)
    return cfg


@app.delete("/api/asns/{asn}")
def del_asn(asn: int):
    cfg = config.load_config()
    cfg["asns"] = [a for a in cfg["asns"] if a["asn"] != asn]
    config.save_config(cfg)
    return cfg


# --- VPN-Whitelist --------------------------------------------------------------

@app.get("/api/vpn/providers")
def providers():
    return [{"id": p.id, "name": p.name, "note": p.note} for p in sources.PROVIDERS.values()]


@app.get("/api/vpn/{provider}/countries")
def vpn_countries(provider: str):
    p = sources.PROVIDERS.get(provider) or _404()
    return _src(p.countries)


class VpnSelection(BaseModel):
    countries: list[str]


@app.put("/api/vpn/{provider}")
def put_vpn(provider: str, sel: VpnSelection):
    if provider not in sources.PROVIDERS:
        _404()
    cfg = config.load_config()
    cfg["vpn_whitelist"] = [v for v in cfg["vpn_whitelist"] if v["provider"] != provider] + \
        [{"provider": provider, "country": c.upper()} for c in sorted(set(sel.countries))]
    config.save_config(cfg)
    return cfg


# --- weitere Ausnahmen / Optionen ----------------------------------------------------

class Settings(BaseModel):
    exempt_asns: list[int]
    manual_exempt: list[str]
    widen_vpn_ips: bool
    include_ipv6: bool


@app.put("/api/settings")
def put_settings(s: Settings):
    for v in s.manual_exempt:
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise HTTPException(422, f"Ungueltige IP/CIDR: {v}")
    cfg = config.load_config()
    cfg.update(s.model_dump())
    config.save_config(cfg)
    return cfg


# --- Ausfuehrung ----------------------------------------------------------------------

@app.get("/api/status")
def status():
    st = config.load_state()
    st.pop("ranges", None)
    st["interval_hours"] = config.UPDATE_INTERVAL_HOURS
    st["container"] = config.CROWDSEC_CONTAINER
    return st


@app.post("/api/run")
def run(dry_run: bool = False):
    if config.load_state().get("running"):
        raise HTTPException(409, "Update laeuft bereits")
    threading.Thread(target=lambda: _safe_run(dry_run), daemon=True).start()
    return {"started": True}


def _safe_run(dry_run):
    try:
        engine.run(dry_run)
    except engine.Abort:
        pass


@app.get("/api/ranges/{typ}", response_class=PlainTextResponse)
def ranges(typ: str):
    r = config.load_state().get("ranges", {}).get(typ)
    if r is None:
        _404()
    return "\n".join(r) + "\n"


def _404():
    raise HTTPException(404)
