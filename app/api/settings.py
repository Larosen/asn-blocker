"""Settings, notifications and the CrowdSec connection."""
import threading
import time
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from .. import auth, crowdsec, db, engine, notify
from .deps import require_user

router = APIRouter(prefix="/api", dependencies=[Depends(require_user)])


PUBLIC_SETTINGS = ["interval_hours", "decision_hours", "include_ipv6", "sanity_percent", "notify_url",
                   "notify_format", "spamhaus_asndrop", "trusted_proxies", "auth_user_header", "auth_mode",
                   "crowdsec_mode", "lapi_url", "lapi_machine_id", "docker_container", "local_user"]


@router.get("/settings")
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


@router.put("/settings")
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


@router.post("/notify/test")
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


@router.put("/notify")
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


@router.put("/crowdsec")
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


@router.post("/crowdsec/cleanup")
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
