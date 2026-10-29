"""Initial setup, sign-in and the account."""
import hmac
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator

from .. import VERSION, auth, db
from .deps import require_user

router = APIRouter(prefix="/api", dependencies=[Depends(require_user)])
public = APIRouter(prefix="/api")


@public.get("/session")
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


@public.post("/setup/auth")
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


@public.post("/login")
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


@public.post("/logout")
def logout(request: Request, response: Response):
    auth.drop_session(request.cookies.get(auth.SESSION_COOKIE))
    response.delete_cookie(auth.SESSION_COOKIE, path="/")
    return {"ok": True}


class Password(BaseModel):
    current: str = Field(max_length=auth.MAX_PASSWORD)
    new: str = Field(min_length=12, max_length=auth.MAX_PASSWORD)


@router.put("/account/password")
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
