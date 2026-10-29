"""Exemptions, watched IPs and self-protection."""
import ipaddress
import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .. import auth, db, engine, selfprotect, sources
from ..store import exemptions as store
from ..store import protection, runs, watch
from ..store import rules as rule_store
from .deps import require_user

router = APIRouter(prefix="/api", dependencies=[Depends(require_user)])


class Exemption(BaseModel):
    kind: Literal["asn", "cidr"]
    value: str = Field(max_length=64)
    note: str = Field("", max_length=300)


@router.get("/exemptions")
def list_exemptions():
    rows = store.listing()
    for r in rows:
        if r["kind"] == "asn":
            r["name"] = sources.asn_name(int(r["value"]))
    return rows


def _asn(v: str) -> int:
    digits = v.strip().upper().removeprefix("AS")
    if not re.fullmatch(r"[0-9]{1,10}", digits) or not 0 < int(digits) < 2**32:
        raise ValueError(v)
    return int(digits)


def exemption_value(e: Exemption) -> str:
    try:
        if e.kind == "asn":
            return str(_asn(e.value))
        net = ipaddress.ip_network(e.value.strip(), strict=False)
    except ValueError:
        raise HTTPException(422, f"Invalid: {e.value}")
    if net.prefixlen < engine.MIN_PREFIXLEN[net.version]:  # would silently switch off blocking for huge areas
        raise HTTPException(422, f"{net} is too large for an exemption (at most /{engine.MIN_PREFIXLEN[net.version]})")
    return str(net)


@router.post("/exemptions")
def add_exemption(e: Exemption, user: str = Depends(require_user)):
    value = exemption_value(e)
    store.add([(e.kind, value, e.note)])
    db.audit(user, "exemption.add", {"kind": e.kind, "value": value})
    return {"ok": True, "value": value}


@router.delete("/exemptions/{kind}/{value:path}")
def delete_exemption(kind: str, value: str, user: str = Depends(require_user)):
    store.delete(kind, value)
    db.audit(user, "exemption.delete", {"kind": kind, "value": value})
    return {"ok": True}


class Watch(BaseModel):
    ip: str = Field(max_length=64)
    note: str = Field("", max_length=300)


def watch_value(w: Watch) -> str:
    try:
        return str(ipaddress.ip_address(w.ip.strip()))
    except ValueError:
        raise HTTPException(422, f"Not a valid IP: {w.ip}")


@router.get("/watch")
def list_watch():
    return watch.listing()


@router.post("/watch")
def add_watch(w: Watch, user: str = Depends(require_user)):
    ip = watch_value(w)
    watch.add([(ip, w.note)])
    db.audit(user, "watch.add", {"ip": ip})
    return {"ok": True}


@router.delete("/watch/{ip}")
def delete_watch(ip: str, user: str = Depends(require_user)):
    watch.delete(ip)
    db.audit(user, "watch.delete", {"ip": ip})
    return {"ok": True}


@router.get("/protect")
def get_protect(request: Request):
    sessions, utmp = selfprotect.ssh_sessions()
    applied = runs.applied()
    rows = protection.listing()
    modes = {int(r["value"]): r["mode"] for r in rows if r["kind"] == "asn"}
    for s in sessions:
        s["status"] = engine.status_of(s["ip"], applied)
        try:
            asns = sources.ip_info(s["ip"])["asns"]
        except sources.SourceError:
            asns = []
        s["asns"] = [{"asn": a, "name": sources.asn_name(a), "protected": modes.get(a)} for a in asns]
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
    with_asn: bool = False
    asn_mode: Literal["exempt", "captcha"] = "captcha"
    note: str = Field("", max_length=200)


@router.post("/protect")
def add_protect(body: Protect, user: str = Depends(require_user)):
    try:
        asns = selfprotect.protect_ip(body.ip.strip(), body.note or f"by {user}", body.with_asn, body.asn_mode)
    except ValueError:
        raise HTTPException(422, "Not a valid IP address")
    except sources.SourceError as e:
        raise HTTPException(502, str(e))
    rule_store.apply_protection(asns, body.asn_mode)
    db.audit(user, "protect.add", {"ip": body.ip, "asns": asns, "asn_mode": body.asn_mode if asns else None})
    return {"ok": True, "asns": asns}


class ProtectMode(BaseModel):
    mode: Literal["exempt", "captcha"]


@router.put("/protect/asn/{asn}")
def set_protect_mode(asn: int, body: ProtectMode, user: str = Depends(require_user)):
    if not protection.set_mode(asn, body.mode):
        raise HTTPException(404, f"AS{asn} is not protected")
    rule_store.apply_protection([asn], body.mode)
    db.audit(user, "protect.mode", {"asn": asn, "mode": body.mode})
    return {"ok": True}


@router.delete("/protect/{kind}/{value:path}")
def delete_protect(kind: str, value: str, user: str = Depends(require_user)):
    protection.delete(kind, value)
    db.audit(user, "protect.delete", {"kind": kind, "value": value})
    return {"ok": True}
