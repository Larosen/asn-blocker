"""Overview, IP check, applied ranges and the audit log."""
import ipaddress
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

from .. import attackers, auth, db, engine, sources
from ..store import exemptions, runs, vpn, watch
from ..store import rules as rule_store
from .deps import require_user

router = APIRouter(prefix="/api", dependencies=[Depends(require_user)])


@router.get("/overview")
def overview(request: Request, user: str = Depends(require_user)):
    ip = auth.client_ip(request)
    me = None
    try:
        ipaddress.ip_address(ip)
        me = {"ip": ip, "status": engine.status_of(ip, runs.applied())}
    except ValueError:
        pass
    counts = runs.applied_counts(engine.REASONS)
    return {
        "user": user, "auth_mode": db.get("auth_mode"), "me": me, "applied": counts,
        "rules": {"asns": rule_store.count(), "vpn": vpn.count(), "exemptions": exemptions.count(), "watch": watch.count()},
        "pending": db.get("config_rev") != db.get("applied_rev"),
        "rev": db.get("config_rev"),
        "running": engine.is_running(), "next_run": engine.next_due(),
        "last_apply": runs.last_apply(),
        "crowdsec_mode": db.get("crowdsec_mode"), "interval_hours": db.get("interval_hours"),
        "asn_names": sources.asn_count(),
        "attackers_recommended": attackers.report(7)["recommended"],
        "untrusted_proxy": auth.untrusted_proxy(request) if db.get("auth_mode") == "local" else None,
        "broad_proxies": auth.broad_trusted_proxies(),
    }


@router.get("/check/{ip}")
def check(ip: str):
    try:
        return engine.check_ip(ip)
    except ValueError:
        raise HTTPException(422, "Not a valid IP address")


@router.get("/ranges/{typ}.txt", response_class=PlainTextResponse)
def ranges(typ: Literal["ban", "captcha"]):
    return "".join(v + "\n" for v in runs.applied_values(typ))


@router.get("/audit")
def audit_log(limit: int = Query(200, ge=1, le=1000)):
    return db.audit_log(min(limit, 1000))
