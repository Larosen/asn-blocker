"""Networks behind CrowdSec's own detections."""
import time
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, field_validator

from .. import attackers, crowdsec, db
from .deps import require_user

router = APIRouter(prefix="/api", dependencies=[Depends(require_user)])


@router.get("/attackers")
def get_attackers(days: int = Query(7)):
    return attackers.report(days) | {"auto": attackers.auto_settings()}


class Auto(BaseModel):
    mode: Literal["captcha", "recommended"] | None
    days: int

    @field_validator("days")
    @classmethod
    def _days(cls, v):
        if v not in attackers.AUTO_DAYS:
            raise ValueError(f"days must be one of {attackers.AUTO_DAYS}")
        return v


@router.put("/attackers/auto")
def put_auto(a: Auto, user: str = Depends(require_user)):
    with db.tx() as c:
        db.put("attackers_auto", a.mode, c)
        db.put("attackers_auto_days", a.days, c)
    db.audit(user, "attackers.auto.put", a.model_dump())
    return {"ok": True, "added": len(attackers.auto_rules())}  # switching it on acts on the current recommendations


_refreshed = [0.0]


@router.post("/attackers/refresh")
def refresh_attackers(user: str = Depends(require_user)):
    if time.time() - _refreshed[0] < 30:
        raise HTTPException(429, "Updated a moment ago – please wait a few seconds")
    _refreshed[0] = time.time()
    try:
        n = attackers.collect()
    except crowdsec.CrowdSecError as e:
        raise HTTPException(502, str(e))
    return {"ok": True, "new_alerts": n}


@router.get("/attackers/{asn}")
def get_attacker_ips(asn: int, days: int = Query(7)):
    return attackers.ips_of(asn, days)
