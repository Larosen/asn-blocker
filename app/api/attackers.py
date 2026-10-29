"""Networks behind CrowdSec's own detections."""
import time

from fastapi import APIRouter, Depends, HTTPException, Query

from .. import attackers, crowdsec
from .deps import require_user

router = APIRouter(prefix="/api", dependencies=[Depends(require_user)])


@router.get("/attackers")
def get_attackers(days: int = Query(7)):
    return attackers.report(days)


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
