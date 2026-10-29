"""VPN exemptions per provider and country."""
import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from .. import db, sources
from ..store import vpn as store
from .deps import require_user, src_call

router = APIRouter(prefix="/api", dependencies=[Depends(require_user)])


@router.get("/vpn/providers")
def providers():
    modes, sel = store.modes(), store.selections()
    return [{"id": p.id, "name": p.name, "note": p.note, "exit_asn": p.exit_asn, "mode": modes.get(p.id, "exact"),
             "countries": sorted(sel.get(p.id, []))} for p in sources.PROVIDERS.values()]


def _provider(pid):
    p = sources.PROVIDERS.get(pid)
    if not p:
        raise HTTPException(404, "Unknown provider")
    return p


@router.get("/vpn/{pid}/countries")
def vpn_countries(pid: str):
    return src_call(_provider(pid).countries)


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


@router.put("/vpn/{pid}")
def put_vpn(pid: str, sel: VpnSel, user: str = Depends(require_user)):
    _provider(pid)
    store.select(pid, sel.countries, sel.mode)
    db.audit(user, "vpn.put", {"provider": pid, **sel.model_dump()})
    return {"ok": True}
