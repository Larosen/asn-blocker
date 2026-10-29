"""Export and import of the configuration."""
import re
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field

from .. import db, sources
from ..store import exemptions as exemption_store
from ..store import rules as rule_store
from ..store import vpn as vpn_store
from ..store import watch as watch_store
from .deps import require_user
from .exemptions import Exemption, Watch, exemption_value, watch_value
from .rules import AsnRule, guard_own_asn, guard_protected, rows

router = APIRouter(prefix="/api", dependencies=[Depends(require_user)])


@router.get("/export")
def export():
    return {"version": 1, "asns": rule_store.export(), "vpn": vpn_store.export(), "vpn_modes": vpn_store.modes(),
            "exemptions": exemption_store.export(), "watch": watch_store.export()}


class ImportData(BaseModel):
    version: Literal[1]
    asns: list[AsnRule] = Field([], max_length=5000)
    vpn: list[dict] = Field([], max_length=5000)
    vpn_modes: dict[str, Literal["exact", "net"]] | None = None
    exemptions: list[Exemption] = Field([], max_length=5000)
    watch: list[Watch] = Field([], max_length=1000)


@router.post("/import")
def import_cfg(data: ImportData, request: Request, confirm_own: bool = Query(False), user: str = Depends(require_user)):
    """Everything is validated first and written in one transaction – an invalid entry changes nothing."""
    guard_protected(data.asns)
    guard_own_asn([r.asn for r in data.asns], request, confirm_own)
    exemptions = [(e.kind, exemption_value(e), e.note) for e in data.exemptions]
    watch = [(watch_value(w), w.note) for w in data.watch]
    vpn = [(v["provider"], v["country"]) for v in data.vpn
           if v.get("provider") in sources.PROVIDERS and re.fullmatch(r"[A-Z]{2}", str(v.get("country", "")))]
    modes = {k: v for k, v in data.vpn_modes.items() if k in sources.PROVIDERS} if data.vpn_modes else None
    with db.tx() as c:
        rule_store.upsert(rows(data.asns), c=c)
        exemption_store.add(exemptions, c=c)
        watch_store.add(watch, c=c)
        vpn_store.add(vpn, modes, c=c)
    db.audit(user, "import", {"asns": len(data.asns), "exemptions": len(exemptions), "watch": len(watch),
                              "vpn": len(vpn), "confirmed_own_network": confirm_own})
    return {"ok": True}
