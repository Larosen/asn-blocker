"""ASN search and the Block/Captcha rules per ASN."""
import ipaddress
import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from .. import auth, db, sources, suggestions
from ..store import protection
from ..store import rules as store
from .deps import require_user, src_call

router = APIRouter(prefix="/api", dependencies=[Depends(require_user)])


@router.get("/asn/search")
def asn_search(q: str = Query(max_length=100)):
    rules = store.actions()
    try:
        ip = ipaddress.ip_address(q.strip())
    except ValueError:
        return [{**r, "rule": rules.get(r["asn"])} for r in src_call(sources.search_asn, q)]
    # An IP (e.g. from a CrowdSec alert): which network does it belong to?
    if not ip.is_global:
        raise HTTPException(422, f"{ip} is not a public address")
    info = src_call(sources.ip_info, str(ip))
    if not info["asns"]:  # not routed: there is no network to block
        try:
            holder = sources.ip_holder(str(ip))
        except sources.SourceError:
            holder = ""
        return [{"asn": None, "rule": None, "via": {"ip": str(ip), "prefix": None, "holder": holder}}]
    return [{"asn": asn, **sources.asn_info(asn), "rule": rules.get(asn), "via": {"ip": str(ip), "prefix": info.get("prefix")}}
            for asn in info["asns"]]


def _prefix_stats(asn):
    p = db.cache_get(f"prefixes:{asn}", 7 * 86400)
    if p is None:
        return None
    v4 = [ipaddress.ip_network(x) for x in p if ":" not in x]
    return {"v4": len(v4), "v6": len(p) - len(v4), "addresses": sum(n.num_addresses for n in v4)}


@router.get("/asns")
def list_asns():
    return [{**r, "stats": _prefix_stats(r["asn"])} for r in store.listing()]


@router.post("/asns/stats")
def load_stats():
    """Load prefix counts for all rules (cached) so the UI can show sizes."""
    asns = sorted(store.asns())
    src_call(sources.prefixes_many, asns)
    return {a: _prefix_stats(a) for a in asns}


class AsnRule(BaseModel):
    asn: int = Field(gt=0, lt=2**32)
    name: str = Field("", max_length=200)
    action: Literal["ban", "captcha"]
    note: str = Field("", max_length=500)
    expires_at: float | None = Field(None, gt=0, lt=4102444800)  # None = permanent


def _own_asns(request: Request) -> dict[int, str]:
    """ASNs of the network the current browser request comes from ({asn: ip}); empty if unknown."""
    ip = auth.client_ip(request)
    try:
        if not ipaddress.ip_address(ip).is_global:
            return {}
        return {a: ip for a in sources.ip_info(ip)["asns"]}
    except (ValueError, sources.SourceError):
        return {}


def guard_own_asn(asns, request: Request, confirmed: bool):
    """Blocking the network you are connected from needs an explicit confirmation (e.g. a hotel or office network)."""
    new = set(asns) - store.asns()
    own = _own_asns(request) if new else {}
    hit = sorted(new & set(own))
    if hit and not confirmed:
        raise HTTPException(409, {"code": "own_asn", "asns": hit, "ip": own[hit[0]],
                                  "message": f"AS{hit[0]} is the network you are connected from ({own[hit[0]]}). "
                                             "Blocking it can lock you out of this page."})


def guard_protected(rules):
    """Protected ASNs: no rules at all ('never block'), or captcha only ('at most captcha')."""
    blocked = sorted({r.asn for r in rules} & protection.asns("exempt"))
    if blocked:
        raise HTTPException(422, "Self-protection: " + ", ".join(f"AS{a}" for a in blocked)
                            + " is protected and cannot be blocked")
    capped = sorted({r.asn for r in rules if r.action == "ban"} & protection.asns("captcha"))
    if capped:
        raise HTTPException(422, "Self-protection: " + ", ".join(f"AS{a}" for a in capped)
                            + " is protected against bans – use Captcha")


def rows(rules):
    """Validated rules -> store rows (names filled in from the local ASN list)."""
    return [r.model_dump() | {"name": r.name or sources.asn_name(r.asn)} for r in rules]


@router.get("/asns/suggestions")
def asn_suggestions():
    existing, protected = store.asns(), protection.asns()
    return {"spamhaus": db.get("spamhaus_asndrop"), "lists": [
        {k: v for k, v in lst.items() if k != "asns"}
        | {"asns": [{"asn": a, "name": sources.asn_name(a) or label, "note": label, "present": a in existing,
                     "protected": a in protected} for a, label in lst["asns"]]}
        for lst in suggestions.LISTS]}


@router.put("/asns")
def put_asns(rules: list[AsnRule], request: Request, confirm_own: bool = Query(False), user: str = Depends(require_user)):
    if len(rules) > 5000:
        raise HTTPException(422, "At most 5000 rules per request")
    guard_protected(rules)
    guard_own_asn([r.asn for r in rules], request, confirm_own)
    store.upsert(rows(rules))
    db.audit(user, "asn.put", [r.model_dump() for r in rules] + ([{"confirmed_own_network": True}] if confirm_own else []))
    return {"ok": True}


@router.delete("/asns/{asn}")
def delete_asn(asn: int, user: str = Depends(require_user)):
    store.delete([asn])
    db.audit(user, "asn.delete", {"asn": asn})
    return {"ok": True}


class AsnDelete(BaseModel):
    asns: list[int] = Field(max_length=5000)


@router.post("/asns/delete")
def delete_asns(body: AsnDelete, user: str = Depends(require_user)):
    store.delete(body.asns)
    db.audit(user, "asn.delete", {"asns": body.asns})
    return {"ok": True}


class AsnImport(BaseModel):
    text: str = Field(max_length=200_000)
    action: Literal["ban", "captcha"]


ASN_LINE = re.compile(r"^\s*(?:AS)?(\d{1,10})\b[\s,;]*(?:#\s*)?(.*)$", re.I)


@router.post("/asns/parse")
def parse_asns(body: AsnImport):
    """Free text, one ASN per line with an optional comment -> preview. Commented-out lines are ignored."""
    out = []
    for line in body.text.splitlines():
        if line.strip().startswith("#"):
            continue
        m = ASN_LINE.match(line)
        if m and 0 < int(m.group(1)) < 2**32:
            asn = int(m.group(1))
            out.append({"asn": asn, "name": sources.asn_name(asn), "note": m.group(2).strip()[:500],
                        "action": body.action})
    return out
