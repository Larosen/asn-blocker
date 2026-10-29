"""Runs: start, preview and history."""
import threading
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from .. import db, engine
from ..store import runs as store
from .deps import require_user

router = APIRouter(prefix="/api", dependencies=[Depends(require_user)])


class RunReq(BaseModel):
    kind: Literal["plan", "apply"]
    confirm: int | None = None  # ID of the stopped run whose result the user reviewed and accepts


@router.post("/runs")
def start_run(body: RunReq, user: str = Depends(require_user)):
    if engine.is_running():
        raise HTTPException(409, "A run is already in progress")
    if body.kind == "apply" and not db.get("crowdsec_mode"):
        raise HTTPException(409, "CrowdSec connection is not set up yet")
    confirmed = None
    if body.confirm is not None:
        last = store.last_apply()
        if body.kind != "apply" or not last or last["id"] != body.confirm or last["status"] != "blocked":
            raise HTTPException(409, "Only the latest stopped run can be confirmed")
        confirmed = (last["id"], last["summary"] or {})

    def go():
        try:
            engine.run(body.kind, user, confirmed=confirmed)
        except engine.Busy:
            pass

    threading.Thread(target=go, daemon=True).start()
    if body.kind == "apply":
        db.audit(user, "run.apply", {"confirmed_run": body.confirm} if body.confirm else None)
    return {"ok": True}


@router.get("/preview")
def get_preview():
    return engine.preview()


@router.get("/runs")
def list_runs(limit: int = Query(30, ge=1, le=500)):
    return store.listing(min(limit, 100))


@router.get("/runs/{run_id}")
def get_run(run_id: int):
    r = store.get(run_id)
    if not r:
        raise HTTPException(404)
    return r
