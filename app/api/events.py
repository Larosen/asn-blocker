"""Live updates: a Server-Sent Events stream with the state the UI needs to know when to reload something."""
import asyncio
import json
import time

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from .. import db, engine, events
from .deps import require_user

router = APIRouter(prefix="/api", dependencies=[Depends(require_user)])
TICK = 0.5          # how often the stream looks for changes (no thread per client: a cheap version check)
KEEPALIVE = 15      # a comment line now and then keeps proxies from closing an idle stream
MAX_AGE = 3600      # the browser reconnects by itself; long-lived streams do not outlive a sign-out for long


def state():
    _, run = events.snapshot()
    return {"rev": db.get("config_rev"), "applied_rev": db.get("applied_rev"), "running": engine.is_running(),
            "run": run or None}


@router.get("/events")
async def stream(request: Request):
    async def gen():
        yield "retry: 3000\n\n"
        sent, last, started = None, time.monotonic(), time.monotonic()
        while time.monotonic() - started < MAX_AGE and not await request.is_disconnected():
            version, _ = events.snapshot()
            if version != sent:
                sent, last = version, time.monotonic()
                yield f"event: state\ndata: {json.dumps(await asyncio.to_thread(state))}\n\n"
            elif time.monotonic() - last > KEEPALIVE:
                last = time.monotonic()
                yield ": keep-alive\n\n"
            await asyncio.sleep(TICK)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})
