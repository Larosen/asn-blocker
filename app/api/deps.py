"""Shared dependencies of the API routers."""
from fastapi import HTTPException, Request

from .. import auth, db, sources


def require_user(request: Request) -> str:
    if not db.get("auth_mode"):
        raise HTTPException(409, "Initial setup not completed")
    user = auth.current_user(request)
    if not user:
        raise HTTPException(401, "Not signed in")
    return user



def src_call(fn, *a, **kw):
    """Calls a data source; its errors become 502 responses."""
    try:
        return fn(*a, **kw)
    except sources.SourceError as e:
        raise HTTPException(502, str(e))
