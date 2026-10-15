"""Logging nach stdout: lesbarer Text (Standard) oder JSON (LOG_FORMAT=json)."""
import json
import logging
import os
import sys
from datetime import UTC, datetime


class JsonFormatter(logging.Formatter):
    def format(self, record):
        data = {"ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
                "level": record.levelname.lower(), "logger": record.name, "msg": record.getMessage()}
        for key in ("run_id",):
            if hasattr(record, key):
                data[key] = getattr(record, key)
        if record.exc_info:
            data["exc"] = self.formatException(record.exc_info)
        return json.dumps(data, ensure_ascii=False)


def setup():
    handler = logging.StreamHandler(sys.stdout)
    if os.environ.get("LOG_FORMAT", "text").lower() == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S"))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())
    # uvicorn-Logger ueber denselben Handler ausgeben
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers = []
        lg.propagate = True
