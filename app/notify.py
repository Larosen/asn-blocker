import logging

import httpx

from . import db
from .sources import USER_AGENT


def send(title, message, level="error"):
    url, fmt = db.get("notify_url"), db.get("notify_format")
    if not url:
        return
    try:
        if fmt == "ntfy":
            httpx.post(url, content=message.encode(), timeout=15,
                       headers={"Title": title, "Priority": "high" if level == "error" else "default",
                                "Tags": "shield", "User-Agent": USER_AGENT})
        elif fmt == "gotify":
            httpx.post(url, json={"title": title, "message": message, "priority": 8 if level == "error" else 4}, timeout=15)
        else:
            httpx.post(url, json={"title": title, "message": message, "level": level, "source": "asn-blocker"}, timeout=15)
    except httpx.HTTPError as e:
        logging.getLogger("asn_blocker.notify").warning("Notification failed: %s", e)
