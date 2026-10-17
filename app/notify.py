"""Notifications via ntfy, Gotify or a JSON webhook.

An optional access token is stored separately from the URL and sent as a header (ntfy and webhook:
`Authorization: Bearer …`, Gotify: `X-Gotify-Key`). If the address of the web UI is known, notifications
link to the run they are about.
"""
import hashlib
import ipaddress
import logging
import socket
import threading
import time

import httpx

from . import db
from .sources import USER_AGENT

log = logging.getLogger("asn_blocker.notify")

# level -> (ntfy priority, ntfy tags, Gotify priority)
LEVELS = {"error": ("high", "rotating_light", 8), "warning": ("high", "warning", 6), "info": ("default", "white_check_mark", 4)}


class NotifyError(RuntimeError):
    pass


# Settings can only be saved after a successful test with exactly these values (fingerprint -> time of the test)
_tested: dict[str, float] = {}
_tested_lock = threading.Lock()
TEST_VALID = 1800


def _fingerprint(*values):
    return hashlib.sha256("\n".join(str(v) for v in values).encode()).hexdigest()


def mark_tested(*values):
    now = time.time()
    with _tested_lock:
        for k in [k for k, t in _tested.items() if now - t > TEST_VALID]:
            del _tested[k]
        _tested[_fingerprint(*values)] = now


def was_tested(*values):
    with _tested_lock:
        t = _tested.get(_fingerprint(*values))
    return t is not None and time.time() - t <= TEST_VALID


def _origin(url):
    u = httpx.URL(url)
    return u.scheme, (u.host or "").lower().rstrip("."), u.port or {"http": 80, "https": 443}.get(u.scheme)


def check_target(url):
    """Notifications may go to internal services (e.g. http://ntfy:80), but never to link-local addresses such as
    cloud metadata endpoints."""
    try:
        host = httpx.URL(url).host
        addrs = {i[4][0] for i in socket.getaddrinfo(host, None)}
    except (OSError, UnicodeError, httpx.InvalidURL):
        return  # unresolvable: the request itself will fail with a clear error
    for a in addrs:
        ip = ipaddress.ip_address(a.split("%")[0])
        if ip.is_link_local or (ip.version == 6 and ip.ipv4_mapped and ip.ipv4_mapped.is_link_local) \
                or ip.is_multicast or ip.is_unspecified:
            raise NotifyError(f"{host} resolves to {ip}, which is not allowed as a notification target")


def mask(url):
    """Notification URLs carry their secret in path, query or userinfo (ntfy topic, Gotify token, webhook path):
    only scheme and host are shown again."""
    if not url:
        return url or ""
    u = httpx.URL(url)
    port = f":{u.port}" if u.port else ""
    return f"{u.scheme}://{u.host}{port}/***"


def same_host(a, b):
    """Same scheme, host and port – a stored token never follows the URL to another server or to plain http."""
    try:
        return bool(a and b) and _origin(a) == _origin(b)
    except (httpx.InvalidURL, TypeError):
        return False


def link(run_id=None, base=None):
    if not base:
        return None
    return f"{base}/#/runs/{run_id}" if run_id else f"{base}/#/overview"


def send(title, message, level="error", run_id=None, raise_errors=False, cfg=None):
    """cfg: (url, format, token, public_url) to use instead of the saved settings – for testing unsaved values."""
    if cfg:
        url, fmt, token, base = cfg
    else:
        url, fmt, token, base = db.get("notify_url"), db.get("notify_format"), db.get("notify_token"), db.get("public_url")
    if not url:
        return
    prio, tags, gotify_prio = LEVELS.get(level, LEVELS["error"])
    click = link(run_id, base)
    headers = {"User-Agent": USER_AGENT}
    try:
        check_target(url)
        if fmt == "ntfy":
            headers |= {"Title": title, "Priority": prio, "Tags": f"{tags},shield"}
            if click:
                headers["Click"] = click
            if token:
                headers["Authorization"] = f"Bearer {token}"
            r = httpx.post(url, content=message.encode(), headers=headers, timeout=15)
        elif fmt == "gotify":
            if token:
                headers["X-Gotify-Key"] = token
            body = {"title": title, "message": message, "priority": gotify_prio}
            if click:
                body["extras"] = {"client::notification": {"click": {"url": click}}}
            r = httpx.post(url, json=body, headers=headers, timeout=15)
        else:
            if token:
                headers["Authorization"] = f"Bearer {token}"
            r = httpx.post(url, json={"title": title, "message": message, "level": level, "source": "asn-blocker",
                                      "url": click}, headers=headers, timeout=15)
        if r.status_code >= 300:
            hint = " – check the access token and the topic's permissions" if r.status_code in (401, 403) else ""
            raise NotifyError(f"{fmt} server answered HTTP {r.status_code}{hint}")
    except httpx.HTTPError as e:
        err = NotifyError(f"{fmt} server not reachable: {type(e).__name__}")
        log.warning("Notification failed: %s", err)
        if raise_errors:
            raise err from e
    except NotifyError as e:
        log.warning("Notification failed: %s", e)
        if raise_errors:
            raise
    except Exception as e:  # noqa: BLE001 - a notification must never break a run
        log.warning("Notification failed: %s", type(e).__name__)
        if raise_errors:
            raise NotifyError(f"notification failed: {type(e).__name__}") from e
