"""CrowdSec integration. Default: Local API (LAPI) as a machine. Legacy: cscli via the Docker socket."""
import io
import json
import re
import secrets
import tarfile
import time
from datetime import datetime, timezone

import httpx

from . import db

BATCH = 500
MANUAL_ORIGINS = ("cscli", "cscli-import")  # decisions added by hand or by scripts via cscli
_DUR = re.compile(r"(-?[\d.]{1,20})(h|ms|m|s|us|µs|ns)")
_UNIT = {"h": 3600, "m": 60, "s": 1, "ms": 1e-3, "us": 1e-6, "µs": 1e-6, "ns": 1e-9}


class CrowdSecError(RuntimeError):
    pass


def go_duration(s: str) -> float:
    """'167h59m58.5s' -> seconds (negative = expired)."""
    return sum(float(n) * _UNIT[u] for n, u in _DUR.findall((s or "")[:64]))


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _alert(reason, typ, values, duration_s):
    now = _now_iso()
    return {
        "scenario": reason, "scenario_hash": "", "scenario_version": "", "message": f"{reason}: {len(values)} ranges",
        "events": [], "events_count": len(values), "capacity": 0, "leakspeed": "0", "simulated": False,
        "start_at": now, "stop_at": now, "created_at": now,
        "source": {"scope": "asn-blocker", "value": reason},
        "decisions": [{"duration": f"{int(duration_s)}s", "origin": "cscli-import", "scenario": reason,
                       "scope": "Range", "type": typ, "value": v} for v in values],
    }


def _decisions_from_alerts(alerts, reason):
    out, now = [], time.time()
    for a in alerts or []:
        for d in a.get("decisions") or []:
            if d.get("scenario") != reason:
                continue
            remaining = go_duration(d.get("duration", ""))
            if remaining > 0:
                out.append({"id": d["id"], "value": d["value"], "type": d["type"], "until": now + remaining})
    return out


class Lapi:
    def __init__(self, url, machine_id, password):
        self.base = url.rstrip("/") + "/v1"
        self.machine_id, self.password = machine_id, password
        self._token, self._exp = None, 0
        self.http = httpx.Client(timeout=120, follow_redirects=False)

    def __del__(self):
        try:
            self.http.close()
        except Exception:  # noqa: BLE001 - interpreter shutdown
            pass

    def _auth(self):
        if self._token and time.time() < self._exp - 60:
            return
        try:
            r = self.http.post(f"{self.base}/watchers/login",
                               json={"machine_id": self.machine_id, "password": self.password, "scenarios": []})
        except httpx.HTTPError as e:
            raise CrowdSecError(f"LAPI not reachable ({self.base}): {type(e).__name__}") from e
        if r.status_code != 200:  # no response body: the URL is user-configurable, don't reflect what it returns
            raise CrowdSecError(f"LAPI login failed (HTTP {r.status_code}) – check machine ID and password")
        self._token, self._exp = r.json()["token"], time.time() + 3000

    def _req(self, method, path, **kw):
        self._auth()
        try:
            r = self.http.request(method, self.base + path, headers={"Authorization": f"Bearer {self._token}"}, **kw)
        except httpx.HTTPError as e:
            raise CrowdSecError(f"LAPI not reachable: {type(e).__name__}") from e
        if r.status_code >= 300:
            try:
                detail = str(r.json().get("message", ""))[:200]
            except (ValueError, AttributeError):
                detail = ""
            raise CrowdSecError(f"LAPI {method} {path} -> HTTP {r.status_code}" + (f": {detail}" if detail else ""))
        return r.json() if r.content else None

    def test(self):
        self._token = None
        self._auth()
        self._req("GET", "/alerts", params={"limit": 1})
        return "Connected"

    def list(self, reason):
        alerts = self._req("GET", "/alerts", params={"scenario": reason, "has_active_decision": "true", "limit": 0})
        return _decisions_from_alerts(alerts, reason)

    def add(self, values, typ, reason, duration_s):
        for i in range(0, len(values), BATCH):
            self._req("POST", "/alerts", json=[_alert(reason, typ, values[i:i + BATCH], duration_s)])

    def delete_ids(self, ids):
        for i in ids:
            self._req("DELETE", f"/decisions/{i}")

    def delete_scenario(self, reason):
        """Only decisions created via cscli (add/import) – never CrowdSec's own detections or blocklists."""
        return sum(int((self._req("DELETE", "/decisions", params={"scenario": reason, "origin": o}) or {})
                       .get("nbDeleted", 0)) for o in MANUAL_ORIGINS)


class DockerCli:
    """Legacy mode: needs /var/run/docker.sock (equivalent to root on the host)."""

    def __init__(self, container):
        import docker
        try:
            self.c = docker.from_env().containers.get(container)
        except Exception as e:  # noqa: BLE001
            raise CrowdSecError(f"Container {container}: {e}") from e

    def _exec(self, *cmd):
        import docker
        try:
            res = self.c.exec_run(list(cmd))
        except docker.errors.DockerException as e:
            raise CrowdSecError(f"docker exec failed: {e}") from e
        out = res.output.decode(errors="replace")
        if res.exit_code != 0:
            raise CrowdSecError(f"{' '.join(cmd[:4])} -> exit {res.exit_code}: {out[-300:]}")
        return out

    def test(self):
        return self._exec("cscli", "version").splitlines()[0]

    def list(self, reason):
        out = self._exec("cscli", "decisions", "list", "--scenario", reason, "-l", "0", "-o", "json")
        return _decisions_from_alerts(json.loads(out or "null"), reason)

    def add(self, values, typ, reason, duration_s):
        name = f"asn-blocker-{secrets.token_hex(8)}.txt"
        data = ("\n".join(values) + "\n").encode()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        if not self.c.put_archive("/tmp", buf.getvalue()):
            raise CrowdSecError("Copying into the CrowdSec container failed")
        try:
            self._exec("cscli", "decisions", "import", "-i", f"/tmp/{name}", "--format", "values",
                       "--scope", "range", "--type", typ, "--duration", f"{int(duration_s)}s", "-R", reason,
                       "--batch", str(BATCH))
        finally:
            self.c.exec_run(["rm", "-f", f"/tmp/{name}"])

    def delete_ids(self, ids):
        for i in ids:
            self._exec("cscli", "decisions", "delete", "--id", str(i))

    def delete_scenario(self, reason):
        n = 0
        for o in MANUAL_ORIGINS:
            m = re.search(r"(\d+) decision", self._exec("cscli", "decisions", "delete", "--scenario", reason, "--origin", o))
            n += int(m.group(1)) if m else 0
        return n


def backend():
    mode = db.get("crowdsec_mode")
    if mode == "lapi":
        return Lapi(db.get("lapi_url"), db.get("lapi_machine_id"), db.get("lapi_password"))
    if mode == "docker":
        return DockerCli(db.get("docker_container"))
    raise CrowdSecError("CrowdSec connection is not set up yet")
