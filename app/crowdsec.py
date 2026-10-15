"""Anbindung an CrowdSec. Standard: Local API (LAPI) als Machine. Legacy: cscli per Docker-Socket."""
import io
import json
import re
import tarfile
import time
from datetime import datetime, timezone

import httpx

from . import db

BATCH = 500
_DUR = re.compile(r"(-?[\d.]+)(h|ms|m|s|us|µs|ns)")
_UNIT = {"h": 3600, "m": 60, "s": 1, "ms": 1e-3, "us": 1e-6, "µs": 1e-6, "ns": 1e-9}


class CrowdSecError(RuntimeError):
    pass


def go_duration(s: str) -> float:
    """'167h59m58.5s' -> Sekunden (negativ = abgelaufen)."""
    return sum(float(n) * _UNIT[u] for n, u in _DUR.findall(s or ""))


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
        self.http = httpx.Client(timeout=120)

    def _auth(self):
        if self._token and time.time() < self._exp - 60:
            return
        r = self.http.post(f"{self.base}/watchers/login",
                           json={"machine_id": self.machine_id, "password": self.password, "scenarios": []})
        if r.status_code != 200:
            raise CrowdSecError(f"LAPI-Login fehlgeschlagen ({r.status_code}): {r.text[:200]}")
        self._token, self._exp = r.json()["token"], time.time() + 3000

    def _req(self, method, path, **kw):
        self._auth()
        try:
            r = self.http.request(method, self.base + path, headers={"Authorization": f"Bearer {self._token}"}, **kw)
        except httpx.HTTPError as e:
            raise CrowdSecError(f"LAPI nicht erreichbar: {e}") from e
        if r.status_code >= 300:
            raise CrowdSecError(f"LAPI {method} {path} -> {r.status_code}: {r.text[:300]}")
        return r.json() if r.content else None

    def test(self):
        self._token = None
        self._auth()
        self._req("GET", "/alerts", params={"limit": 1})
        return "Verbunden"

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
        return int((self._req("DELETE", "/decisions", params={"scenario": reason}) or {}).get("nbDeleted", 0))


class DockerCli:
    """Legacy-Modus: braucht /var/run/docker.sock (entspricht Root-Rechten auf dem Host)."""

    def __init__(self, container):
        import docker
        try:
            self.c = docker.from_env().containers.get(container)
        except Exception as e:  # noqa: BLE001
            raise CrowdSecError(f"Container {container}: {e}") from e

    def _exec(self, *cmd):
        res = self.c.exec_run(list(cmd))
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
        data = ("\n".join(values) + "\n").encode()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo("asn-blocker-import.txt")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        if not self.c.put_archive("/tmp", buf.getvalue()):
            raise CrowdSecError("Kopieren in den CrowdSec-Container fehlgeschlagen")
        self._exec("cscli", "decisions", "import", "-i", "/tmp/asn-blocker-import.txt", "--format", "values",
                   "--scope", "range", "--type", typ, "--duration", f"{int(duration_s)}s", "-R", reason,
                   "--batch", str(BATCH))
        self.c.exec_run(["rm", "-f", "/tmp/asn-blocker-import.txt"])

    def delete_ids(self, ids):
        for i in ids:
            self._exec("cscli", "decisions", "delete", "--id", str(i))

    def delete_scenario(self, reason):
        out = self._exec("cscli", "decisions", "delete", "--scenario", reason)
        m = re.search(r"(\d+) decision", out)
        return int(m.group(1)) if m else 0


def backend():
    mode = db.get("crowdsec_mode")
    if mode == "lapi":
        return Lapi(db.get("lapi_url"), db.get("lapi_machine_id"), db.get("lapi_password"))
    if mode == "docker":
        return DockerCli(db.get("docker_container"))
    raise CrowdSecError("CrowdSec-Verbindung ist noch nicht eingerichtet")
