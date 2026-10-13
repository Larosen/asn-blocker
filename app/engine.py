"""Kernlogik: Ranges sammeln, Ausnahmen heraustrennen, Decisions in CrowdSec ersetzen.

Wie im urspruenglichen Bash-Skript gilt: Erst wenn ALLE Daten gueltig vorliegen,
werden bestehende Decisions geloescht. Jeder Quellfehler bricht vorher ab.
"""
import bisect
import io
import ipaddress
import json
import tarfile
import threading
import time
from datetime import datetime, timedelta, timezone

from . import config
from .sources import PROVIDERS, asn_prefixes

_run_lock = threading.Lock()


class Abort(RuntimeError):
    pass


def _parse(values, ipv6):
    out = []
    for v in values:
        try:
            n = ipaddress.ip_network(str(v).strip(), strict=False)
        except ValueError:
            continue
        if n.version == 4 or ipv6:
            out.append(n)
    return out


def _collapse(nets):
    v4 = [n for n in nets if n.version == 4]
    v6 = [n for n in nets if n.version == 6]
    return sorted(ipaddress.collapse_addresses(v4)) + sorted(ipaddress.collapse_addresses(v6))


def subtract(source, exempt):
    """source minus exempt (beides Netzlisten), Ergebnis zusammengefasst."""
    exempt = _collapse(exempt)
    result = []
    for ver in (4, 6):
        ex = [n for n in exempt if n.version == ver]
        starts = [int(n.network_address) for n in ex]
        ends = [int(n.broadcast_address) for n in ex]
        for src in (n for n in source if n.version == ver):
            s, e = int(src.network_address), int(src.broadcast_address)
            i = max(bisect.bisect_right(starts, s) - 1, 0)
            rem = [src]
            while i < len(ex) and starts[i] <= e:
                if ends[i] >= s:
                    nxt = []
                    for r in rem:
                        if not r.overlaps(ex[i]):
                            nxt.append(r)
                        elif not ex[i].supernet_of(r):
                            nxt.extend(r.address_exclude(ex[i]))
                    rem = nxt
                i += 1
            result.extend(rem)
    return _collapse(result)


def build(cfg, log):
    ipv6 = cfg.get("include_ipv6", False)

    log("Schritt 1: Ausnahmen sammeln")
    exempt = []
    for entry in cfg["vpn_whitelist"]:
        prov = PROVIDERS.get(entry["provider"])
        if not prov:
            raise Abort(f"Unbekannter VPN-Anbieter {entry['provider']}")
        ips = prov.ips(entry["country"])
        if not ips:
            raise Abort(f"{prov.name} {entry['country']}: keine IPs ermittelt")
        for ip in ips:
            a = ipaddress.ip_address(ip)
            plen = (24 if a.version == 4 else 64) if cfg.get("widen_vpn_ips", True) else a.max_prefixlen
            exempt.append(ipaddress.ip_network(f"{ip}/{plen}", strict=False))
        log(f"  {prov.name} {entry['country']}: {len(ips)} Server-IPs")
    for asn in cfg["exempt_asns"]:
        p = asn_prefixes(int(asn), ipv6=True)
        if not p:
            raise Abort(f"Ausnahme-AS{asn}: keine Prefixe")
        exempt += _parse(p, True)
        log(f"  Ausnahme-AS{asn}: {len(p)} Prefixe")
    manual = _parse(cfg["manual_exempt"], True)
    exempt += manual
    log(f"  {len(manual)} manuelle Ausnahmen, {len(_collapse(exempt))} Ausnahme-Ranges gesamt")

    log("Schritt 2: ASN-Ranges sammeln")
    raw = {"ban": [], "captcha": []}
    for e in cfg["asns"]:
        p = asn_prefixes(int(e["asn"]), ipv6=ipv6)
        log(f"  AS{e['asn']} ({e.get('name', '')}) -> {e['action']}: {len(p)} Prefixe")
        raw[e["action"]] += _parse(p, ipv6)

    log("Schritt 3: Ausnahmen heraustrennen")
    ban = subtract(raw["ban"], exempt)
    # Captcha nur dort, wo nicht ohnehin gebannt wird
    captcha = subtract(raw["captcha"], exempt + ban)
    log(f"  ban: {len(raw['ban'])} Roh -> {len(ban)} final | captcha: {len(raw['captcha'])} Roh -> {len(captcha)} final")
    return {"ban": [str(n) for n in ban], "captcha": [str(n) for n in captcha]}


# --- CrowdSec ---------------------------------------------------------------------

def _container():
    import docker
    return docker.from_env().containers.get(config.CROWDSEC_CONTAINER)


def _exec(c, cmd):
    res = c.exec_run(cmd)
    out = res.output.decode(errors="replace")
    if res.exit_code != 0:
        raise Abort(f"{' '.join(cmd)} -> exit {res.exit_code}: {out[-500:]}")
    return out


def _put_file(c, path, content: str):
    buf = io.BytesIO()
    data = content.encode()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(path.rsplit("/", 1)[1])
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    if not c.put_archive(path.rsplit("/", 1)[0], buf.getvalue()):
        raise Abort("Kopieren in den CrowdSec-Container fehlgeschlagen")


def _count(c, reason):
    out = _exec(c, ["cscli", "decisions", "list", "--scenario", reason, "-l", "0", "-o", "json"])
    data = json.loads(out or "null") or []
    return sum(len(a.get("decisions") or []) for a in data)


def apply(ranges, log):
    c = _container()
    log("Schritt 4: Decisions in CrowdSec ersetzen")
    result = {}
    for typ, values in ranges.items():
        reason = config.REASONS[typ]
        _exec(c, ["cscli", "decisions", "delete", "--scenario", reason])
        if not values:
            log(f"  {typ}: keine Ranges, nur alte entfernt")
            result[typ] = {"expected": 0, "active": 0}
            continue
        path = f"/tmp/asn-blocker-{typ}.txt"
        _put_file(c, path, "\n".join(values) + "\n")
        _exec(c, ["cscli", "decisions", "import", "-i", path, "--format", "values", "--scope", "range",
                  "--type", typ, "--duration", config.DECISION_DURATION, "-R", reason, "--batch", "200"])
        active = _count(c, reason)
        result[typ] = {"expected": len(values), "active": active}
        log(f"  {typ}: erwartet {len(values)}, aktiv {active}" + ("" if active == len(values) else "  WARNUNG: Abweichung!"))
    return result


# --- Ausfuehrung / Scheduler ----------------------------------------------------------

def run(dry_run=False):
    if not _run_lock.acquire(blocking=False):
        raise Abort("Es laeuft bereits ein Update")
    state = config.load_state()
    lines = []

    def log(msg):
        line = f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S} {msg}"
        print(line, flush=True)
        lines.append(line)
        state["log"] = lines
        config.save_state(state)

    state.update(running=True, log=[])
    config.save_state(state)
    ok = False
    try:
        ranges = build(config.load_config(), log)
        if dry_run:
            log("Testlauf - CrowdSec wurde nicht veraendert")
            state["preview"] = {k: len(v) for k, v in ranges.items()}
        else:
            state["stats"] = apply(ranges, log)
            state["ranges"] = ranges
        ok = True
    except Exception as e:  # noqa: BLE001 - alles loggen, nichts loeschen
        log(f"ABBRUCH: {e}  (bestehende Decisions blieben unveraendert, falls vor Schritt 4)")
    finally:
        now = datetime.now(timezone.utc)
        state["running"] = False
        if not dry_run:
            state["last_run"] = now.isoformat()
            state["last_ok"] = ok
        config.save_state(state)
        _run_lock.release()
    return ok


def scheduler():
    """Laeuft im Hintergrund; startet alle UPDATE_INTERVAL_HOURS ein Update.
    Nach einem Fehler wird nach 1 h erneut versucht."""
    while True:
        state = config.load_state()
        now = datetime.now(timezone.utc)
        last = state.get("last_run")
        interval = timedelta(hours=config.UPDATE_INTERVAL_HOURS if state.get("last_ok", True) else 1)
        due = datetime.fromisoformat(last) + interval if last else now
        state["next_run"] = due.isoformat()
        config.save_state(state)
        if due <= now and config.load_config()["asns"]:
            try:
                run()
            except Abort:
                pass
        time.sleep(60)
