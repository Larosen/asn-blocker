"""Soll-Zustand berechnen und mit CrowdSec abgleichen (Diff-Sync).

Ablauf: alle Quellen laden -> Soll-Ranges berechnen -> Plausibilitaet pruefen ->
neue/zu erneuernde Decisions anlegen -> erst danach entfallene loeschen.
Es gibt also keine Luecke ohne Schutz; jeder Fehler vor dem Schreiben laesst CrowdSec unveraendert.
"""
import ipaddress
import json
import logging
import threading
import time
from collections import defaultdict

from . import crowdsec, db, netset, notify, selfprotect, sources

REASONS = {"ban": "asn-blocker ban", "captcha": "asn-blocker captcha"}
_lock = threading.Lock()
log_ = logging.getLogger("asn_blocker.engine")


class Busy(RuntimeError):
    pass


class Blocked(RuntimeError):
    """Plausibilitaetspruefung schlaegt an - braucht Bestaetigung."""


# --- Soll-Zustand ---------------------------------------------------------------------------

def rules():
    asn_rules = {r["asn"]: r for r in db.q("SELECT * FROM asn_rules")}
    return asn_rules


def build(log, fresh=True):
    ipv6 = db.get("include_ipv6")
    modes = db.get("vpn_modes") or {}

    log("Ausnahmen sammeln")
    exempt = []  # (network, label)
    by_provider = defaultdict(list)
    for r in db.q("SELECT provider, country FROM vpn_rules ORDER BY provider, country"):
        by_provider[r["provider"]].append(r["country"])
    for pid, countries in by_provider.items():
        prov = sources.PROVIDERS.get(pid)
        if not prov:
            raise sources.SourceError(f"Unbekannter VPN-Anbieter {pid}")
        if fresh:
            db.cache_put(f"vpn:{pid}", [list(e) for e in prov.fetch() if e[0] and e[2]])
        widen = modes.get(pid) == "net"
        for cc in countries:
            ips = prov.ips(cc)
            if not ips:
                raise sources.SourceError(f"{prov.name} {cc}: keine Server-IPs ermittelt")
            for ip in ips:
                a = ipaddress.ip_address(ip)
                plen = (24 if a.version == 4 else 64) if widen else a.max_prefixlen
                exempt.append((ipaddress.ip_network(f"{ip}/{plen}", strict=False), f"VPN {prov.name} {cc}"))
            log(f"  {prov.name} {cc}: {len(ips)} Server-IPs" + (" (als Netz)" if widen else ""))

    ex_asns = [int(r["value"]) for r in db.q("SELECT value FROM exemptions WHERE kind='asn'")]
    for asn, p in sources.prefixes_many(ex_asns, use_cache=not fresh).items():
        if not p:
            raise sources.SourceError(f"Ausnahme-AS{asn}: keine Prefixe")
        exempt += [(n, f"Ausnahme-AS{asn}") for n in netset.parse(p)]
        log(f"  Ausnahme-AS{asn}: {len(p)} Prefixe")
    for r in db.q("SELECT value, note FROM exemptions WHERE kind='cidr'"):
        exempt += [(n, "Manuell" + (f": {r['note']}" if r["note"] else "")) for n in netset.parse([r["value"]])]

    guard = guard_ips()
    exempt += [(ipaddress.ip_network(ip), label) for ip, label in guard.items()]
    prot_asns = sorted(selfprotect.protected_asns())
    for asn, p in sources.prefixes_many(prot_asns, use_cache=not fresh).items():
        exempt += [(n, f"Selbstschutz AS{asn}") for n in netset.parse(p)]
    log(f"  Selbstschutz: {len(guard)} IPs, {len(prot_asns)} ASNs")

    log("ASN-Ranges sammeln")
    asn_rules = rules()
    if db.get("spamhaus_asndrop"):
        drop = sources.spamhaus_asndrop(use_cache=not fresh)
        added = 0
        for d in drop:
            if d["asn"] not in asn_rules:
                asn_rules[d["asn"]] = {"asn": d["asn"], "name": d["name"], "action": db.get("spamhaus_asndrop"), "spamhaus": True}
                added += 1
        log(f"  Spamhaus ASN-DROP: {len(drop)} ASNs, davon {added} zusätzlich")
    for asn in set(asn_rules) & set(prot_asns):
        log(f"  AS{asn} ist geschützt (Selbstschutz) – Regel wird ignoriert")
        del asn_rules[asn]
    raw = {"ban": [], "captcha": []}
    prefixes = sources.prefixes_many(asn_rules, use_cache=not fresh)
    spamhaus = [0, 0]  # ASNs, Prefixe – zusammengefasst statt hunderter Einzelzeilen
    for asn, r in sorted(asn_rules.items()):
        nets = [n for n in netset.parse(prefixes[asn]) if ipv6 or n.version == 4]
        raw[r["action"]] += nets
        if r.get("spamhaus"):
            spamhaus[0] += 1
            spamhaus[1] += len(nets)
        else:
            log(f"  AS{asn} {r.get('name') or sources.asn_name(asn)} -> {r['action']}: {len(nets)} Prefixe")
    if spamhaus[0]:
        log(f"  Spamhaus ASN-DROP -> {db.get('spamhaus_asndrop')}: {spamhaus[0]} ASNs, {spamhaus[1]} Prefixe")

    log("Ausnahmen heraustrennen")
    ex_nets = [n for n, _ in exempt]
    ban = netset.subtract(raw["ban"], ex_nets)
    captcha = netset.subtract(raw["captcha"], ex_nets + ban)  # Captcha nur, wo nicht ohnehin gebannt
    log(f"  ban: {len(ban)} Ranges, captcha: {len(captcha)} Ranges, {len(netset.collapse(ex_nets))} Ausnahme-Netze")
    # harte Endkontrolle: keine geschuetzte IP darf in einer Sperre landen
    for ip, label in guard.items():
        hit = status_of(str(ipaddress.ip_network(ip).network_address), {"ban": [str(n) for n in ban], "captcha": [str(n) for n in captcha]})
        if hit:
            raise sources.SourceError(f"Selbstschutz verletzt: {ip} ({label}) wäre von {hit} betroffen – Lauf abgebrochen")
    return {"ban": [str(n) for n in ban], "captcha": [str(n) for n in captcha]}, \
        [(str(n), label) for n, label in exempt]


def guard_ips():
    """Alle IPs, die nie gesperrt werden duerfen: geschuetzte IPs + aktive SSH-Sitzungen. {ip_cidr: label}"""
    out = {}
    for r in db.q("SELECT value, note FROM protected WHERE kind='ip'"):
        out[str(ipaddress.ip_network(r["value"]))] = "Selbstschutz" + (f": {r['note']}" if r["note"] else "")
    sessions, _ = selfprotect.ssh_sessions()
    for s in sessions:
        out.setdefault(str(ipaddress.ip_network(s["ip"])), f"SSH-Sitzung {s['user']}@{s['line']}")
    return out


# --- Abgleich ------------------------------------------------------------------------------------

def diff(desired, current, refresh_before):
    """current: Liste {id,value,until}. Gibt (add, delete_ids, refresh_count) zurueck."""
    by_value = defaultdict(list)
    for d in current:
        by_value[d["value"]].append(d)
    want = set(desired)
    add, delete, refresh = [], [], 0
    for v in desired:
        ds = sorted(by_value.get(v, []), key=lambda d: d["until"], reverse=True)
        if not ds:
            add.append(v)
        elif ds[0]["until"] < refresh_before:
            add.append(v)
            delete += [d["id"] for d in ds]
            refresh += 1
        else:
            delete += [d["id"] for d in ds[1:]]  # Duplikate
    for v, ds in by_value.items():
        if v not in want:
            delete += [d["id"] for d in ds]
    return add, delete, refresh


def _counts():
    return {t: db.q1("SELECT count(*) n FROM applied WHERE type=?", (t,))["n"] for t in REASONS}


def _sanity(desired, force):
    prev = sum(_counts().values())
    new = sum(len(v) for v in desired.values())
    if force or prev == 0:
        return
    if new == 0 and (db.q1("SELECT 1 x FROM asn_rules") or db.get("spamhaus_asndrop")):
        raise Blocked("Regeln vorhanden, aber 0 Ranges berechnet")
    pct = abs(new - prev) / prev * 100
    if pct > db.get("sanity_percent"):
        raise Blocked(f"Range-Anzahl ändert sich um {pct:.0f} % ({prev} -> {new}), Grenze {db.get('sanity_percent')} %")


def status_of(ip, ranges):
    """'ban' | 'captcha' | None fuer eine IP gegen {type: [cidr]}"""
    for t in ("ban", "captcha"):
        if netset.contains(ranges.get(t, []), ip):
            return t
    return None


def run(kind, user, force=False):
    """kind: 'plan' (nur berechnen) oder 'apply'. Gibt die Run-ID zurueck."""
    if not _lock.acquire(blocking=False):
        raise Busy("Es läuft bereits ein Lauf")
    try:
        with db.tx() as c:
            run_id = c.execute("INSERT INTO runs(kind,status,triggered_by,started_at) VALUES(?,?,?,?)",
                               (kind, "running", user, time.time())).lastrowid
        lines = []

        def log(msg):
            line = f"{time.strftime('%H:%M:%S')} {msg}"
            log_.info(msg, extra={"run_id": run_id})
            lines.append(line)
            with db.tx() as c:
                c.execute("UPDATE runs SET log=? WHERE id=?", ("\n".join(lines), run_id))

        status, summary = "failed", {}
        rev = db.get("config_rev")
        try:
            desired, exempt = build(log, fresh=(kind == "apply"))
            summary = {t: len(v) for t, v in desired.items()}
            try:
                backend = crowdsec.backend()
            except crowdsec.CrowdSecError:
                if kind == "apply":
                    raise
                backend = None
            refresh_before = time.time() + db.get("interval_hours") * 3600 * 2
            changes, plan = [], {}
            for t, reason in REASONS.items():
                if backend:
                    current = backend.list(reason)
                else:
                    current = [{"id": None, "value": r["value"], "until": float("inf")}
                               for r in db.q("SELECT value FROM applied WHERE type=?", (t,))]
                add, delete, refresh = diff(desired[t], current, refresh_before)
                removed = {d["value"] for d in current} - set(desired[t])
                new = set(add) - {d["value"] for d in current}
                plan[t] = (add, delete)
                summary[f"{t}_added"], summary[f"{t}_removed"], summary[f"{t}_refreshed"] = len(new), len(removed), refresh
                changes += [(run_id, "+", t, v) for v in sorted(new)] + [(run_id, "-", t, v) for v in sorted(removed)]
                log(f"Plan {t}: +{len(new)} neu, -{len(removed)} entfallen, {refresh} erneuert")
            with db.tx() as c:
                c.executemany("INSERT INTO run_changes VALUES(?,?,?,?)", changes)

            watch = {}
            for w in db.q("SELECT ip FROM watch_ips"):
                watch[w["ip"]] = status_of(w["ip"], desired)
                if watch[w["ip"]]:
                    log(f"WARNUNG Wächter-IP {w['ip']} wäre betroffen: {watch[w['ip']]}")
            summary["watch_hits"] = [ip for ip, s in watch.items() if s]

            if kind == "apply":
                _sanity(desired, force)
                log("Änderungen an CrowdSec übertragen")
                for t, reason in REASONS.items():
                    add, delete = plan[t]
                    if add:
                        backend.add(add, t, reason, db.get("decision_hours") * 3600)
                    if delete:
                        backend.delete_ids(delete)
                    active = {d["value"] for d in backend.list(reason)}
                    missing = set(desired[t]) - active
                    extra = active - set(desired[t])
                    summary[f"{t}_active"] = len(active)
                    log(f"  {t}: {len(active)} aktiv" + (f", FEHLEN {len(missing)}" if missing else "")
                        + (f", ÜBERZÄHLIG {len(extra)}" if extra else ""))
                    if missing:
                        raise crowdsec.CrowdSecError(f"{len(missing)} {t}-Ranges fehlen nach dem Import")
                with db.tx() as c:
                    c.execute("DELETE FROM applied")
                    c.executemany("INSERT INTO applied VALUES(?,?)", [(t, v) for t, vs in desired.items() for v in vs])
                    c.execute("DELETE FROM exempt_index")
                    c.executemany("INSERT INTO exempt_index VALUES(?,?)", exempt)
                    for ip, s in watch.items():
                        c.execute("UPDATE watch_ips SET last_status=? WHERE ip=?", (s or "frei", ip))
                    db.put("applied_rev", rev, c)
                if summary["watch_hits"]:
                    notify.send("asn-blocker: Wächter-IP betroffen", ", ".join(summary["watch_hits"]), "warning")
            status = "ok"
            log("Fertig")
        except Blocked as e:
            status = "blocked"
            log(f"ANGEHALTEN: {e}. CrowdSec unverändert – im UI bestätigen, um trotzdem anzuwenden.")
            notify.send("asn-blocker: Lauf angehalten", str(e), "warning")
        except (sources.SourceError, crowdsec.CrowdSecError) as e:
            log(f"FEHLER: {e}")
            if kind == "apply":
                notify.send("asn-blocker: Lauf fehlgeschlagen", str(e))
        except Exception as e:  # noqa: BLE001
            log(f"FEHLER (unerwartet): {e!r}")
            log_.exception("Unerwarteter Fehler im Lauf %s", run_id)
            if kind == "apply":
                notify.send("asn-blocker: Lauf fehlgeschlagen", repr(e))
        with db.tx() as c:
            c.execute("UPDATE runs SET status=?, finished_at=?, summary=? WHERE id=?",
                      (status, time.time(), json.dumps(summary), run_id))
            # Historie begrenzen
            c.execute("DELETE FROM run_changes WHERE run_id IN (SELECT id FROM runs ORDER BY id DESC LIMIT -1 OFFSET 100)")
            c.execute("DELETE FROM runs WHERE id IN (SELECT id FROM runs ORDER BY id DESC LIMIT -1 OFFSET 100)")
        return run_id
    finally:
        _lock.release()


_preview = {"rev": None, "result": None}
_preview_lock = threading.Lock()


def preview():
    """Schnelle Vorschau fuer die Apply-Leiste: Soll (aus Caches) gegen zuletzt angewendeten Stand."""
    rev = db.get("config_rev")
    if _preview["rev"] == rev:
        return _preview["result"]
    if not _preview_lock.acquire(blocking=False):
        return {"busy": True}
    try:
        try:
            desired, _ = build(lambda _msg: None, fresh=False)
        except sources.SourceError as e:
            return {"error": str(e)}
        result = {"rev": rev}
        for t in REASONS:
            applied = {r["value"] for r in db.q("SELECT value FROM applied WHERE type=?", (t,))}
            want = set(desired[t])
            result[t] = {"total": len(want), "add": len(want - applied), "remove": len(applied - want)}
        _preview.update(rev=rev, result=result)
        return result
    finally:
        _preview_lock.release()


def is_running():
    return _lock.locked()


# --- IP-Pruefung ------------------------------------------------------------------------------------

def check_ip(ip):
    ip = str(ipaddress.ip_address(ip))
    applied = defaultdict(list)
    for r in db.q("SELECT type, value FROM applied"):
        applied[r["type"]].append(r["value"])
    hits = {t: netset.contains(v, ip) for t, v in applied.items()}
    a = ipaddress.ip_address(ip)
    exempt = sorted({r["label"] for r in db.q("SELECT cidr, label FROM exempt_index")
                     if a in ipaddress.ip_network(r["cidr"])})
    manual = [r["value"] for r in db.q("SELECT value FROM exemptions WHERE kind='cidr'")
              if a in ipaddress.ip_network(r["value"], strict=False)]
    out = {"ip": ip, "status": status_of(ip, applied), "ranges": {t: [str(n) for n in v] for t, v in hits.items() if v},
           "exempt": exempt or (["Manuell"] if manual else []), "asns": [], "global": a.is_global}
    if a.is_global:
        try:
            info = sources.ip_info(ip)
            out["prefix"] = info["prefix"]
            for asn in info["asns"]:
                r = db.q1("SELECT action FROM asn_rules WHERE asn=?", (asn,))
                out["asns"].append({"asn": asn, "name": sources.asn_name(asn), "rule": r["action"] if r else None})
        except sources.SourceError as e:
            out["lookup_error"] = str(e)
    return out


# --- Scheduler -------------------------------------------------------------------------------------------

def _last_apply():
    return db.q1("SELECT status, started_at FROM runs WHERE kind='apply' AND status!='running' ORDER BY id DESC LIMIT 1")


def next_due():
    """Zeitpunkt des naechsten automatischen Laufs oder None (noch nie manuell angewendet)."""
    last = _last_apply()
    if not last or not db.get("crowdsec_mode"):
        return None
    wait = db.get("interval_hours") * 3600 if last["status"] in ("ok", "blocked") else 3600
    return last["started_at"] + wait


def scheduler():
    while True:
        try:
            due = next_due()
            if due and due <= time.time() and not is_running():
                run("apply", "scheduler")
            updated = db.get("asn_names_updated") or 0
            if time.time() - updated > 7 * 86400:
                try:
                    n = sources.refresh_asn_names()
                    log_.info("ASN-Namensliste aktualisiert: %d Einträge", n)
                except sources.SourceError as e:
                    log_.warning("ASN-Namensliste: %s", e)
                    db.put("asn_names_updated", time.time() - 6 * 86400)  # in 1 Tag erneut
        except Busy:
            pass
        except Exception:  # noqa: BLE001
            log_.exception("Scheduler-Fehler")
        time.sleep(30)
