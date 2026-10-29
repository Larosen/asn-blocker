"""Attackers: which networks CrowdSec's own detections keep catching, and which of them to block as a whole.

CrowdSec keeps alerts for about a week, so every collection adds the new alerts to a compact history (one row per
attacking IP and day). Only real local detections count: community blocklists, manual decisions and this app's own
alerts are left out. Collections are incremental (alert IDs), so a busy host never loads weeks of alerts at once.
"""
import ipaddress
import json
import logging
import re
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

from . import crowdsec, db, notify, sources
from .store import exemptions, protection
from .store import rules as rule_store

log = logging.getLogger("asn_blocker.attackers")

SCENARIO = re.compile(r"[A-Za-z0-9_.-]{1,64}/[A-Za-z0-9_.-]{1,128}")  # author/name – real detection scenarios
MAX_LOOKUPS = 200          # RIPE lookups per collection for alerts without ASN enrichment …
LOOKUP_BUDGET = 20         # … and at most this many seconds for them (the rest follows next time)
MIN_IPS = 5                # attacking IPs before a whole network is recommended
LARGE = 2 ** 22            # IPv4 addresses (~4 M) from which a network is "large": captcha, not block
WINDOWS = (7, 30, 90)
NOTIFY_AGAIN = 30 * 86400  # a network that keeps being recommended is reported again after this long
_lock = threading.Lock()


def _day(ts: str) -> tuple[str, float]:
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%d"), dt.timestamp()


def _ip(v):
    try:
        a = ipaddress.ip_address(str(v).strip())
    except ValueError:
        return None
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return str(a) if a.is_global else None


def collect(backend=None) -> int:
    """Adds alerts newer than the last collection. Returns the number of counted alerts."""
    if not _lock.acquire(blocking=False):
        return 0
    try:
        backend = backend or crowdsec.backend()
        last_id, last_run = db.get("attackers_last_id") or 0, db.get("attackers_updated")
        hours = 168 if not last_run else max(2, min(168, int((time.time() - last_run) / 3600) + 2))
        try:
            alerts = backend.alerts(hours)
        except crowdsec.CrowdSecError as e:
            db.put("attackers_error", str(e))
            raise
        rows, lookups, newest, counted = {}, {}, last_id, 0
        deadline = time.monotonic() + LOOKUP_BUDGET
        for a in alerts if isinstance(alerts, list) else []:
            try:
                aid = int(a.get("id") or 0)
            except (TypeError, ValueError):
                continue
            newest = max(newest, aid)
            src = a.get("source") or {}
            scenario = str(a.get("scenario") or "")
            if aid <= last_id or a.get("simulated") or str(src.get("scope", "")).lower() != "ip" \
                    or not SCENARIO.fullmatch(scenario):
                continue
            ip = _ip(src.get("value") or src.get("ip"))
            if not ip:
                continue
            asn, name = str(src.get("as_number") or ""), sources.clean(src.get("as_name") or "", 120)
            asn = int(asn) if re.fullmatch(r"[0-9]{1,10}", asn) and 0 < int(asn) < 2**32 else None
            if asn is None:  # CrowdSec without ASN enrichment: look it up (cached by RIPE lookups)
                if ip not in lookups and len(lookups) < MAX_LOOKUPS and time.monotonic() < deadline:
                    try:
                        lookups[ip] = (sources.ip_info(ip).get("asns") or [None])[0]
                    except sources.SourceError:
                        lookups[ip] = None
                asn = lookups.get(ip)
            day, ts = _day(a.get("start_at") or a.get("created_at") or "")
            r = rows.setdefault((day, ip), {"asn": asn, "name": name, "alerts": 0, "scenarios": set(), "last": 0.0})
            r["alerts"] += 1
            r["scenarios"].add(scenario)
            r["last"] = max(r["last"], ts)
            counted += 1
        with db.tx() as c:
            for (day, ip), r in rows.items():
                old = c.execute("SELECT alerts, scenarios, last_seen FROM attack_ips WHERE day=? AND ip=?", (day, ip)).fetchone()
                scen = set(json.loads(old["scenarios"])) | r["scenarios"] if old else r["scenarios"]
                c.execute("INSERT INTO attack_ips(day, ip, asn, as_name, alerts, scenarios, last_seen) VALUES(?,?,?,?,?,?,?) "
                          "ON CONFLICT(day, ip) DO UPDATE SET alerts=alerts+excluded.alerts, scenarios=excluded.scenarios, "
                          "last_seen=max(last_seen, excluded.last_seen), asn=coalesce(excluded.asn, asn), "
                          "as_name=CASE WHEN excluded.as_name<>'' THEN excluded.as_name ELSE as_name END",
                          (day, ip, r["asn"], r["name"], r["alerts"], json.dumps(sorted(scen)[:20]), r["last"]))
            db.put("attackers_last_id", newest, c)
            db.put("attackers_updated", time.time(), c)
            db.put("attackers_error", None, c)
        _backfill(deadline)
        _fetch_sizes()
        _notify_new()
        if counted:
            log.info("Attackers: %d new alerts from %d IPs", counted, len({ip for _, ip in rows}))
        return counted
    finally:
        _lock.release()


def _backfill(deadline):
    """IPs whose ASN could not be looked up in time get it in a later collection."""
    for r in db.q("SELECT DISTINCT ip FROM attack_ips WHERE asn IS NULL LIMIT ?", (MAX_LOOKUPS,)):
        if time.monotonic() >= deadline:
            return
        try:
            asn = (sources.ip_info(r["ip"]).get("asns") or [None])[0]
        except sources.SourceError:
            continue
        if asn:
            with db.tx() as c:
                c.execute("UPDATE attack_ips SET asn=? WHERE ip=? AND asn IS NULL", (asn, r["ip"]))


def _size(asn):
    """IPv4 addresses announced by an ASN, from the prefix cache only (None if unknown)."""
    hit = db.cache_get(f"asnsize:{asn}", 7 * 86400)
    return hit if hit is not None else None


def _fetch_sizes(limit=30):
    """Network sizes for the most active ASNs, so recommendations can tell a small hoster from a giant cloud."""
    top = db.q("SELECT asn, count(DISTINCT ip) n FROM attack_ips WHERE asn IS NOT NULL AND day >= date('now', '-30 days') "
               "GROUP BY asn HAVING n >= 2 ORDER BY n DESC LIMIT ?", (limit,))
    for r in top:
        if _size(r["asn"]) is not None:
            continue
        try:
            nets = [ipaddress.ip_network(p) for p in sources.asn_prefixes(r["asn"])]
        except (sources.SourceError, ValueError):
            continue
        v4 = sum(n.num_addresses for n in ipaddress.collapse_addresses(n for n in nets if n.version == 4))
        db.cache_put(f"asnsize:{r['asn']}", v4)


def _notify_new():
    """One notification when networks newly qualify for a recommendation (each again after 30 days at the earliest)."""
    if not db.get("notify_url"):
        return
    now = time.time()
    seen = {k: v for k, v in (db.get("attackers_notified") or {}).items() if now - v < NOTIFY_AGAIN}
    new = [r for r in report(7)["rows"] if r["recommendation"]["kind"] == "recommend" and str(r["asn"]) not in seen]
    if new:
        act = {"ban": "block", "captcha": "captcha"}
        lines = [f"AS{r['asn']} {r['name'] or '?'}: {r['ips']} attacking IPs – {act[r['recommendation']['action']]}"
                 for r in new[:10]]
        more = f"\n… and {len(new) - 10} more" if len(new) > 10 else ""
        notify.send(f"asn-blocker: {len(new)} network{'s' if len(new) > 1 else ''} keep attacking",
                    "\n".join(lines) + more + "\nReview them under Attackers.", "warning", page="attackers")
        seen |= {str(r["asn"]): now for r in new}
    db.put("attackers_notified", seen)


def _recommend(row, days):
    ips, cls, size = row["ips"], (row["class"] or "").lower(), row["size"]
    top = row["scenarios"][0]["name"].split("/")[-1] if row["scenarios"] else ""
    why = f"{ips} attacking IPs in {days} days" + (f", mostly {top}" if top else "")
    if row["rule"]:
        return {"kind": "active", "action": row["rule"], "reason": "Already a rule"}
    if row["protected"]:
        return {"kind": "protected", "reason": "Protected or exempted – never blocked"}
    if "eyeball" in cls:
        return {"kind": "watch", "reason": "Consumer network – blocking it would hit real visitors; " + why}
    if ips < MIN_IPS:
        return {"kind": "watch", "reason": why}
    if row.get("capped"):
        return {"kind": "recommend", "action": "captcha", "reason": why + "; protected against bans – at most captcha"}
    if size and size >= LARGE:
        return {"kind": "recommend", "action": "captcha", "reason": why + "; large network with legitimate services"}
    if "carrier" in cls or "transit" in cls:
        return {"kind": "recommend", "action": "captcha", "reason": why + "; transit network"}
    return {"kind": "recommend", "action": "ban", "reason": why}


def report(days=7, limit=100):
    days = days if days in WINDOWS else 7
    since = f"-{days - 1} days"
    rows = db.q("SELECT asn, max(as_name) as_name, count(DISTINCT ip) ips, sum(alerts) alerts, max(last_seen) last_seen, "
                "min(day) first_day FROM attack_ips WHERE asn IS NOT NULL AND day >= date('now', ?) "
                "GROUP BY asn ORDER BY ips DESC, alerts DESC LIMIT ?", (since, limit))
    scen = defaultdict(Counter)
    for r in db.q("SELECT asn, scenarios FROM attack_ips WHERE asn IS NOT NULL AND day >= date('now', ?)", (since,)):
        scen[r["asn"]].update(json.loads(r["scenarios"]))
    rules = rule_store.actions()
    names = {r["asn"]: r for r in db.q("SELECT asn, name, class, cc FROM asn_names WHERE asn IN (SELECT DISTINCT asn FROM "
                                       "attack_ips WHERE day >= date('now', ?))", (since,))}
    shielded = protection.asns("exempt") | set(exemptions.asns())
    capped = protection.asns("captcha")
    out = []
    for r in rows:
        n = names.get(r["asn"])
        row = {"asn": r["asn"], "name": (n["name"] if n else "") or r["as_name"], "class": n["class"] if n else "",
               "cc": n["cc"] if n else "", "ips": r["ips"], "alerts": r["alerts"], "last_seen": r["last_seen"],
               "first_day": r["first_day"], "size": _size(r["asn"]), "rule": rules.get(r["asn"]),
               "protected": r["asn"] in shielded, "capped": r["asn"] in capped,
               "scenarios": [{"name": k, "n": v} for k, v in scen[r["asn"]].most_common(3)]}
        row["recommendation"] = _recommend(row, days)
        out.append(row)
    first = db.q1("SELECT min(day) d FROM attack_ips")["d"]
    return {"days": days, "rows": out, "history_since": first, "updated": db.get("attackers_updated"),
            "error": db.get("attackers_error"), "recommended": sum(r["recommendation"]["kind"] == "recommend" for r in out)}


def ips_of(asn, days=7):
    days = days if days in WINDOWS else 7
    rows = db.q("SELECT ip, sum(alerts) alerts, max(last_seen) last_seen, group_concat(scenarios, '|') sc FROM attack_ips "
                "WHERE asn=? AND day >= date('now', ?) GROUP BY ip ORDER BY alerts DESC LIMIT 500", (asn, f"-{days - 1} days"))
    out = []
    for r in rows:
        sc = sorted({s for part in (r["sc"] or "").split("|") if part for s in json.loads(part)})
        out.append({"ip": r["ip"], "alerts": r["alerts"], "last_seen": r["last_seen"], "scenarios": sc[:5]})
    return out
