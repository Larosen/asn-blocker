"""Compute the desired state and reconcile it with CrowdSec (diff sync).

Flow: load all sources -> compute desired ranges -> sanity check ->
create new/refreshed decisions -> only then delete obsolete ones.
So there is never a gap without protection; any error before writing leaves CrowdSec unchanged.
"""
import ipaddress
import logging
import threading
import time
from collections import defaultdict

from . import attackers, crowdsec, db, netset, notify, policy, routing, sources
from .store import exemptions, runs, vpn, watch
from .store import rules as rule_store

REASONS = {"ban": "asn-blocker ban", "captcha": "asn-blocker captcha"}
NON_PUBLIC, MIN_PREFIXLEN = policy.NON_PUBLIC, policy.MIN_PREFIXLEN
# Hard caps even on the first run: about 12 % of the IPv4 space, 2^36 IPv6 /48s (as much as a /12, of 2000::/3),
# and a number of ranges far above any realistic configuration (16k for 40 large hosting ASNs)
MAX_V4_ADDRESSES = 2**29
MAX_V6_48S = 2**36
MAX_RANGES = 150000
_lock = threading.Lock()
log_ = logging.getLogger("asn_blocker.engine")


class Busy(RuntimeError):
    pass


class Blocked(RuntimeError):
    """Sanity check tripped - needs confirmation. Carries every reason, not just the first."""

    def __init__(self, reasons):
        self.reasons = [reasons] if isinstance(reasons, str) else list(reasons)
        super().__init__("; ".join(self.reasons))


CONFIRM_TOLERANCE = 5  # % a confirmed run's result may differ from the stopped run the user reviewed


# --- Desired state -------------------------------------------------------------------------

def rules():
    """Active ASN rules – an expired rule no longer counts, even before the scheduler has removed it."""
    return rule_store.active()


def expire_rules():
    """Removes rules whose time is up. Returns the removed ASNs."""
    gone = rule_store.expire()
    if gone:
        db.audit("scheduler", "asn.expired", [{"asn": r["asn"], "action": r["action"]} for r in gone])
        log_.info("Rules expired: %s", ", ".join(f"AS{r['asn']}" for r in gone))
    return [r["asn"] for r in gone]


def build(log, fresh=True):
    """The desired state from all active policies – see policy.py."""
    return policy.evaluate(log, fresh)


guard_ips = policy.guard_ips
status_of = policy.status_of


# --- Reconcile ----------------------------------------------------------------------------------

def diff(desired, current, refresh_before):
    """current: list of {id,value,until}. Returns (add, delete_ids, refresh_count)."""
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
            delete += [d["id"] for d in ds[1:]]  # duplicates
    for v, ds in by_value.items():
        if v not in want:
            delete += [d["id"] for d in ds]
    return add, delete, refresh


def _counts():
    return runs.applied_counts(REASONS)


def _space(cidrs):
    """Blocked address space: IPv4 addresses and IPv6 /48 networks."""
    v4 = v6 = 0
    for n in netset.parse(cidrs):
        if n.version == 4:
            v4 += n.num_addresses
        else:
            v6 += max(1, n.num_addresses >> 80)
    return v4, v6


def _sanity(desired, force=False, confirmed=None):
    """force: skip all checks. confirmed: summary of the stopped run the user reviewed and accepted. A result within
    CONFIRM_TOLERANCE of it is applied; one that changed since the review goes through the normal checks again, so a
    confirmation never waves through data the user has not seen."""
    if force:
        return
    new = sum(len(v) for v in desired.values())
    changed = []
    if confirmed is not None:
        changed = [f"{t} ranges changed from {confirmed.get(t, 0):,} to {len(v):,} since the run you confirmed"
                   for t, v in desired.items()
                   if abs(len(v) - confirmed.get(t, 0)) > max(confirmed.get(t, 0), 1) * CONFIRM_TOLERANCE / 100]
        if not changed:
            return
    prev = sum(_counts().values())
    reasons = []
    if new > MAX_RANGES:
        reasons.append(f"{new:,} ranges would be pushed, more than the limit of {MAX_RANGES:,}")
    v4, v6 = _space([c for v in desired.values() for c in v])
    if v4 > MAX_V4_ADDRESSES:
        reasons.append(f"{v4:,} IPv4 addresses would be blocked ({v4 / 2**32:.1%} of IPv4), "
                       f"more than the limit of {MAX_V4_ADDRESSES:,}")
    if v6 > MAX_V6_48S:
        reasons.append(f"{v6:,} IPv6 /48 networks would be blocked, more than the limit of {MAX_V6_48S:,}")
    if new == 0 and (rule_store.count() or db.get("spamhaus_asndrop")):
        reasons.append("Rules exist, but 0 ranges computed")
    if prev:
        pv4, pv6 = _space(runs.applied_values())
        limit = db.get("sanity_percent")
        for label, before, after in (("IPv4 address space", pv4, v4), ("IPv6 address space", pv6, v6)):
            if before and abs(after - before) / before * 100 > limit:
                reasons.append(f"Blocked {label} changes by {abs(after - before) / before * 100:.0f} % "
                               f"({before:,} -> {after:,}), limit {limit} %")
            if not before and after > 2**24:  # IPv6 newly enabled: more than a /24 worth of /48s needs confirmation
                reasons.append(f"Blocked {label} grows from 0 to {after:,} /48 networks (IPv6 newly enabled)")
        pct = abs(new - prev) / prev * 100
        if pct > limit:
            reasons.append(f"Range count changes by {pct:.0f} % ({prev:,} -> {new:,}), limit {limit} %")
    if reasons:  # a result that changed since the review only needs a new confirmation if it trips a check itself
        raise Blocked(changed + reasons)


def watch_ips():
    return watch.ips()


def run(kind, user, force=False, confirmed=None):
    """kind: 'plan' (compute only) or 'apply'. confirmed: (run id, summary) of the stopped run the user accepted.
    Returns the run ID."""
    if not _lock.acquire(blocking=False):
        raise Busy("A run is already in progress")
    try:
        run_id = runs.create(kind, user)
        lines = []

        def log(msg):
            msg = sources.clean(msg, 600)  # external text must not forge lines in the run log or stdout
            line = f"{time.strftime('%H:%M:%S')} {msg}"
            log_.info(msg, extra={"run_id": run_id})
            lines.append(line)
            runs.set_log(run_id, "\n".join(lines))

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
                    current = [{"id": None, "value": v, "until": float("inf")} for v in runs.applied_values(t)]
                add, delete, refresh = diff(desired[t], current, refresh_before)
                removed = {d["value"] for d in current} - set(desired[t])
                new = set(add) - {d["value"] for d in current}
                plan[t] = (add, delete)
                summary[f"{t}_added"], summary[f"{t}_removed"], summary[f"{t}_refreshed"] = len(new), len(removed), refresh
                changes += [(run_id, "+", t, v) for v in sorted(new)] + [(run_id, "-", t, v) for v in sorted(removed)]
                log(f"Plan {t}: +{len(new)} new, -{len(removed)} removed, {refresh} refreshed")
            runs.add_changes(changes)

            watch = {}
            for ip in watch_ips():
                watch[ip] = status_of(ip, desired)
                if watch[ip]:
                    log(f"WARNING watch IP {ip} would be affected: {watch[ip]}")
            summary["watch_hits"] = [ip for ip, s in watch.items() if s]

            if kind == "apply":
                _sanity(desired, force, confirmed[1] if confirmed else None)
                if confirmed:
                    log(f"Confirmed by {user} after review of run #{confirmed[0]}")
                log("Pushing changes to CrowdSec")
                for t, reason in REASONS.items():  # all additions first: no gap when a range moves ban <-> captcha
                    if plan[t][0]:
                        backend.add(plan[t][0], t, reason, db.get("decision_hours") * 3600)
                for t in REASONS:
                    if plan[t][1]:
                        backend.delete_ids(plan[t][1])
                for t, reason in REASONS.items():
                    active = {d["value"] for d in backend.list(reason)}
                    missing = set(desired[t]) - active
                    extra = active - set(desired[t])
                    summary[f"{t}_active"] = len(active)
                    log(f"  {t}: {len(active)} active" + (f", MISSING {len(missing)}" if missing else "")
                        + (f", EXTRA {len(extra)}" if extra else ""))
                    if missing:
                        raise crowdsec.CrowdSecError(f"{len(missing)} {t} ranges missing after import")
                runs.commit_apply(desired, exempt, watch, rev)
                if summary["watch_hits"]:
                    notify.send("asn-blocker: watch IP affected",
                                "Affected by the current rules: " + ", ".join(f"{ip} ({watch[ip]})" for ip in summary["watch_hits"]),
                                "warning", run_id)
            status = "ok"
            log("Done")
        except Blocked as e:
            status = "blocked"
            summary["stopped"] = e.reasons
            for r in e.reasons:
                log(f"STOPPED: {r}")
            log("CrowdSec unchanged – confirm in the UI to apply anyway.")
            notify.send("asn-blocker: run stopped", f"{e}. CrowdSec is unchanged – review and confirm the run.",
                        "warning", run_id)
        except (sources.SourceError, crowdsec.CrowdSecError) as e:
            log(f"ERROR: {e}")
            if kind == "apply":
                notify.send("asn-blocker: run failed", f"{e}. The active decisions stay until they expire.",
                            "error", run_id)
        except Exception as e:  # noqa: BLE001
            log(f"ERROR (unexpected): {e!r}")
            log_.exception("Unexpected error in run %s", run_id)
            if kind == "apply":
                notify.send("asn-blocker: run failed", f"Unexpected error: {e!r}", "error", run_id)
        runs.finish(run_id, status, summary)
        return run_id
    finally:
        _lock.release()


_preview = {"rev": None, "result": None}
_preview_lock = threading.Lock()


def preview():
    """Quick preview for the apply bar: desired state (from caches) vs. last applied state."""
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
            applied = set(runs.applied_values(t))
            want = set(desired[t])
            result[t] = {"total": len(want), "add": len(want - applied), "remove": len(applied - want)}
        _preview.update(rev=rev, result=result)
        return result
    finally:
        _preview_lock.release()


def is_running():
    return _lock.locked()


# --- IP check --------------------------------------------------------------------------------------

def check_ip(ip):
    ip = str(ipaddress.ip_address(ip))
    applied = runs.applied()
    hits = {t: netset.contains(v, ip) for t, v in applied.items()}
    a = ipaddress.ip_address(ip)
    exempt = sorted({label for cidr, label in runs.exempt_index() if a in ipaddress.ip_network(cidr)})
    manual = [cidr for cidr, _ in exemptions.networks() if a in ipaddress.ip_network(cidr, strict=False)]
    out = {"ip": ip, "status": status_of(ip, applied), "ranges": {t: [str(n) for n in v] for t, v in hits.items() if v},
           "exempt": exempt or (["Manual"] if manual else []), "asns": [], "global": a.is_global}
    if a.is_global:
        try:
            info = sources.ip_info(ip)
            out["prefix"] = info["prefix"]
            actions = rule_store.actions()
            for asn in info["asns"]:
                n = sources.asn_info(asn)
                out["asns"].append({"asn": asn, "name": n["name"], "rule": actions.get(asn), "class": n["class"]})
        except sources.SourceError as e:
            out["lookup_error"] = str(e)
        out["vpn_near"] = _vpn_neighbours(a)
    out["explain"] = explain(a)
    return out


def explain(a):
    """Why the IP gets what it gets: the policies that cover it, and whether that differs from what is applied."""
    e = policy.explain(str(a))
    keep = ("id", "source", "value", "effect", "locked", "name", "note", "origin", "expires_at", "via", "wins")
    return {**e, "matches": [{k: m[k] for k in keep} for m in e["matches"]]}


def _vpn_neighbours(a):
    """VPN servers listed in the same /24 (IPv6 /64) as the address. Exit IPs often differ from the listed server
    IPs but sit next to them – then the address is most likely a VPN exit. Uses cached lists only."""
    net = ipaddress.ip_network(f"{a}/{24 if a.version == 4 else 64}", strict=False)
    selected = {(pid, cc) for pid, ccs in vpn.selections().items() for cc in ccs}
    modes = vpn.modes()
    out = []
    for pid, prov in sources.PROVIDERS.items():
        near = set()
        for cc, _, v in db.cache_get(f"vpn:{pid}", float("inf")) or []:
            try:
                if ipaddress.ip_address(v) in net:
                    near.add(cc)
            except ValueError:
                continue  # hostname entries
        out += [{"provider": pid, "name": prov.name, "country": cc, "selected": (pid, cc) in selected,
                 "mode": modes.get(pid, "exact")} for cc in sorted(near)]
    return out[:10]


# --- Scheduler -------------------------------------------------------------------------------------------

def next_due():
    """Time of the next automatic run, or None (never applied manually yet)."""
    last = runs.last_apply(finished=True)
    if not last or not db.get("crowdsec_mode"):
        return None
    wait = db.get("interval_hours") * 3600 if last["status"] in ("ok", "blocked") else 3600
    return last["started_at"] + wait


def scheduler():
    last_prune = last_attackers = 0.0
    release = False  # expired rules are released right away instead of at the next regular run
    while True:
        try:
            release = bool(expire_rules()) or release
            due = next_due()
            if due and (release or due <= time.time()) and not is_running():
                release = False
                run("apply", "scheduler")
            if time.time() - last_prune > 86400:
                db.prune()
                last_prune = time.time()
            if db.get("crowdsec_mode") and time.time() - (db.get("attackers_updated") or 0) > 3600 \
                    and time.time() - last_attackers > 900:
                last_attackers = time.time()
                try:
                    attackers.collect()
                except (crowdsec.CrowdSecError, sources.SourceError) as e:
                    log_.warning("Attackers: %s", e)
            if routing.due():
                try:
                    routing.refresh()
                except routing.RoutingError as e:
                    log_.warning("Routing table: %s", e)
            updated = db.get("asn_names_updated") or 0
            if time.time() - updated > 7 * 86400:
                try:
                    n = sources.refresh_asn_names()
                    log_.info("ASN name list updated: %d entries", n)
                except sources.SourceError as e:
                    log_.warning("ASN name list: %s", e)
                    db.put("asn_names_updated", time.time() - 6 * 86400)  # retry in 1 day
        except Busy:
            pass
        except Exception:  # noqa: BLE001
            log_.exception("Scheduler error")
        time.sleep(30)
